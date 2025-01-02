import logging
from django.db import models
from django.contrib.auth import get_user_model
from api.exceptions import DryccException
from .base import UuidAuditedModel, PTYPE_WEB
from .config import Config
from .release import Release

User = get_user_model()
logger = logging.getLogger(__name__)


class Build(UuidAuditedModel):
    """
    Instance of a software build used by runtime nodes
    """

    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    image = models.TextField()
    stack = models.CharField(max_length=32)

    # optional fields populated by builder
    sha = models.CharField(max_length=40, blank=True)
    procfile = models.JSONField(default=dict, blank=True)
    dryccfile = models.JSONField(default=dict, blank=True)
    dockerfile = models.TextField(blank=True)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'uuid'),)

    @property
    def type(self):
        """Figures out what kind of build type is being deal it with"""
        if self.dockerfile:
            return 'dockerfile'
        elif self.sha:
            return 'buildpack'
        else:
            # container image (or any sort of image) used via drycc pull
            return 'image'

    @property
    def ptypes(self):
        if self.dryccfile:
            return list([pipeline['ptype'] for pipeline in self.dryccfile['pipeline'].values()])
        if self.procfile:
            return list(self.procfile.keys())
        return [PTYPE_WEB]

    @property
    def source_based(self):
        """
        Checks if a build is source (has a sha) based or not
        If True then the Build is coming from the drycc builder or something that
        built from git / svn / hg / etc directly
        """
        return self.sha != ''

    @property
    def version(self):
        return 'git-{}'.format(self.sha) if self.source_based else 'latest'

    def get_image(self, ptype, default_image=None):
        pipeline = self.get_pipeline(ptype)
        if pipeline and 'build' in pipeline:
            return self.image if ptype == 'web' else f'{self.image}-{ptype}'
        return default_image if default_image else self.image

    def get_pipeline(self, ptype):
        pipelines = self.get_pipelines([ptype])
        if len(pipelines) > 0:
            return pipelines[0]
        return {}

    def get_pipelines(self, ptypes):
        results = []
        for pipeline in self.dryccfile.get('pipeline', {}).values():
            if pipeline['ptype'] in ptypes:
                results.append(pipeline)
        return results

    def create_release(self, user, *args, **kwargs):
        latest_release = Release.latest(self.app)
        try:
            new_release = latest_release.new(
                user,
                build=self,
                config=self._get_or_create_config(),
            )
            if self.app.appsettings_set.latest().autodeploy:
                new_release.deploy(force_deploy=False)
            return new_release
        except Exception as e:
            # check if the exception is during create or publish
            latest_version = self.app.release_set.latest().version
            if ('new_release' not in locals() and
                    self.app.release_set.latest().version == latest_version+1):
                new_release = self.app.release_set.latest()
                new_release.state = "crashed"
                new_release.failed = True
                if new_release.summary:
                    new_release.summary += " "
                new_release.summary += "{} deployed {} which failed".format(
                    self.owner, str(self.uuid)[:7])
                # Get the exception that has occured
                new_release.exception = "error: {}".format(str(e))
                # avoid overwriting other fields
                new_release.save(update_fields=["state", "failed", "summary", "exception"])
            if 'new_release' not in locals():
                self.delete()
            raise DryccException(str(e)) from e

    def __str__(self):
        return "{0}-{1}".format(self.app.id, str(self.uuid)[:7])

    def _get_or_create_config(self):
        """
        dryccfile to config
        """
        config_values, config_values_ref, changed_fields = [], {}, set()
        for group, envs in self.dryccfile.get('config', {}).items():
            for key, value in envs.items():
                config_values.append({"name": key, "group": group, "value": value})
            changed_fields.update(["values", "values_refs"])

        replace_values_ptypes = set()
        for pipeline in self.dryccfile.get('pipeline', {}).values():
            if 'env' in pipeline or 'config' in pipeline:
                for key, value in pipeline.get('env', {}).items():
                    config_values.append({"name": key, "ptype": pipeline['ptype'], "value": value})
                for config_ref in pipeline.get('config', []):
                    if pipeline['ptype'] not in config_values_ref:
                        config_values_ref[pipeline['ptype']] = [config_ref]
                    else:
                        config_values_ref[pipeline['ptype']].append(config_ref)
                replace_values_ptypes.add(pipeline['ptype'])
                changed_fields.update(["values", "values_refs"])

        old_config = self.app.release_set.filter(failed=False).latest().config
        if not changed_fields:
            return old_config
        config = Config(
            owner=self.owner, app=self.app, values=config_values, values_refs=config_values_ref)
        config.merge_field("values", old_config, replace_values_ptypes)
        config.merge_field("values_refs", old_config, replace_values_ptypes)
        config.save(ignore_update_fields=changed_fields)
        return config
