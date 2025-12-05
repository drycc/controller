import logging
from copy import deepcopy
from collections import defaultdict
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

    def merge(self, config):
        if self.dryccfile and any({"values", "values_refs"} & set(config.diff(None).keys())):
            dryccfile = deepcopy(self.dryccfile)
            ptype_env, group_env = defaultdict(dict), defaultdict(dict)
            for value in config.values:
                if "ptype" in value:
                    ptype_env[value["ptype"]][value["name"]] = value["value"]
                if "group" in value:
                    group_env[value["group"]][value["name"]] = value["value"]
            dryccfile['config'] = dict(group_env)
            for pipeline in dryccfile['pipeline'].values():
                pipeline['env'] = ptype_env[pipeline['ptype']]
                pipeline['config'] = config.values_refs.get(pipeline['ptype'], [])
            return Build.objects.create(
                owner=config.owner, app=self.app, image=self.image, stack=self.stack, sha=self.sha,
                procfile=self.procfile, dryccfile=dryccfile, dockerfile=self.dockerfile,
            )
        return self

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
        if not self.dryccfile:
            return self.app.release_set.filter(failed=False).latest().config
        # create config from dryccfile
        values, values_ref = [], {}
        for group, envs in self.dryccfile.get('config', {}).items():
            for key, value in envs.items():
                values.append({"name": key, "group": group, "value": value})
        for pipeline in self.dryccfile.get('pipeline', {}).values():
            if 'env' in pipeline or 'config' in pipeline:
                for key, value in pipeline.get('env', {}).items():
                    values.append({"name": key, "ptype": pipeline['ptype'], "value": value})
                for config_ref in pipeline.get('config', []):
                    if pipeline['ptype'] not in values_ref:
                        values_ref[pipeline['ptype']] = [config_ref]
                    else:
                        values_ref[pipeline['ptype']].append(config_ref)
        config = Config(
            owner=self.owner, app=self.app, values=values, values_refs=values_ref)
        config.save(ignore_update_fields=["values", "values_refs"])
        return config
