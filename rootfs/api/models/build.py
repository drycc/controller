import logging
from django.db import models
from django.contrib.auth import get_user_model
from api.exceptions import DryccException
from .base import UuidAuditedModel, PTYPE_WEB
from .config import Config

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
            return list(self.dryccfile['deploy'].keys())
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
        docker = self.dryccfile.get('build', {}).get('docker', {})
        if ptype in docker:
            if ptype == 'web':
                return self.image
            else:
                return f'{self.image}-{ptype}'
        return default_image if default_image else self.image

    def create_release(self, user, *args, **kwargs):
        latest_release = self.app.release_set.filter(failed=False).latest()
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
        latest_release = self.app.release_set.filter(failed=False).latest()
        config_values, config_values_ref, config_healthcheck = [], {}, {}
        for group, values in self.dryccfile.get('config', {}).items():
            for value in values:
                value['group'] = group
                config_values.append(value)
        for ptype, values in self.dryccfile.get('deploy', {}).items():
            for value in values.get('config', {}).get('env', []):
                value['ptype'] = ptype
                config_values.append(value)
            for config_ref in values.get('config', {}).get('ref', []):
                if ptype not in config_values_ref:
                    config_values_ref[ptype] = [config_ref]
                else:
                    config_values_ref[ptype].append(config_ref)
            if 'healthcheck' in values:
                config_healthcheck[ptype] = values.get('healthcheck')
        if not config_values:
            return latest_release.config
        config = Config(
            owner=self.owner, app=self.app, values=config_values, values_refs=config_values_ref,
            healthcheck=config_healthcheck,
        )
        config.save(ignore_update_fields=["values", "values_refs", "healthcheck"])
        return config
