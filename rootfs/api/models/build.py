import logging
from django.conf import settings
from django.db import models
from django.contrib.auth import get_user_model
from api.exceptions import DryccException, Conflict
from .base import UuidAuditedModel

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
    def procfile_types(self):
        if self.dryccfile:
            return list(self.dryccfile['deploy'].keys())
        return list(self.procfile.keys())

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

    def get_image(self, procfile_type, default_image=None):
        docker = self.dryccfile.get('build', {}).get('docker', {})
        if procfile_type in docker:
            if procfile_type == 'web':
                return self.image
            else:
                return f'{self.image}-{procfile_type}'
        return default_image if default_image else self.image

    def create_release(self, user, *args, **kwargs):
        latest_release = self.app.release_set.filter(failed=False).latest()
        latest_version = self.app.release_set.latest().version
        try:
            new_release = latest_release.new(
                user,
                build=self,
                config=latest_release.config,
            )
            if self.app.appsettings_set.latest().autodeploy:
                new_release.deploy(force_deploy=False)
            return new_release
        except Exception as e:
            # check if the exception is during create or publish
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

    def save(self, **kwargs):
        previous_release = self.app.release_set.filter(failed=False).latest()

        if (
            settings.DRYCC_DEPLOY_REJECT_IF_PROCFILE_MISSING is True and
            # previous release had a Procfile and the current one does not
            (
                previous_release.build is not None and
                len(previous_release.procfile_types) > 0 and
                len(self.procfile_types) == 0
            )
        ):
            # Reject deployment
            raise Conflict(
                'Last deployment had process types but is missing in this deploy. '
                'For a successful deployment provide process types.'
            )

        # See if processes are permitted to be removed
        remove_procs = (
            # If set to True then contents of Procfile does not affect the outcome
            settings.DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE is True or
            # previous release had a Procfile and the current one does as well
            (
                previous_release.build is not None and
                len(previous_release.procfile_types) > 0 and
                len(self.procfile_types) > 0
            )
        )

        # spin down any proc type removed between the last procfile and the newest one
        if remove_procs and previous_release.build is not None:
            removed = {}
            for proc in previous_release.procfile_types:
                if proc not in self.procfile_types and self.app.structure.get(proc, 0) > 0:
                    # Scale proc type down to 0
                    removed[proc] = 0

            self.app.scale(self.owner, removed)

        # make sure the latest build has procfile if the intent is to
        # allow empty Procfile without removals
        if (
            settings.DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE is False and
            previous_release.build is not None and
            len(previous_release.procfile_types) > 0 and
            len(self.procfile_types) == 0
        ):
            self.procfile = previous_release.build.procfile
            self.dryccfile = previous_release.build.dryccfile

        return super(Build, self).save(**kwargs)

    def __str__(self):
        return "{0}-{1}".format(self.app.id, str(self.uuid)[:7])
