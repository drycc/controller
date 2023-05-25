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
            # docker image (or any sort of image) used via drycc pull
            return 'image'

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

    def create(self, user, *args, **kwargs):
        app_settings = self.app.appsettings_set.latest()
        latest_release = self.app.release_set.filter(failed=False).latest()
        latest_version = self.app.release_set.latest().version
        try:
            new_release = latest_release.new(
                user,
                build=self,
                config=latest_release.config,
                canary=len(app_settings.canaries) > 0,
            )
            self.app.deploy(new_release)
            return new_release
        except Exception as e:
            # check if the exception is during create or publish
            if ('new_release' not in locals() and
                    self.app.release_set.latest().version == latest_version+1):
                new_release = self.app.release_set.latest()
            if 'new_release' in locals():
                new_release.failed = True
                new_release.summary = "{} deployed {} which failed".format(self.owner, str(self.uuid)[:7])  # noqa
                # Get the exception that has occured
                new_release.exception = "error: {}".format(str(e))
                new_release.save()
            else:
                self.delete()

            raise DryccException(str(e)) from e

    def save(self, **kwargs):
        previous_release = self.app.release_set.filter(failed=False).latest()

        if (
            settings.DRYCC_DEPLOY_REJECT_IF_PROCFILE_MISSING is True and
            # previous release had a Procfile and the current one does not
            (
                previous_release.build is not None and
                len(previous_release.build.procfile) > 0 and
                len(self.procfile) == 0
            )
        ):
            # Reject deployment
            raise Conflict(
                'Last deployment had a Procfile but is missing in this deploy. '
                'For a successful deployment provide a Procfile.'
            )

        # See if processes are permitted to be removed
        remove_procs = (
            # If set to True then contents of Procfile does not affect the outcome
            settings.DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE is True or
            # previous release had a Procfile and the current one does as well
            (
                previous_release.build is not None and
                len(previous_release.build.procfile) > 0 and
                len(self.procfile) > 0
            )
        )

        # spin down any proc type removed between the last procfile and the newest one
        if remove_procs and previous_release.build is not None:
            removed = {}
            for proc in previous_release.build.procfile:
                if proc not in self.procfile:
                    # Scale proc type down to 0
                    removed[proc] = 0

            self.app.scale(self.owner, removed)

        # make sure the latest build has procfile if the intent is to
        # allow empty Procfile without removals
        if (
            settings.DRYCC_DEPLOY_PROCFILE_MISSING_REMOVE is False and
            previous_release.build is not None and
            len(previous_release.build.procfile) > 0 and
            len(self.procfile) == 0
        ):
            self.procfile = previous_release.build.procfile

        return super(Build, self).save(**kwargs)

    def __str__(self):
        return "{0}-{1}".format(self.app.id, str(self.uuid)[:7])
