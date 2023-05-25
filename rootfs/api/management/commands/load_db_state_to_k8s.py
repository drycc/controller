import logging
from django.core.management.base import BaseCommand
from django.shortcuts import get_object_or_404

from api.models.key import Key
from api.models.app import App
from api.models.domain import Domain
from api.models.certificate import Certificate
from api.models.service import Service
from api.exceptions import DryccException, AlreadyExists


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for publishing Drycc platform state from the database
    to k8s.
    """

    def _deploy(self, app, release):
        if release.build is None:
            print('WARNING: {} has no build associated with '
                  'its latest release. Skipping deployment...'.format(app))
            return

        try:
            app.deploy(release)
        except AlreadyExists as error:
            logger.debug(error)
            print('WARNING: {} has a deployment in progress. '
                  'Skipping deployment...'.format(app))
        except DryccException as error:
            logger.exception(error)
            print('ERROR: There was a problem deploying {} '
                  'due to {}'.format(app, str(error)))

    def handle(self, *args, **options):
        """Publishes Drycc platform state from the database to kubernetes."""
        print("Publishing DB state to kubernetes...")

        self.save_apps()

        # certificates have to be attached to domains to create k8s secrets
        for cert in Certificate.objects.all():
            for domain in cert.domains:
                domain = get_object_or_404(Domain, domain=domain)
                cert.attach_in_kubernetes(domain)

        # deploy apps
        print("Deploying available applications")
        for app in App.objects.all():
            release = app.release_set.filter(failed=False).latest()
            if release.canary:
                self._deploy(app, app.release_set.filter(failed=False, canary=False).latest())
            self._deploy(app, release)

        print("Done Publishing DB state to kubernetes.")

    def save_apps(self):
        """Saves important Django data models to the database."""
        for app in App.objects.all():
            try:
                app.save()
                app.config_set.latest().save()
                app.tls_set.latest().sync()
            except DryccException as error:
                print('ERROR: Problem saving to model {} for {}'
                      'due to {}'.format(str(App.__name__), str(app), str(error)))
        for model in (Key, Domain, Certificate, Service):
            for obj in model.objects.all():
                try:
                    obj.save()
                except DryccException as error:
                    print('ERROR: Problem saving to model {} for {}'
                          'due to {}'.format(str(model.__name__), str(obj), str(error)))
