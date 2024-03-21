import time
from django.core.management.base import BaseCommand
from django.core.cache import cache
from django.conf import settings

lock_key = "drycc:controller:version"
waitting_init_msg = "version inconsistency %s!=%s, waiting for initialization to complete..."


class Command(BaseCommand):
    """Management command for push data to manager"""

    def add_arguments(self, parser):
        parser.add_argument(
            "args",
            metavar="action",
            nargs="+",
            choices=["lock", "unlock", "waitting"],
            help="an action that needs to be executed.",
        )

    def lock(self):
        cache.delete(lock_key)
        print("lock completed!")

    def unlock(self):
        cache.set(lock_key, settings.VERSION)
        print("unlock completed!")

    def waitting(self):
        while True:
            version = cache.get(lock_key, None)
            if version != settings.VERSION:
                print(waitting_init_msg % (version, settings.VERSION))
            else:
                break
            time.sleep(10)
        print("waiting completed!")

    def handle(self, *args, **options):
        action = args[0]
        getattr(self, action)()
