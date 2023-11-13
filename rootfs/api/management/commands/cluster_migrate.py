from django.core.cache import cache
from django.core.management.commands import migrate


class Command(migrate.Command):
    """Management command for cluster_lock"""
    def handle(self, *args, **options):
        print("preparing migrate...")
        with cache.lock("drycc:controller", timeout=60 * 60 * 24):
            super().handle(self, *args, **options)
        print("migrate completed...")
