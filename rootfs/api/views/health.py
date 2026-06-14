"""
Health check views.
"""
from django.db import connection, Error
from django.views.generic import View
from django.http import HttpResponse

from api.exceptions import ServiceUnavailable


class ReadinessCheckView(View):
    """Simple readiness check view to determine DB connection and Migrations."""
    migrations_completed = False

    def get(self, request):
        try:
            with connection.cursor() as c:
                c.execute("SELECT 0")
            if not ReadinessCheckView.migrations_completed:
                from django.db.migrations.executor import MigrationExecutor
                executor = MigrationExecutor(connection)
                targets = executor.loader.graph.leaf_nodes()
                if executor.migration_plan(targets):
                    raise ServiceUnavailable("Migrations are not yet applied")
                ReadinessCheckView.migrations_completed = True
        except Error as e:
            raise ServiceUnavailable(f"Database health check failed: {e}") from e
        return HttpResponse("OK")
    head = get


class LivenessCheckView(View):
    """
    Simple liveness check view to determine if the server
    is responding to HTTP requests.
    """

    def get(self, request):
        return HttpResponse("OK")
    head = get
