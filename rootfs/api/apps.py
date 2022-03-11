from django import apps


class AppConfig(apps.AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        super(AppConfig, self).ready()
        __import__("api.signals")
