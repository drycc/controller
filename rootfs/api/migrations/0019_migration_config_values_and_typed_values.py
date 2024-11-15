# Generated by Django 4.2.15 on 2024-09-06 03:58
import json
from django.db import connection, migrations
from api.models.config import Config


def migration_values(apps, schema_editor):
    with connection.cursor() as cursor:
        cursor.execute("SELECT uuid,values,typed_values,registry FROM api_config")
        for uuid, values, typed_values, registry in cursor:
            new_values = []
            config = Config.objects.get(pk=uuid)
            for name, value in json.loads(values).items():
                new_values.append({
                    "name": name,
                    "group": "global",
                    "value": value
                })
            for ptype, values in json.loads(typed_values).items():
                for name, value in values.items():
                    new_values.append({
                        "name": name,
                        "ptype": ptype,
                        "value": value
                    })
            new_registry, data = {}, json.loads(registry)
            if data:
                for ptype in config.app.structure.keys():
                    new_registry[ptype] = data
            config.values = new_values
            config.registry = new_registry
            config.save(ignore_update_fields=config.allof_fields)


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0018_config_values_refs'),
    ]

    operations = [
        migrations.RunPython(migration_values),
    ]
