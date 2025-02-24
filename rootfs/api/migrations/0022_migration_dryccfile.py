# Generated by Django 4.2.15 on 2024-09-06 03:58

from django.db import migrations
from api.models.release import Release


def migration_dryccfile(apps, schema_editor):
    for release in Release.objects.all():
        build = release.build
        if not build or not build.dryccfile or "pipeline" in build.dryccfile:
            continue
        config, envs = {}, {}
        if release.config:
            for value in release.config.values:
                if "ptype" in value:
                    if value["ptype"] not in envs:
                        envs[value["ptype"]] = {}
                    envs[value["ptype"]][value["name"]] = value["value"]
                elif "group" in value:
                    if value["group"] not in envs:
                        config[value["group"]] = {}
                    config[value["group"]][value["name"]] = value["value"]
        pipeline = {}
        for key, value in build.dryccfile.get('deploy', {}).items():
            pipeline.update({
                "%s.yaml" % key: {
                    "kind": "pipeline",
                    "ptype": key,
                    "env": envs.get(key, {}),
                    "deploy": value,
                }
            })
        build.dryccfile = {"config": config, "pipeline": pipeline}
        build.save()


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0021_limitplan_runtime_class_name'),
    ]

    operations = [
        migrations.RunPython(migration_dryccfile),
    ]
