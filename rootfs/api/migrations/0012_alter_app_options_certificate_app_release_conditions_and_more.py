# Generated by Django 4.2.15 on 2024-08-30 00:53

import api.utils
from django.db import migrations, models
import django.db.models.deletion
from guardian.shortcuts import assign_perm, get_users_with_perms, remove_perm
from api.models.app import App, VIEW_APP_PERMISSION, CHANGE_APP_PERMISSION
from api.models.domain import Domain


def migration_permission(apps, schema_editor):
    for app in App.objects.all():
        for user in get_users_with_perms(app):
            remove_perm('use_app', user, app)
            assign_perm(VIEW_APP_PERMISSION.codename, user, app)
            assign_perm(CHANGE_APP_PERMISSION.codename, user, app)


def migration_certificate(apps, schema_editor):
    for domain in Domain.objects.all():
        if domain.certificate:
            if domain.certificate.app == None:
                domain.certificate.app = domain.app
                domain.certificate.save()
            else:
                certificate = domain.certificate
                certificate.pk = None
                certificate.app = domain.app
                certificate.save()
                domain.certificate = certificate
                domain.save()


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_appsettings_autodeploy'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='app',
            options={'ordering': ['id'], 'verbose_name': 'Application'},
        ),
        migrations.AddField(
            model_name='certificate',
            name='app',
            field=models.ForeignKey(default=None, on_delete=django.db.models.deletion.CASCADE, to='api.app'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='release',
            name='conditions',
            field=models.JSONField(default=list),
        ),
        migrations.AlterField(
            model_name='certificate',
            name='name',
            field=models.CharField(max_length=253, validators=[api.utils.validate_label]),
        ),
        migrations.AlterUniqueTogether(
            name='certificate',
            unique_together={('app', 'name')},
        ),
        migrations.RunPython(migration_permission),
        migrations.RunPython(migration_certificate),
    ]
