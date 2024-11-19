# Generated by Django 4.2.16 on 2024-10-21 04:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_alter_appsettings_autodeploy_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='route',
            name='port',
        ),
        migrations.RemoveField(
            model_name='route',
            name='ptype',
        ),
        migrations.AddField(
            model_name='release',
            name='deployed_ptypes',
            field=models.JSONField(default=list),
        ),
    ]