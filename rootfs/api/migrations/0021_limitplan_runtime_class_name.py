# Generated by Django 4.2.17 on 2024-12-25 08:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0020_remove_config_typed_values_alter_config_values'),
    ]

    operations = [
        migrations.AddField(
            model_name='limitplan',
            name='runtime_class_name',
            field=models.CharField(default='', max_length=63),
        ),
    ]
