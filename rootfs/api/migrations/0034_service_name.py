import api.utils
from django.db import migrations, models


def backfill_service_names(apps, schema_editor):
    Service = apps.get_model('api', 'Service')
    for service in Service.objects.all():
        if service.ptype == 'web':
            service.name = service.app.id
        else:
            service.name = f'{service.app.id}-{service.ptype}'
        service.save(update_fields=['name'])


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0033_addoninstance'),
    ]

    operations = [
        migrations.AddField(
            model_name='service',
            name='name',
            field=models.CharField(
                db_index=True,
                max_length=63,
                null=True,
                validators=[api.utils.validate_label],
            ),
        ),
        migrations.RunPython(backfill_service_names, migrations.RunPython.noop),
        migrations.AlterUniqueTogether(
            name='service',
            unique_together=set(),
        ),
        migrations.AlterField(
            model_name='service',
            name='name',
            field=models.CharField(
                db_index=True,
                max_length=63,
                validators=[api.utils.validate_label],
            ),
        ),
        migrations.AlterUniqueTogether(
            name='service',
            unique_together={('app', 'name')},
        ),
    ]
