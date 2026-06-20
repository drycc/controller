import uuid
from django.db import migrations, models
import django.db.models.deletion
import api.models.addon


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0032_remove_resource'),
    ]

    operations = [
        migrations.CreateModel(
            name='AddonInstance',
            fields=[
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True, verbose_name='UUID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('app', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.app')),
                ('name', models.CharField(max_length=63, validators=[api.models.addon.validate_addon_instance_name])),
                ('plan', models.CharField(max_length=128)),
                ('kind', models.CharField(max_length=63)),
                ('multiplier', models.PositiveIntegerField(default=1)),
                ('parameters', models.JSONField(blank=True, default=dict)),
            ],
            options={
                'unique_together': {('app', 'name')},
            },
        ),
    ]
