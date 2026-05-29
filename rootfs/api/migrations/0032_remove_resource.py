# Generated migration to remove Resource model after extraction to standalone service

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0031_app_uid_alter_workspace_uid'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.DeleteModel(
                    name='Resource',
                ),
            ],
            # Keep the database table for now as a rollback safety measure.
            # A future migration will drop the table after confirming stability.
            database_operations=[],
        ),
    ]
