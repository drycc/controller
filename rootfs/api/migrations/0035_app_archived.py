from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0034_service_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='app',
            name='archived',
            field=models.BooleanField(default=False, editable=False),
        ),
    ]
