from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cobalt_strike_monitor', '0030_auto_20250317_2000'),
    ]

    operations = [
        migrations.AddField(
            model_name='beaconlog',
            name='task_id',
            field=models.CharField(max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='archive',
            name='task_id',
            field=models.CharField(max_length=20, null=True),
        ),
    ]
