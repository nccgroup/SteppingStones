# Generated by Django 5.1 on 2024-09-19 08:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('event_tracker', '0080_importedevent_raw_evidence'),
    ]

    operations = [
        migrations.AlterField(
            model_name='webhook',
            name='url',
            field=models.URLField(max_length=500),
        ),
    ]
