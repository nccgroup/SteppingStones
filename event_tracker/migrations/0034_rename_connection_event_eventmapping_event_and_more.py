# Generated by Django 4.0.5 on 2022-06-24 09:18

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('event_tracker', '0033_rename_eventmappingcsbeacon_eventmapping'),
    ]

    operations = [
        migrations.RenameField(
            model_name='eventmapping',
            old_name='connection_event',
            new_name='event',
        ),
        migrations.RenameField(
            model_name='eventmapping',
            old_name='beacon',
            new_name='object_id',
        ),
    ]
