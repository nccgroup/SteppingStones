# Generated by Django 4.0.3 on 2022-04-23 11:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('event_tracker', '0025_credential_hash_event_timestamp_end_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='credential',
            name='hash',
            field=models.CharField(blank=True, max_length=3000, null=True),
        ),
        migrations.AlterField(
            model_name='credential',
            name='purpose',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='credential',
            name='secret',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='credential',
            name='source',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='credential',
            name='source_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='credential',
            name='system',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
