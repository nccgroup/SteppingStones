# Generated by Django 4.0.2 on 2022-02-17 15:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('event_tracker', '0022_credential_alter_file_filename'),
    ]

    operations = [
        migrations.AlterField(
            model_name='credential',
            name='source',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='credential',
            name='source_time',
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name='credential',
            name='system',
            field=models.CharField(max_length=200, null=True),
        ),
    ]
