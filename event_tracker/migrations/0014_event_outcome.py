# Generated by Django 3.2.8 on 2021-11-09 13:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('event_tracker', '0013_alter_context_options'),
    ]

    operations = [
        migrations.AddField(
            model_name='event',
            name='outcome',
            field=models.CharField(default='', max_length=1000),
            preserve_default=False,
        ),
    ]
