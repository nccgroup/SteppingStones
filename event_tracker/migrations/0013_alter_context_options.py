# Generated by Django 3.2.8 on 2021-11-09 09:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('event_tracker', '0012_auto_20211022_1157'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='context',
            options={'ordering': ['-pk']},
        ),
    ]
