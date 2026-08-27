# Generated migration to seed the special "n/a" Context entry.

from django.db import migrations


def seed_na_context(apps, schema_editor):
    Context = apps.get_model('event_tracker', 'Context')
    Context.objects.get_or_create(host='n/a', user='', process='')


class Migration(migrations.Migration):

    dependencies = [
        ('event_tracker', '0085_event_timestamp_end_after_timestamp_start_squashed_0086_alter_context_host_alter_context_process_and_more'),
    ]

    operations = [
        migrations.RunPython(seed_na_context, migrations.RunPython.noop),
    ]
