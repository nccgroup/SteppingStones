from django.db import migrations, models


def backfill_is64(apps, schema_editor):
    Beacon = apps.get_model('cobalt_strike_monitor', 'Beacon')
    # arch is reliably populated by the log parser (unlike the long-dead barch field); is64 was
    # never actually saved before this migration due to a trailing-comma bug that made the field
    # declaration a tuple instead of a real column. Beacons where arch is blank (e.g. SSH
    # sessions, where the parser never determines 64-bitness) are left as is64=NULL (unknown).
    Beacon.objects.exclude(arch='').update(is64=models.Case(
        models.When(arch='x64', then=models.Value(True)),
        default=models.Value(False),
        output_field=models.BooleanField(),
    ))


class Migration(migrations.Migration):

    dependencies = [
        ('cobalt_strike_monitor', '0032_beacon_row_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='beacon',
            name='is64',
            field=models.BooleanField(default=None, null=True),
        ),
        migrations.RunPython(backfill_is64, migrations.RunPython.noop),
    ]
