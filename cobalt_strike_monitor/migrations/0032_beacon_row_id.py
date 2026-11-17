from django.db import migrations, models
from django.db.migrations.operations.base import Operation
from django.db.models import F

# CS beacon IDs are only unique within a single TeamServer, but Beacon.id was the sole
# primary key, so two beacons from different team servers sharing a number would silently
# clash. This gives Beacon a real surrogate primary key (row_id) and makes (team_server, id)
# the actual uniqueness constraint. Every other model's FK to Beacon stores row_id afterwards,
# so their beacon_id columns are rewritten from the old id values to the new row_id values.
#
# This relies on Beacon.id being globally unique at the moment this migration runs (true right
# after the one-off GreenUncle TeamServer merge cleanup) - it is not a generally safe assumption
# and this migration is not reversible.

FK_TARGETS = [
    ('cobalt_strike_monitor', 'Archive', 'beacon_id'),
    ('cobalt_strike_monitor', 'BeaconLog', 'beacon_id'),
    ('cobalt_strike_monitor', 'BeaconPresence', 'beacon_id'),
    ('cobalt_strike_monitor', 'Download', 'beacon_id'),
    ('cobalt_strike_monitor', 'CSAction', 'beacon_id'),
    ('cobalt_strike_monitor', 'Beacon', 'parent_beacon_id'),  # self-referential
    ('event_tracker', 'BeaconReconnectionWatcher', 'beacon_id'),
]

# Tables with a ForeignKey to Beacon whose SQLite schema needs rebuilding (see RemakeTable below).
DEPENDENT_TABLES = [
    ('cobalt_strike_monitor', 'Archive'),
    ('cobalt_strike_monitor', 'BeaconLog'),
    ('cobalt_strike_monitor', 'BeaconPresence'),
    ('cobalt_strike_monitor', 'Download'),
    ('cobalt_strike_monitor', 'CSAction'),
    ('event_tracker', 'BeaconReconnectionWatcher'),
]

# Comfortably larger than any real id/row_id value, used to avoid value collisions while
# remapping beacon_id columns in place (see repoint_beacon_fks below).
OFFSET = 10 ** 15


def repoint_beacon_fks(apps, schema_editor):
    Beacon = apps.get_model('cobalt_strike_monitor', 'Beacon')

    for i, beacon in enumerate(Beacon.objects.order_by('pk'), start=1):
        beacon.row_id = i
        beacon.save(update_fields=['row_id'])

    mapping = dict(Beacon.objects.values_list('id', 'row_id'))

    for app_label, model_name, fk_field in FK_TARGETS:
        model = apps.get_model(app_label, model_name)
        model.objects.update(**{fk_field: F(fk_field) + OFFSET})
        for old_id, new_id in mapping.items():
            model.objects.filter(**{fk_field: old_id + OFFSET}).update(**{fk_field: new_id})


class RemakeTable(Operation):
    """
    Force SQLite to recreate a table's schema from the current model state.

    SQLite bakes each table's "REFERENCES parent (column)" clause into its schema at creation
    time; it isn't updated just because the referenced model's primary key field changed
    elsewhere. Django's own AlterField only triggers this rebuild for dependent tables when the
    altered field's *type* changes alongside becoming unique (see SQLite SchemaEditor._alter_field),
    which doesn't apply to swapping Beacon's primary key from id to row_id. This operation calls
    the same rebuild Django would have used, directly, for the tables that need it.
    """

    reduces_to_sql = True
    reversible = True

    def __init__(self, app_label, model_name):
        self.target_app_label = app_label
        self.model_name = model_name

    def state_forwards(self, app_label, state):
        pass  # No model-state change; this is a database-only fixup.

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if schema_editor.connection.vendor != 'sqlite':
            return
        model = to_state.apps.get_model(self.target_app_label, self.model_name)
        schema_editor._remake_table(model)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if schema_editor.connection.vendor != 'sqlite':
            return
        model = from_state.apps.get_model(self.target_app_label, self.model_name)
        schema_editor._remake_table(model)

    def describe(self):
        return f"Remake table for {self.target_app_label}.{self.model_name} to refresh its FK schema"


class Migration(migrations.Migration):

    dependencies = [
        ('cobalt_strike_monitor', '0031_beaconlog_archive_task_id'),
        ('event_tracker', '0088_alter_credential_hash_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='beacon',
            name='row_id',
            field=models.BigIntegerField(null=True, unique=True),
        ),
        migrations.RunPython(repoint_beacon_fks, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='beacon',
            name='row_id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='beacon',
            name='id',
            field=models.IntegerField(),
        ),
        migrations.AddConstraint(
            model_name='beacon',
            constraint=models.UniqueConstraint(fields=('team_server', 'id'), name='unique_beacon_id_per_team_server'),
        ),
    ] + [RemakeTable(app_label, model_name) for app_label, model_name in DEPENDENT_TABLES]
