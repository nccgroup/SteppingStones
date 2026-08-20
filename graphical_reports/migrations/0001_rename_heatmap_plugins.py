from django.db import migrations


def rename_heatmap_plugins(apps, schema_editor):
    Plugin = apps.get_model('djangoplugins', 'Plugin')

    old_activity = 'graphical_reports.plugins.GraphicalMitreHeatMap'
    new_activity = 'graphical_reports.plugins.GraphicalMitreActivityHeatMap'
    Plugin.objects.filter(pythonpath=old_activity).update(pythonpath=new_activity)

    old_det_prev = 'graphical_reports.plugins.GraphicalMitreDetectionHeatMap'
    new_det_prev = 'graphical_reports.plugins.GraphicalMitreDetectionPreventionHeatMap'
    if Plugin.objects.filter(pythonpath=new_det_prev).exists():
        # New entry already registered (e.g. by a partial syncplugins run); just drop the stale old row.
        Plugin.objects.filter(pythonpath=old_det_prev).delete()
    else:
        Plugin.objects.filter(pythonpath=old_det_prev).update(pythonpath=new_det_prev)


def reverse_rename_heatmap_plugins(apps, schema_editor):
    Plugin = apps.get_model('djangoplugins', 'Plugin')
    Plugin.objects.filter(
        pythonpath='graphical_reports.plugins.GraphicalMitreActivityHeatMap'
    ).update(
        pythonpath='graphical_reports.plugins.GraphicalMitreHeatMap'
    )
    Plugin.objects.filter(
        pythonpath='graphical_reports.plugins.GraphicalMitreDetectionPreventionHeatMap'
    ).update(
        pythonpath='graphical_reports.plugins.GraphicalMitreDetectionHeatMap'
    )


class Migration(migrations.Migration):
    # NOTE: Django's URL checks load include_plugins() which queries the plugin table,
    # so this migration cannot be applied with a plain `migrate`. Use:
    #   python manage.py migrate --skip-checks

    dependencies = [
        ('djangoplugins', '0002_auto_20230718_1254'),
    ]

    operations = [
        migrations.RunPython(rename_heatmap_plugins, reverse_rename_heatmap_plugins),
    ]
