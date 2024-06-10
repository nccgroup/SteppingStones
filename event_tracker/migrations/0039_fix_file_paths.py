from django.db import migrations

from event_tracker.utils import split_path


def fix_files(apps, schema_editor):
    # If we have a file distribution to put the directory into, then do so
    FileDistribution = apps.get_model("event_tracker", "FileDistribution")
    for dist in FileDistribution.objects.all():
        if not dist.location:
            directory, sep, filename = split_path(dist.file.filename)
            dist.location = directory
            dist.save()

    # Now throw away all the directory parts of the filenames
    File = apps.get_model("event_tracker", "File")
    for file in File.objects.all():
        directory, sep, filename = split_path(file.filename)
        file.filename = filename
        file.save()


class Migration(migrations.Migration):

    dependencies = [
        ('event_tracker', '0038_alter_credential_hash_type'),
    ]

    operations = [
        migrations.RunPython(fix_files, reverse_code=migrations.RunPython.noop),
    ]
