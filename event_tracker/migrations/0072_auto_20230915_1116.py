# Generated by Django 4.2.5 on 2023-09-15 10:16
import re

from django.db import migrations

evidence_pattern = re.compile(r"\s*~~~.*~~~", flags=re.DOTALL)

def extract_evidence(apps, schema_editor):
    # We can't import the Person model directly as it may be a newer
    # version than this migration expects. We use the historical version.
    Event = apps.get_model("event_tracker", "Event")
    for event in Event.objects.all():
        evidence = ""
        for match in re.findall(evidence_pattern, event.description):
            evidence += match.strip("~\n\r ")

        if evidence:
            event.raw_evidence = evidence
            event.description = re.sub(evidence_pattern, "", event.description)
            event.save()

def reverse(apps, schema_editor):
    pass

class Migration(migrations.Migration):

    dependencies = [
        ('event_tracker', '0071_event_raw_evidence_alter_credential_account_and_more'),
    ]

    operations = [
        migrations.RunPython(extract_evidence, reverse),
    ]
