import csv
import json
import pathlib

import dateparser
from django.contrib.auth.models import User
from django.core.management import BaseCommand

from event_tracker.models import Context, AttackTactic, AttackTechnique, AttackSubTechnique, Event, Task


class Command(BaseCommand):
    help = 'Parse a csv export back into events'

    def add_arguments(self, parser):
        parser.add_argument('csv_file', type=pathlib.Path)

    def handle(self, *args, **options):
        filename = options["csv_file"]
        with open(filename) as csvfile:
            event_reader = csv.DictReader(csvfile)

            task = Task.objects.first()
            operator = User.objects.first()

            print(f"Assigning all events to {task.name}, operator: {operator.username}")

            for csv_event in event_reader:
                source, _ = Context.objects.get_or_create(process=csv_event["Source Process"],
                                                       user=csv_event["Source User"],
                                                       host=csv_event["Source Host"])
                target, _ = Context.objects.get_or_create(process=csv_event["Target Process"],
                                                       user=csv_event["Target User"],
                                                       host=csv_event["Target Host"])

                if csv_event["MITRE Tactic ID"]:
                    tactic = AttackTactic.objects.get(mitre_id=csv_event["MITRE Tactic ID"])

                    if csv_event["MITRE Technique ID"]:
                        technique = AttackTechnique.objects.get(mitre_id=csv_event["MITRE Technique ID"])

                        if csv_event["MITRE Subtechnique ID"]:
                            subtechnique = AttackSubTechnique.objects.get(mitre_id=csv_event["MITRE Subtechnique ID"])
                        else:
                            subtechnique = None
                    else:
                        technique = None
                        subtechnique = None
                else:
                    tactic = None
                    technique = None
                    subtechnique = None

                timestamp = dateparser.parse(csv_event["Timestamp"])
                if csv_event["Timestamp End"]:
                    timestamp_end = dateparser.parse(csv_event["Timestamp End"])
                else:
                    timestamp_end = None

                event, created = Event.objects.get_or_create(timestamp=timestamp, timestamp_end=timestamp_end,
                                                    mitre_attack_tactic=tactic, mitre_attack_technique=technique,
                                                    mitre_attack_subtechnique=subtechnique,
                                                    source=source, target=target,
                                                    description=csv_event["Description"] or None,
                                                    raw_evidence=csv_event["Raw Evidence"] if "Raw Evidence" in csv_event else None,
                                                    outcome=csv_event["Outcome"] or None,
                                                    detected=csv_event["Detected"],
                                                    prevented=csv_event["Prevented"],
                                                    task=task, operator=operator)

                if "Tags" in csv_event:
                    tag_list = json.loads(csv_event["Tags"].replace("'", '"'))
                    event.tags.set(tags=tag_list, clear=True)

                print(f"{'Created' if created else 'Re-imported'} Event: {event}")
