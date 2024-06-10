import json
import sys

import requests

def fetch_and_create():
    resp = requests.get("https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json")

    if resp.ok:
        mitre_data = resp.json()
        create_fixture(mitre_data)
    else:
        exit("Unable to download MITRE data, must be loaded manually")


def load_and_create(filename):
    with open(filename, encoding="UTF8") as mitre_fp:
        mitre_data = json.load(mitre_fp)
    create_fixture(mitre_data)


def create_fixture(mitre_data):
    fixture = []

    # Variable used to determine kill chain step numbers
    tactic_ordering = []

    for mitre_object in mitre_data["objects"]:
        if mitre_object["type"] == "x-mitre-matrix":
            tactic_ordering = mitre_object["tactic_refs"]

    # ----

    for mitre_object in mitre_data["objects"]:
        # Skip revoked
        if "revoked" in mitre_object and mitre_object["revoked"] is True:
            continue

        # Top level tactics
        elif mitre_object["type"] == "x-mitre-tactic":
            for reference in mitre_object["external_references"]:
                if reference["source_name"] == "mitre-attack":
                    print(reference["external_id"] + " " + mitre_object["name"])
                    fixture.append({
                        "model": "event_tracker.attacktactic",
                        "fields": {
                            "mitre_id": reference["external_id"],
                            "name": mitre_object["name"],
                            "shortname": mitre_object["x_mitre_shortname"],
                            "step": tactic_ordering.index(mitre_object["id"]),
                        }
                    })

    # ----

    for mitre_object in mitre_data["objects"]:
        if "revoked" in mitre_object and mitre_object["revoked"] is True:
            continue

        # first level techniques
        elif mitre_object["type"] == "attack-pattern" and ("x_mitre_is_subtechnique" not in mitre_object or
                                                           mitre_object["x_mitre_is_subtechnique"] == False):
            for reference in mitre_object["external_references"]:
                if reference["source_name"] == "mitre-attack":
                    print("** " + reference["external_id"] + " " + mitre_object["name"])
                    tactics = []
                    if "kill_chain_phases" in mitre_object:
                        tactics.extend([tactic["phase_name"]] for tactic in mitre_object["kill_chain_phases"] if tactic["kill_chain_name"] == "mitre-attack")

                    fixture.append({
                        "model": "event_tracker.attacktechnique",
                        "fields": {
                            "mitre_id": reference["external_id"],
                            "name": mitre_object["name"],
                            "tactics": tactics,
                            "detection_advice": mitre_object["x_mitre_detection"]
                        }
                    })

    # ----

    for mitre_object in mitre_data["objects"]:
        if "revoked" in mitre_object and mitre_object["revoked"] is True:
            continue

        # Sub techniques
        elif mitre_object["type"] == "attack-pattern" and (
                "x_mitre_is_subtechnique" in mitre_object and
                mitre_object["x_mitre_is_subtechnique"] is True):
            for reference in mitre_object["external_references"]:
                if reference["source_name"] == "mitre-attack":
                    print("**** " + reference["external_id"] + " " + mitre_object["name"])
                    fixture.append({
                        "model": "event_tracker.attacksubtechnique",
                        "fields": {
                            "mitre_id": reference["external_id"],
                            "name": mitre_object["name"],
                            "parent_technique": [reference["external_id"].split(".", 1)[0]],
                            "detection_advice": mitre_object["x_mitre_detection"]
                        }
                    })

    with open("mitre-fixture.json", "w") as fixture_fp:
        json.dump(fixture, fixture_fp)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        load_and_create(sys.argv[1])
    else:
        fetch_and_create()
