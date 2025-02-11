import concurrent
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple, Set

from event_tracker.models import AttackTactic, AttackSubTechnique, AttackTechnique
from event_tracker.event_detail_suggester.yara_suggester import YaraSuggester

executor = ThreadPoolExecutor()

suggester_classes = [YaraSuggester]


def generate_suggestions(event_form) -> Tuple[Set, List[Dict[str, object]]]:
    description_suggestions = set()
    mitre_suggestions = []

    suggestions = []

    # Lookup the objects from the DB as part of the validation, we don't care if it is valid or not.
    event_form.is_valid()

    functions = [subclass().get_suggestions for subclass in suggester_classes]
    futures = []
    for function in functions:
        futures.append(executor.submit(function, event_form.cleaned_data["raw_evidence"]))
    for future in concurrent.futures.as_completed(futures):
        suggestions += future.result()

    for description, tactic, technique in suggestions:
        if description and ("description" not in event_form.cleaned_data or description != event_form.cleaned_data["description"]):
            description_suggestions.add(description)

        mitre_suggestion = {}
        mitre_suggestion["mitre_attack_tactic"] = AttackTactic.objects.get(mitre_id=tactic)
        if technique:
            if "." in technique:
                # We're actually dealing with a subtechnique
                mitre_suggestion["mitre_attack_subtechnique"] = AttackSubTechnique.objects.get(mitre_id=technique)
                technique = technique.split(".")[0]
            mitre_suggestion['mitre_attack_technique'] = AttackTechnique.objects.get(mitre_id=technique)

        # Skip the suggestion if it's the current TTP
        if event_form.cleaned_data["mitre_attack_tactic"] and mitre_suggestion["mitre_attack_tactic"] != event_form.cleaned_data["mitre_attack_tactic"]:
            # The tactics are different, it's a good suggestion
            pass
        elif event_form.cleaned_data["mitre_attack_technique"] and 'mitre_attack_technique' in mitre_suggestion and mitre_suggestion["mitre_attack_technique"] != event_form.cleaned_data["mitre_attack_technique"]:
            # The technique are different, it's a good suggestion
            pass
        elif bool(event_form.cleaned_data["mitre_attack_technique"]) ^ bool('mitre_attack_technique' in mitre_suggestion):
            # Only one of the two has a technique, so the suggestions can't be same
            pass
        elif event_form.cleaned_data["mitre_attack_subtechnique"] and 'mitre_attack_subtechnique' in mitre_suggestion and mitre_suggestion["mitre_attack_subtechnique"] != event_form.cleaned_data["mitre_attack_subtechnique"]:
            # The subtechnique are different, it's a good suggestion
            pass
        elif bool(event_form.cleaned_data["mitre_attack_subtechnique"]) ^ bool('mitre_attack_subtechnique' in mitre_suggestion):
            # Only one of the two has a subtechnique, so the suggestions can't be same
            pass
        else:
            # Skip this suggestion
            continue

        mitre_suggestions.append(mitre_suggestion)

    return description_suggestions, mitre_suggestions
