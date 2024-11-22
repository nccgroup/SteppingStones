import concurrent
from concurrent.futures import ThreadPoolExecutor

from event_tracker.models import AttackTactic, AttackSubTechnique, AttackTechnique
from event_tracker.mitre_attack_suggester.yara_suggester import YaraSuggester

executor = ThreadPoolExecutor()

suggester_classes = [YaraSuggester]


def generate_suggestions(event_form):
    result = []
    suggestions = []

    # Lookup the objects from the DB as part of the validation, we don't care if it is valid or not.
    event_form.is_valid()

    functions = [subclass().get_suggestions for subclass in suggester_classes]
    futures = []
    for function in functions:
        futures.append(executor.submit(function, event_form.cleaned_data["raw_evidence"]))
    for future in concurrent.futures.as_completed(futures):
        suggestions += future.result()

    for tactic, technique in suggestions:
        suggestion = {}
        suggestion["mitre_attack_tactic"] = AttackTactic.objects.get(mitre_id=tactic)
        if technique:
            if "." in technique:
                # We're actually dealing with a subtechnique
                suggestion["mitre_attack_subtechnique"] = AttackSubTechnique.objects.get(mitre_id=technique)
                technique = technique.split(".")[0]
            suggestion['mitre_attack_technique'] = AttackTechnique.objects.get(mitre_id=technique)

        # Skip the suggestion if it's the current TTP
        if event_form.cleaned_data["mitre_attack_tactic"] and suggestion["mitre_attack_tactic"] != event_form.cleaned_data["mitre_attack_tactic"]:
            # The tactics are different, it's a good suggestion
            pass
        elif event_form.cleaned_data["mitre_attack_technique"] and 'mitre_attack_technique' in suggestion and suggestion["mitre_attack_technique"] != event_form.cleaned_data["mitre_attack_technique"]:
            # The technique are different, it's a good suggestion
            pass
        elif bool(event_form.cleaned_data["mitre_attack_technique"]) ^ bool('mitre_attack_technique' in suggestion):
            # Only one of the two has a technique, so the suggestions can't be same
            pass
        elif event_form.cleaned_data["mitre_attack_subtechnique"] and 'mitre_attack_subtechnique' in suggestion and suggestion["mitre_attack_subtechnique"] != event_form.cleaned_data["mitre_attack_subtechnique"]:
            # The subtechnique are different, it's a good suggestion
            pass
        elif bool(event_form.cleaned_data["mitre_attack_subtechnique"]) ^ bool('mitre_attack_subtechnique' in suggestion):
            # Only one of the two has a subtechnique, so the suggestions can't be same
            pass
        else:
            # Skip this suggestion
            continue

        result.append(suggestion)

    return result
