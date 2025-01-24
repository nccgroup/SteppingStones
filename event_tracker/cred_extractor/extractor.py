import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

from django.db import transaction
from django.forms import model_to_dict

from event_tracker.cred_extractor.askcreds_extractor import AskCredsExtractor
from event_tracker.cred_extractor.asreproast_extractor import PlainASREPRoastExtractor
from event_tracker.cred_extractor.browser_extractor import BrowserExtractor
from event_tracker.cred_extractor.certipy_extractor import CertipyHashExtractor
from event_tracker.cred_extractor.credphisher_extractor import CredPhisherExtractor
from event_tracker.cred_extractor.domaincachedcredentials2_extractor import DCC2Extractor
from event_tracker.cred_extractor.kerberoast_extractor import PlainKerberoastExtractor
from event_tracker.cred_extractor.netntlmv1_extractor import NetNTLMv1Extractor
from event_tracker.cred_extractor.netntlmv2_extractor import NetNTLMv2Extractor
from event_tracker.cred_extractor.outflankkerberoast_extractor import OutflankKerberoastExtractor
from event_tracker.cred_extractor.rubeus_extractor import RubeusU2UExtractor, RubeusKerberoastExtractor, \
    RubeusASREPRoastExtractor
from event_tracker.cred_extractor.seatbelt_extractor import CredEnumExtractor
from event_tracker.cred_extractor.secretsdump_extractor import SecretsDumpDCSyncExtractor
from event_tracker.cred_extractor.sharpsccm_extractor import SharpSCCMNAAExtractor
from event_tracker.cred_extractor.snaffler_extractor import SnafflerExtractor
from event_tracker.cred_extractor.sprayad_extractor import SprayADExtractor
from event_tracker.models import Credential

executor = ThreadPoolExecutor()

extractor_classes = [SnafflerExtractor, BrowserExtractor, NetNTLMv1Extractor, NetNTLMv2Extractor,
                     AskCredsExtractor, CredPhisherExtractor, DCC2Extractor, SprayADExtractor, CredEnumExtractor,
                     OutflankKerberoastExtractor, RubeusU2UExtractor, RubeusKerberoastExtractor,
                     RubeusASREPRoastExtractor,
                     PlainKerberoastExtractor, PlainASREPRoastExtractor, SecretsDumpDCSyncExtractor,
                     SharpSCCMNAAExtractor, CertipyHashExtractor]


@transaction.atomic
def extract_and_save(input_text: str, default_system: str) -> tuple[int, int]:
    credentials_to_add, credentials_to_delete = extract(input_text, default_system)
    saved_secrets = 0

    creds_to_add_in_bulk = []
    for cred in credentials_to_add:
        if cred.secret:
            # post-save action should be called, as we have a secret
            # use keys_to_save as a pseudo-uniqueness constraint for this write operation
            keys_to_save = ['source', 'source_time', 'system', 'account', 'secret', 'hash', 'hash_type', 'purpose', 'enabled']
            saved_credential, created = Credential.objects.get_or_create(**{key: model_to_dict(cred)[key] for key in keys_to_save})
            if created:
                saved_secrets += 1
        else:
            creds_to_add_in_bulk.append(cred)

    # A before and after count may be incorrect if other users are concurrently modifying the table,
    # but it's the best we have given the bulk operations don't return meaningful objects.
    pre_insert_count = Credential.objects.count()
    Credential.objects.bulk_create(creds_to_add_in_bulk, ignore_conflicts=True,
                                   unique_fields=["hash", "hash_type", "account", "system"])

    for obj in credentials_to_delete:
        obj.delete()

    return Credential.objects.count() - pre_insert_count, saved_secrets


def extract(input_text: str, default_system: str) -> ([Credential], [Credential]):
    credentials_to_add = []
    credentials_to_remove = []
    functions = [subclass().extract for subclass in extractor_classes]
    futures = []
    for function in functions:
        futures.append(executor.submit(function, input_text, default_system))
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result is not None:
            to_add, to_remove = result
            credentials_to_add += to_add
            credentials_to_remove += to_remove
    return credentials_to_add, credentials_to_remove
