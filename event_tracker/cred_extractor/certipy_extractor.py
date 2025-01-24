import re

from event_tracker.cred_extractor import CredentialExtractorGenerator, valid_windows_username, valid_windows_domain
from event_tracker.cred_extractor.secretsdump_extractor import EMPTY_LMHASH, EMPTY_NTLMHASH
from event_tracker.models import Credential, HashCatMode

certipy_hash_regex = re.compile(
    r"\[*] Got hash for '(?P<account>[^@]+)@(?P<system>[^']+)': (?P<lmhash>[a-f0-9]{32}):(?P<ntlmhash>[a-f0-9]{32})")


class CertipyHashExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in certipy_hash_regex.finditer(input_text):
            lmhash = match.groupdict()["lmhash"]
            if lmhash.upper() != EMPTY_LMHASH:
                yield Credential(hash=lmhash, system=match.groupdict()["system"] or default_system,
                                 account=match.groupdict()["account"], hash_type=HashCatMode.LM,
                                 purpose="Windows Login", source="Certipy Auth")

            ntlmhash = match.groupdict()["ntlmhash"]
            if ntlmhash != EMPTY_NTLMHASH:
                yield Credential(hash=ntlmhash,
                                 system=match.groupdict()["system"] or default_system,
                                 account=match.groupdict()["account"],
                                 hash_type=HashCatMode.NTLM,
                                 purpose="Windows Login", source="Certipy Auth")
