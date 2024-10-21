import re

from event_tracker.cred_extractor import CredentialExtractorGenerator, valid_windows_domain, valid_windows_username
from event_tracker.models import Credential, HashCatMode

secretsdump_dcsync_regex = re.compile(
    rf'^(?:(?P<system>{valid_windows_domain}?)\\)?(?P<account>{valid_windows_username}):\d+:(?P<lmhash>[a-f0-9]{{32}}):(?P<ntlmhash>[a-f0-9]{{32}}):::',
    flags=re.MULTILINE)
EMPTY_LMHASH = "AAD3B435B51404EEAAD3B435B51404EE"
EMPTY_NTLMHASH = "31d6cfe0d16ae931b73c59d7e0c089c0"


class SecretsDumpDCSyncExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in secretsdump_dcsync_regex.finditer(input_text):
            lmhash = match.groupdict()["lmhash"]
            if lmhash.upper() != EMPTY_LMHASH:
                yield Credential(hash=lmhash, system=match.groupdict()["system"] or default_system,
                                 account=match.groupdict()["account"], hash_type=HashCatMode.LM,
                                 purpose="Windows Login", source="Impacket secretsdump.py")

            ntlmhash = match.groupdict()["ntlmhash"]
            if ntlmhash != EMPTY_NTLMHASH:
                yield Credential(hash=ntlmhash,
                                 system=match.groupdict()["system"] or default_system,
                                 account=match.groupdict()["account"],
                                 hash_type=HashCatMode.NTLM,
                                 purpose="Windows Login", source="Impacket secretsdump.py")
