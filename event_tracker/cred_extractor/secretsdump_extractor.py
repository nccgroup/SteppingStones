import re

from event_tracker.cred_extractor import CredentialExtractorGenerator, valid_windows_domain, valid_windows_username, \
    EMPTY_LMHASH, EMPTY_NTLMHASH
from event_tracker.models import Credential, HashCatMode

secretsdump_dcsync_regex = re.compile(
    r'^(?:\[.+] )*(?:(?P<system>' + valid_windows_domain + r'?)\\)?(?P<account>' + valid_windows_username +
    r')(?::\d+)?:(?P<lmhash>[a-f0-9]{32}):(?P<ntlmhash>[a-f0-9]{32}):::', flags=re.MULTILINE)


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
