import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential, HashCatMode

netntlmv2_regex = re.compile(
    r"(?P<hash>(?P<account>[\w\.]+)::(?P<system>.+):[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]+)", flags=re.MULTILINE)


class NetNTLMv2Extractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in netntlmv2_regex.finditer(input_text):
            yield Credential(**match.groupdict(), purpose="Windows Login", hash_type=HashCatMode.NetNTLMv2)
