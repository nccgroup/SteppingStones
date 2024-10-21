import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential

credphisher_regex = re.compile(
    r"\[\+] Collected Credentials:\nUsername: (?:(?P<system>.*)\\)?(?P<account>.*)\nPassword: (?P<secret>.*)\n",
    flags=re.MULTILINE)


class CredPhisherExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in credphisher_regex.finditer(input_text):
            yield Credential(**match.groupdict(), purpose="Windows Login", source="CredPhisher")
