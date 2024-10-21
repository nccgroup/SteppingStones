import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential, HashCatMode

askcreds_regex = re.compile(r"\[\+] Username: (?:(?P<system>.*)\\)?(?P<account>.*)\n\[\+] Password: (?P<secret>.*)\n", flags=re.MULTILINE)

class AskCredsExtractor(CredentialExtractorGenerator):
    """
    Extractor for https://github.com/outflanknl/C2-Tool-Collection/tree/main/BOF/Askcreds
    """
    def cred_generator(self, input_text: str, default_system: str):
        for match in askcreds_regex.finditer(input_text):
            yield Credential(**match.groupdict(), purpose="Windows Login", source="AskCreds")
