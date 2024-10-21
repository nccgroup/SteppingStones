import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential

sprayad = re.compile(
    r'\[\+] Password correct for useraccount\(s\):\n(?P<allaccounts>.*?)\n-{68}.*?Domain tested: (?P<system>\S+).*?Password tested: (?P<secret>\S+)',
    re.DOTALL)


class SprayADExtractor(CredentialExtractorGenerator):
    """
    Extractor for https://github.com/outflanknl/C2-Tool-Collection/tree/main/BOF/SprayAD
    """

    def cred_generator(self, input_text: str, default_system: str):
        for match in sprayad.finditer(input_text):
            match_dict = match.groupdict()
            for account in match_dict.pop("allaccounts").split('\n'):
                yield Credential(**match_dict,
                                 account=account.strip(),
                                 purpose="Kerberos Login",
                                 source="Outflank Spray-AD BOF")
