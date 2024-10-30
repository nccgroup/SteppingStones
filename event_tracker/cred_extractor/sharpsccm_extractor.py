import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential

naa_regex = re.compile(
    r"^ {4}NetworkAccessUsername: (?P<system>.+)\\(?P<account>\S+)\n {4}NetworkAccessPassword: (?P<secret>.*)$",
    flags=re.MULTILINE)


class SharpSCCMNAAExtractor(CredentialExtractorGenerator):
    """
    Extractor for https://github.com/Mayyhem/SharpSCCM
    """

    def cred_generator(self, input_text: str, default_system: str):
        for match in naa_regex.finditer(input_text):
            yield Credential(**match.groupdict(),
                             purpose="SCCM Network Access Account",
                             source="SharpSCCM")
