import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential

plain_asrep_regex = re.compile(r'(?P<hash>\$krb5asrep\$\d\d?\$(?P<account>.+?)@(?P<system>.+?):.{400,})')


class PlainASREPRoastExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in plain_asrep_regex.finditer(input_text):
            yield Credential(**match.groupdict(),
                             hash_type=18200,
                             purpose="Windows Login",
                             source="ASREPRoasting")
