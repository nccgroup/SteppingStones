import re

from event_tracker.cred_extractor import CredentialExtractorGenerator, EMPTY_LMHASH, EMPTY_NTLMHASH
from event_tracker.models import Credential, HashCatMode

ldap_shell_laps = re.compile(
    r"get_laps_password (?P<system>.+)\s+?Found Computer DN:.+\s+?LAPS Password: (?P<secret>.+)$", re.MULTILINE)


class LDAPShellLAPSExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in ldap_shell_laps.finditer(input_text):
            yield Credential(**match.groupdict(), purpose="Windows LAPS Password", source="LDAP")
