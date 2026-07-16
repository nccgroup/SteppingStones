import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential

privcheck_bof_regex = re.compile(
    r"^\[CREDMANAGER\] --- Credential \[\d+\] ---\n"
    r"(?:\[CREDMANAGER\]   Target: (?P<system>.+)\n)?"
    r"(?:\[CREDMANAGER\]   User:   (?P<account>.+)\n)?"
    r"\[CREDMANAGER\]   Secret: (?P<secret>.+)",
    flags=re.MULTILINE)

_EMPTY_SECRET = "<empty or protected>"


class PrivCheckBOFExtractor(CredentialExtractorGenerator):
    """
    Extractor for the SAL-BOF Privcheck Credential Manager BOF output.
    Target and User lines are omitted when NULL; Secret is always present
    but may be "<empty or protected>".
    """

    def cred_generator(self, input_text: str, default_system: str):
        for match in privcheck_bof_regex.finditer(input_text):
            d = match.groupdict()
            secret = d["secret"] if d["secret"] != _EMPTY_SECRET else None
            yield Credential(
                system=d["system"] or default_system,
                account=d["account"],
                secret=secret,
                purpose="Stored Credentials",
                source="SAL-BOF Privcheck")
