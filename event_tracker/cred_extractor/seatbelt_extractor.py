import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential

credenum_regex = re.compile(
    r"  Target {14}: (?P<system>.+)\n  UserName {12}: (?P<account>.+)\n  Password {12}: (?P<secret>.+)\n",
    flags=re.MULTILINE)


class CredEnumExtractor(CredentialExtractorGenerator):
    """
    Extractor for https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Commands/Windows/CredEnumCommand.cs
    """

    def cred_generator(self, input_text: str, default_system: str):
        for match in credenum_regex.finditer(input_text):
            match_dict = match.groupdict()

            # Teams stores creds hex encoded in the cred store, so decode
            secret = match_dict.pop("secret")
            if secret and re.match("^([0-9A-f]{2} )+[0-9A-f]{2}$", secret, re.IGNORECASE):
                secret = bytes.fromhex(secret).decode("utf-8")

            yield Credential(**match_dict, secret=secret,
                             purpose="Stored Credentials",
                             source="Seatbelt CredEnum")
