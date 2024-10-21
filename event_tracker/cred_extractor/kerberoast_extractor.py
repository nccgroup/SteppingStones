import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential

plain_kerberoast_regex = re.compile(
    r"(?P<hash>\$krb5tgs\$\d\d?\$\*?(?P<account>.+?)\$(?P<system>.+?)\$(?P<purpose>.+?)\*\$.{1000,})")


class PlainKerberoastExtractor(CredentialExtractorGenerator):

    def cred_generator(self, input_text: str, default_system: str):

        for match in plain_kerberoast_regex.finditer(input_text):
            hash_str = match.groupdict()["hash"]

            hash_type = -1
            if hash_str.startswith("$krb5tgs$23$"):
                hash_type = 13100
            elif hash_str.startswith("$krb5tgs$18$"):
                hash_type = 19700
                hash_str = convert_tgs_to_hashcat_format(hash_str)
            elif hash_str.startswith("$krb5tgs$17$"):
                hash_type = 19600
            elif hash_str.startswith("$krb5tgs$3$"):
                print("Encountered a DES TGS(!) skipping because hashcat doesn't support")
                continue

            yield Credential(hash=hash_str.rstrip(), account=match.groupdict()["account"],
                             hash_type=hash_type,
                             system=match.groupdict()["system"] or default_system,
                             purpose=f"Windows Login (used by SPN: {match.groupdict()['purpose']})",
                             source="Kerberoasting")


def convert_tgs_to_hashcat_format(hash):
    return re.sub(r"\$\*.*?\*\$", "$", hash)
