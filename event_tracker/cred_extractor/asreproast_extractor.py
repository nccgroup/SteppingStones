import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential, HashCatMode

plain_asrep_regex = re.compile(r'(?P<hash>\$krb5asrep\$(?P<etype>\d\d?)\$(?P<account>.+?)@(?P<system>.+?)[:$](?P<tail>.{400,}))')

ETYPE_TO_HASHCAT_MODE = {
    "17": HashCatMode.Kerberos_5_ASREP_AES128,
    "18": HashCatMode.Kerberos_5_ASREP_AES256,
    "23": HashCatMode.Kerberos_5_ASREP_RC4,
}

# Older AS-REP capture tools emit etype 17/18 hashes as a single hex blob (account@realm$blob) rather
# than hashcat's expected account$realm$checksum$ciphertext. The checksum is always the trailing 12
# bytes (24 hex chars) of the blob, so split it out and reorder to match hashcat modes 32100/32200.
def _normalise_aes_asrep(etype: str, account: str, system: str, tail: str) -> str:
    if "$" in tail:
        # Already split into checksum$ciphertext
        return f"$krb5asrep${etype}${account}${system}${tail}"

    checksum, ciphertext = tail[-24:], tail[:-24]
    return f"$krb5asrep${etype}${account}${system}${checksum}${ciphertext}"


class PlainASREPRoastExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in plain_asrep_regex.finditer(input_text):
            groups = match.groupdict()
            etype = groups.pop("etype")
            tail = groups.pop("tail")
            account, system = groups["account"], groups["system"]

            if etype in ("17", "18"):
                groups["hash"] = _normalise_aes_asrep(etype, account, system, tail)

            yield Credential(**groups,
                             hash_type=ETYPE_TO_HASHCAT_MODE.get(etype, HashCatMode.Unlisted),
                             purpose="Windows Login",
                             source="ASREPRoasting")
