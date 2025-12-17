import re

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.libs.outflank.ticket_to_hashcat import TicketConverter
from event_tracker.models import Credential

outflank_kerberoast_regex = re.compile(r'<TICKET>\s+(?P<ticket>sAMAccountName = (?P<account>\S+)\n[^<]*)</TICKET>')


class OutflankKerberoastExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in outflank_kerberoast_regex.finditer(input_text):
            hash_type, hash, system, purpose = TicketConverter.convert_ticket(match.groupdict()["ticket"])
            yield Credential(hash=hash, account=match.groupdict()["account"],
                             hash_type=hash_type, system=system,
                             purpose=f"Windows Login (used by SPN: {purpose})",
                             source="Outflank Kerberoasting")
