import re

import dateparser

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.models import Credential

browser_cred_regex = re.compile(
    r"^(.:[^?*,]+),https?://[^\s]+,(https?://[^\s]+),(\d+/\d+/\d+ \d+:\d+:\d+ ?[AP]?M?),\d{16,},([^,]*),([^,\r\n]*)",
    flags=re.MULTILINE)


class BrowserExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        # Look for creds
        for match in browser_cred_regex.finditer(input_text):
            date_str = match.group(3)
            date_parsed = dateparser.parse(date_str, settings={'TO_TIMEZONE': 'UTC'}).replace(tzinfo=timezone.utc)

            yield Credential(source=match.group(1), system=match.group(2),
                             source_time=date_parsed,
                             account=match.group(4), secret=match.group(5),
                             purpose="Web Login")
