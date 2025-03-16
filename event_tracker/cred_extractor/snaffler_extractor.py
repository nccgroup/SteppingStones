import csv
import io
import re

from event_tracker.cred_extractor import CredentialExtractor
from event_tracker.models import Credential

snaffler_plaintext_finding = re.compile(r'\[.+] \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z \[(File|Share)\] \{(?P<triagestring>Red|Yellow|Green)\}<(?P<matchedclassifier>.+?)\|(?P<canread>R?)(?P<canwrite>W?)(?P<canmodify>M?)\|(?P<matchedstring>.+?)\|(?P<filesize>.+?)\|(?P<modifiedstamp>.+?)>\((?P<filepath>.+?)\) (?P<matchcontext>.*)')
snaffler_tsv_finding = re.compile(r'\[.+]\t\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z\t\[(File|Share)\]\t(Red|Yellow|Green)\t')
net_user_add_command = re.compile(r'net user (/add )?((?P<system>\S+)\\)?(?P<account>\S+) (?P<secret>\S+)$', re.IGNORECASE + re.MULTILINE)
net_use_command = re.compile(r'net use (?:\S+ )?(?P<purpose>\\\S+)(?=.*/user)(?: /user:((?P<system>\S+)\\)?(?P<account>\S+)| (?P<secret>[^/]\S+)| /\S+){2,}?', re.IGNORECASE + re.MULTILINE)
dotnet_connection_string = re.compile(r'\"(;?\s*User( ID)?=(?P<account>[^;\"]+)|;?\s*Password=(?P<secret>[^;\"]+)|;?\s*(Data Source|Server)=(?P<system>[^;\"]+)|;?[^\";]+)+', re.IGNORECASE)
db_connection_string = re.compile(r'(?=.*Password=)(;?\s*User( ID)?=(?P<account>[^;<>\"]+)|;?\s*Password=(?P<secret>[^;<>\"]+)|;?\s*(Data Source|Server)=(?P<system>[^;<>\"]+)|;?[^;<>\"]+)+', re.IGNORECASE)  # Similar to above, but embedded in XML, so switch quotes to angle brackets
websense_client_password = re.compile(r'WDEUtil[^\n]+-password +(?P<secret>\S+)', re.IGNORECASE)


class SnafflerExtractor(CredentialExtractor):
    def extract(self, input_text: str, default_system: str) -> ([Credential], [Credential]):
        result = []

        if snaffler_plaintext_finding.search(input_text):
            finding_iter = snaffler_plaintext_finding.finditer(input_text)
        elif snaffler_tsv_finding.search(input_text):
            finding_iter = csv.DictReader(io.StringIO(input_text), delimiter='\t', fieldnames=["0", "1", "2", "triagestring", "matchedclassifier", "canread", "canwrite", "canmodify", "matchedstring", "filesize", "modifiedstamp", "filepath", "matchcontext"])
        else:
            # Nothing to do here
            return [], []


        for finding in finding_iter:
            if finding["matchedclassifier"] == "KeepCmdCredentials":
                content = self.unescape_content(finding["matchcontext"])

                for innermatch in net_user_add_command.finditer(content):
                    if innermatch.group("secret"):
                        result.append(Credential(**innermatch.groupdict(),
                                               purpose="Automated user creation",
                                               source=finding['filepath'],
                                               source_time=finding['modifiedstamp']))

                for innermatch in net_use_command.finditer(content):
                    if innermatch.group("secret"):
                        innermatch_dict = remove_quotes(innermatch.groupdict())
                        if 'purpose' in innermatch_dict:
                            innermatch_dict['purpose'] = f"SMB login to use {chr(0x22) + innermatch_dict['purpose'] + chr(0x22)}"
                        else:
                            innermatch_dict['purpose'] = "SMB login"
                        result.append(Credential(**innermatch_dict,
                                               source=finding['filepath'],
                                               source_time=finding['modifiedstamp']))

            if finding["matchedclassifier"] == "KeepCSharpDbConnStringsRed":
                content = self.unescape_content(finding["matchcontext"])
                for innermatch in dotnet_connection_string.finditer(content):
                    if innermatch.group("secret"):
                        innermatch_dict = remove_quotes(innermatch.groupdict())
                        result.append(Credential(**innermatch_dict,
                                               source=finding['filepath'],
                                               source_time=finding['modifiedstamp'],
                                               purpose='Database Credentials'))

            if finding["matchedclassifier"] == "KeepDbConnStringPw":
                content = self.unescape_content(finding["matchcontext"])
                for innermatch in db_connection_string.finditer(content):
                    if innermatch.group("secret"):
                        innermatch_dict = remove_quotes(innermatch.groupdict())
                        result.append(Credential(**innermatch_dict,
                                               source=finding['filepath'],
                                               source_time=finding['modifiedstamp'],
                                               purpose='Database Credentials'))

            if finding["matchedclassifier"] == "KeepPassOrKeyInCode":
                content = self.unescape_content(finding["matchcontext"])
                for innermatch in websense_client_password.finditer(content):
                    if innermatch.group("secret"):
                        innermatch_dict = remove_quotes(innermatch.groupdict())
                        result.append(Credential(**innermatch_dict,
                                               source=finding['filepath'],
                                               source_time=finding['modifiedstamp'],
                                               purpose='Websense Client Password'))

        return result, []

    def unescape_content(self, content):
        # We might be processing a partial output line, in which case we can return the empty string
        # and let the remainder of the code fail to find an inner match.
        if not content:
            return ""

        content = re.sub(r'\\r', r'\r', content)
        content = re.sub(r'\\n', r'\n', content)
        content = re.sub(r'\\t', r'\t', content)
        content = re.sub(r'\\([\\*+?|{\[()^$.# ])', r'\1', content)

        # Recurse if we need to
        if "\\ " in content:
            return self.unescape_content(content)
        else:
            return content


def remove_quotes(input_dict):
    result = input_dict.copy()
    for key, value in input_dict.items():
        if value and ((value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'"))):
            result[key] = value[1:-1]
    return result
