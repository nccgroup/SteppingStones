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
sql_account_creation = re.compile(r"CREATE (USER|LOGIN)\s+(=\s+)?[nN]?(['\"]?)(?P<account>\S+)(\3).{0,200}\s+(IDENTIFIED BY|WITH PASSWORD)\s+(=\s+)?[nN]?(['\"]?)(?P<secret>\S+)(\8)", re.IGNORECASE)

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

            if  finding["matchedclassifier"] == "KeepSqlAccountCreation":
                content = self.unescape_content(finding["matchcontext"])
                for innermatch in sql_account_creation.finditer(content):
                    if innermatch.group("secret"):
                        candidate = Credential(**innermatch.groupdict(),
                                                 source=finding['filepath'],
                                                 source_time=finding['modifiedstamp'],
                                                 purpose='SQL Account Creation')
                        if not self.is_garbage(candidate):
                            result.append(candidate)

        return result, []

    def is_garbage(self, credential):
        # If the username and secret both appear to be variable placeholders (i.e. both start with common placeholder symbols)
        if credential.account[0] == credential.secret[0] and credential.account[0] in "$&{":
            return True
        # If the username is just made up of symbols, it's unlikely to be parsed properly
        elif not any(c.isalnum() for c in credential.account):
            return True
        else:
            return False

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
