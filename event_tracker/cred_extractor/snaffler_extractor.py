import re

from event_tracker.cred_extractor import CredentialExtractor
from event_tracker.models import Credential

snaffler_finding = re.compile(r'\[.+] \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z \[(File|Share)\] \{(Red|Yellow|Green)\}<(?P<ainfo>.+?)>\((?P<binfo>.+?)\) (?P<cinfo>.*)')
net_user_add_command = re.compile(r'net user (/add )?((?P<system>\S+)\\)?(?P<account>\S+) (?P<secret>\S+)$')
net_use_command = re.compile(r'net use (?:\S+ )?(?P<purpose>\\\S+)(?=.*/user)(?: /user:((?P<system>\S+)\\)?(?P<account>\S+)| (?P<secret>[^/]\S+)| /\S+){2,}?', re.IGNORECASE + re.MULTILINE)
dotnet_connection_string = re.compile(r'\"(;?\s*User ID=(?P<account>[^;\"]+)|;?\s*Password=(?P<secret>[^;\"]+)|;?\s*(Data Source|Server)=(?P<system>[^;\"]+)|;?[^\";]+)+', re.IGNORECASE)

class SnafflerExtractor(CredentialExtractor):
    def extract(self, input_text: str, default_system: str) -> [Credential]:
        result = []

        for match in snaffler_finding.finditer(input_text):
            if match["ainfo"].startswith("KeepCmdCredentials|"):
                content = self.unescape_content(match)

                for innermatch in net_user_add_command.finditer(content):
                    if innermatch.group("secret"):
                        result.append(Credential(**innermatch.groupdict(),
                                               purpose="Automated user creation",
                                               source=match['binfo'],
                                               source_time=match['ainfo'].split('|')[-1]))

                for innermatch in net_use_command.finditer(content):
                    if innermatch.group("secret"):
                        innermatch_dict = remove_quotes(innermatch.groupdict())
                        result.append(Credential(**innermatch_dict,
                                               source=match['binfo'],
                                               source_time=match['ainfo'].split('|')[-1]))

            if match["ainfo"].startswith("KeepCSharpDbConnStringsRed|"):
                content = self.unescape_content(match)
                for innermatch in dotnet_connection_string.finditer(content):
                    if innermatch.group("secret"):
                        innermatch_dict = remove_quotes(innermatch.groupdict())
                        result.append(Credential(**innermatch_dict,
                                               source=match['binfo'],
                                               source_time=match['ainfo'].split('|')[-1]))

        return result

    def unescape_content(self, match):
        content = re.sub(r'\\r', r'\r', match["cinfo"])
        content = re.sub(r'\\n', r'\n', content)
        content = re.sub(r'\\t', r'\t', content)
        content = re.sub(r'\\([\\*+?|{\[()^$.# ])', r'\1', content)
        return content


def remove_quotes(input_dict):
    result = input_dict.copy()
    for key, value in input_dict.items():
        if value and ((value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'"))):
            result[key] = value[1:-1]
    return result
