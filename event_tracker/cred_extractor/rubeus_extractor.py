import re

from django.db.models import CharField, Value
from django.db.models.functions import Length, StrIndex

from event_tracker.cred_extractor import CredentialExtractorGenerator
from event_tracker.cred_extractor.kerberoast_extractor import convert_tgs_to_hashcat_format
from event_tracker.models import Credential, HashCatMode

rubeus_kerberoast_regex = re.compile(
    r'\[\*] SamAccountName {9}: (?P<account>.+)\r?\n.*\n\[\*] ServicePrincipalName   : (?P<purpose>.+)\r?\n(?:\[\*].*\n)*?\[\*] Hash {19}: (?P<hash>\$krb5tgs\$.+\$(?P<system>.*?)(?<!\*)\$[^$]+\$.+\n(?:.{29}.+\n)+)')
rubeus_asrep_regex = re.compile(r'(?P<hash>\$krb5asrep\$(?!\d\d?\$)(?P<account>.+?)@(?P<system>.+?):[A-F0-9$\s]{400,})')
rubeus_u2u_ntlm_regex = re.compile(
    r'^  UserName                 :  (?P<account>\S+).*^  UserRealm                :  (?P<system>\S+).+\[*] Getting credentials using U2U.*NTLM              : (?P<hash>\S+)',
    flags=re.DOTALL + re.MULTILINE)


class RubeusU2UExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in rubeus_u2u_ntlm_regex.finditer(input_text):
            yield Credential(**match.groupdict(), hash_type=HashCatMode.NTLM,
                             purpose="Windows Login", source="Rubeus U2U")


class RubeusKerberoastExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in rubeus_kerberoast_regex.finditer(input_text):
            hash_str = match.groupdict()["hash"].replace(" ", "").replace("\n", "").replace("\r", "")

            hash_type = -1
            if hash_str.startswith("$krb5tgs$23$"):
                hash_type = 13100
            elif hash_str.startswith("$krb5tgs$18$"):
                hash_type = 19700
                hash_str = convert_tgs_to_hashcat_format(hash_str)
            elif hash_str.startswith("$krb5tgs$17$"):
                hash_type = 19600

            yield Credential(hash=hash_str, account=match.groupdict()["account"],
                             hash_type=hash_type, system=match.groupdict()["system"] or default_system,
                             purpose=f"Windows Login (used by SPN: {match.groupdict()['purpose'].strip()})",
                             source="Rubeus Kerberoasting")

            # Remove any similar but truncated hashes which haven't cracked, these are a result of stream processing kicking
            # in before the multiline kerberos ticket has been fully parsed from CS logs
            CharField.register_lookup(Length)
            Credential.objects.filter(account=match.groupdict()["account"],
                                      hash_type=hash_type, system=match.groupdict()["system"] or default_system,
                                      purpose=f"Windows Login (used by SPN: {match.groupdict()['purpose'].strip()})",
                                      source="Rubeus Kerberoasting") \
                .filter(hash__length__lt=len(hash_str), secret__isnull=True) \
                .annotate(stri=StrIndex(Value(hash_str), "hash")).filter(stri=1) \
                .delete()


class RubeusASREPRoastExtractor(CredentialExtractorGenerator):
    def cred_generator(self, input_text: str, default_system: str):
        for match in rubeus_asrep_regex.finditer(input_text):
            hash_str = match.groupdict()["hash"].replace(" ", "").replace("\n", "").replace("\r", "") \
                .replace("$krb5asrep$", "$krb5asrep$23$")

            yield Credential(hash=hash_str, account=match.groupdict()["account"],
                             hash_type=18200, system=match.groupdict()["system"] or default_system,
                             purpose="Windows Login",
                             source="Rubeus ASREPRoasting")
