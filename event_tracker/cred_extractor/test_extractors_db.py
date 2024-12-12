import django.test

from event_tracker.cred_extractor.extractor import extract_and_save, extract
from event_tracker.models import Credential


class ExtractorTestCaseWithDB(django.test.TestCase):

    def test_rubeus_kerberoast_crlf(self):
        # Hash from HashCat example hashes
        result, _ = extract("""
[*] SamAccountName         : USER\r
[*] DistinguishedName      : CN=USER,OU=Service Accounts,OU=Non-Personal,OU=Accounts,OU=Brand,DC=domain,DC=local\r
[*] ServicePrincipalName   : test/spn\r
[*] PwdLastSet             : 06/03/2013 20:40:54\r
[*] Supported ETypes       : RC4_HMAC_DEFAULT\r
[*] Hash                   : $krb5tgs$23$*user$realm$test/spn*$63386D22D359FE42230300D56852C9EB$891AD31D09AB8\r
                             9C6B3B8C5E5DE6C06A7F49FD559D7A9A3C32576C8FEDF705376CEA582AB5938F7FC8BC741ACF05C5\r
                             990741B36EF4311FE3562A41B70A4EC6ECBA849905F2385BB3799D92499909658C7287C49160276B\r
                             CA0006C350B0DB4FD387ADC27C01E9E9AD0C20ED53A7E6356DEE2452E35ECA2A6A1D1432796FC5C1\r
                             9D068978DF74D3D0BAF35C77DE12456BF1144B6A750D11F55805F5A16ECE2975246E2D026DCE997F\r
                             BA34AC8757312E9E4E6272DE35E20D52FB668C5ED\r

        """, "DUMMY")
        self.assertEqual(1, len(result))
        self.assertEqual("realm", result[0].system)
        self.assertEqual("USER", result[0].account)

    def test_rubeus_kerberoast_lf(self):
        # Hash from HashCat example hashes
        result, _ = extract("""
[*] SamAccountName         : USER
[*] DistinguishedName      : CN=USER,OU=Service Accounts,OU=Non-Personal,OU=Accounts,OU=Brand,DC=domain,DC=local
[*] ServicePrincipalName   : test/spn
[*] PwdLastSet             : 06/03/2013 20:40:54
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*user$realm$test/spn*$63386D22D359FE42230300D56852C9EB$891AD31D09AB8
                             9C6B3B8C5E5DE6C06A7F49FD559D7A9A3C32576C8FEDF705376CEA582AB5938F7FC8BC741ACF05C5
                             990741B36EF4311FE3562A41B70A4EC6ECBA849905F2385BB3799D92499909658C7287C49160276B
                             CA0006C350B0DB4FD387ADC27C01E9E9AD0C20ED53A7E6356DEE2452E35ECA2A6A1D1432796FC5C1
                             9D068978DF74D3D0BAF35C77DE12456BF1144B6A750D11F55805F5A16ECE2975246E2D026DCE997F
                             BA34AC8757312E9E4E6272DE35E20D52FB668C5ED

        """, "DUMMY")
        self.assertEqual(1, len(result))
        self.assertEqual("realm", result[0].system)
        self.assertEqual("USER", result[0].account)
