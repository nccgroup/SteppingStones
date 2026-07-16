import django.test

from event_tracker.cred_extractor.extractor import extract
from event_tracker.models import HashCatMode


class ExtractorTestCase(django.test.SimpleTestCase):
    def test_netntlmv1(self):
        # Hash from hashcat sample hashes
        result, _ = extract(
            "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c",
            "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual(result[0].system, "kNS")
        self.assertEqual(result[0].account, "u4-netntlm")
        self.assertEqual(result[0].hash_type, HashCatMode.NetNTLMv1)

    def test_netntlmv2(self):
        # Hash from hashcat sample hashes
        result, _ = extract(
            "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030",
            "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual(result[0].system, "N46iSNekpT")
        self.assertEqual(result[0].account, "admin")
        self.assertEqual(result[0].hash_type, HashCatMode.NetNTLMv2)


    def test_dcc2(self):
        # Hash from hashcat sample hashes, embedded in secrets dump output
        result, _ = extract(
            """
[*] Dumping cached domain logon information (domain/username:hash)
DOMAIN.COMPANY.COM/tom:$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f: (2024-10-17 12:31:41)
""",
            "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual("DOMAIN.COMPANY.COM", result[0].system)
        self.assertEqual("tom", result[0].account)
        self.assertEqual(result[0].hash_type, HashCatMode.Domain_Cached_Credentials_2)

    def test_secretsdump_local_users_datestamped(self):
        # Hash from hashcat sample hashes, embedded in secrets dump output
        result, _ = extract(
            """
[2024-10-16 16:12:05] [*] Administrator:500:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::
[2024-10-16 16:12:07] [*] Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[2024-10-16 16:12:09] [*] DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[2024-10-16 16:12:12] [*] WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::
""",
            "DUMMY")

        self.assertEqual(2, len(result))
        self.assertEqual("DUMMY", result[0].system)
        self.assertEqual("Administrator", result[0].account)
        self.assertEqual("WDAGUtilityAccount", result[1].account)
        self.assertEqual(result[0].hash_type, HashCatMode.NTLM)
        self.assertEqual(result[1].hash_type, HashCatMode.NTLM)

    def test_secretsdump_machine_account(self):
        # Hash from hashcat sample hashes, embedded in secrets dump output
        result, _ = extract(r"""
[2024-10-16 16:12:23] [*] DOMAIN\HOST$:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::
""", "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual("DOMAIN", result[0].system)
        self.assertEqual("HOST$", result[0].account)
        self.assertEqual(result[0].hash_type, HashCatMode.NTLM)

    def test_sharpsccm_naa(self):
        # Hash from hashcat sample hashes, embedded in secrets dump output
        result, _ = extract(r"""
[+] Decrypting network access account credentials

    NetworkAccessUsername: DOMAIN\USER
    NetworkAccessPassword: Password123
""", "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual("DOMAIN", result[0].system)
        self.assertEqual("USER", result[0].account)
        self.assertEqual("Password123", result[0].secret)

    def test_privcheck_credmanager_full(self):
        result, _ = extract("""[CREDMANAGER] Found 1 credential(s)
[CREDMANAGER] --- Credential [1] ---
[CREDMANAGER]   Target: somehost
[CREDMANAGER]   User:   jsmith
[CREDMANAGER]   Secret: Password123
""", "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual("somehost", result[0].system)
        self.assertEqual("jsmith", result[0].account)
        self.assertEqual("Password123", result[0].secret)
        self.assertEqual("SAL-BOF Privcheck", result[0].source)

    def test_privcheck_credmanager_no_target_uses_default(self):
        result, _ = extract("""[CREDMANAGER] --- Credential [1] ---
[CREDMANAGER]   User:   jsmith
[CREDMANAGER]   Secret: Password123
""", "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual("DUMMY", result[0].system)
        self.assertEqual("jsmith", result[0].account)

    def test_privcheck_credmanager_no_user(self):
        result, _ = extract("""[CREDMANAGER] --- Credential [1] ---
[CREDMANAGER]   Target: somehost
[CREDMANAGER]   Secret: Password123
""", "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual("somehost", result[0].system)
        self.assertIsNone(result[0].account)

    def test_privcheck_credmanager_empty_secret(self):
        result, _ = extract("""[CREDMANAGER] --- Credential [1] ---
[CREDMANAGER]   Target: somehost
[CREDMANAGER]   User:   jsmith
[CREDMANAGER]   Secret: <empty or protected>
""", "DUMMY")

        self.assertEqual(1, len(result))
        self.assertIsNone(result[0].secret)

    def test_privcheck_credmanager_multiple_full(self):
        result, _ = extract("""[CREDMANAGER] Found 3 credential(s)
[CREDMANAGER] --- Credential [1] ---
[CREDMANAGER]   Target: fileserver
[CREDMANAGER]   User:   alice
[CREDMANAGER]   Secret: PasswordOne
[CREDMANAGER] --- Credential [2] ---
[CREDMANAGER]   Target: mailserver
[CREDMANAGER]   User:   bob
[CREDMANAGER]   Secret: PasswordTwo
[CREDMANAGER] --- Credential [3] ---
[CREDMANAGER]   Target: vpngateway
[CREDMANAGER]   User:   carol
[CREDMANAGER]   Secret: PasswordThree
[CREDMANAGER] Enumeration complete: 3 credential(s) found
""", "DUMMY")

        privcheck_results = sorted(
            [c for c in result if c.source == "SAL-BOF Privcheck"],
            key=lambda c: c.system)
        self.assertEqual(3, len(privcheck_results))
        self.assertEqual("fileserver",  privcheck_results[0].system)
        self.assertEqual("alice",       privcheck_results[0].account)
        self.assertEqual("PasswordOne", privcheck_results[0].secret)
        self.assertEqual("mailserver",  privcheck_results[1].system)
        self.assertEqual("bob",         privcheck_results[1].account)
        self.assertEqual("PasswordTwo", privcheck_results[1].secret)
        self.assertEqual("vpngateway",    privcheck_results[2].system)
        self.assertEqual("carol",         privcheck_results[2].account)
        self.assertEqual("PasswordThree", privcheck_results[2].secret)

    def test_privcheck_credmanager_multiple_mixed_optional_fields(self):
        # First credential has all fields; second has no User; third has no Target and an empty secret
        result, _ = extract("""[CREDMANAGER] Found 3 credential(s)
[CREDMANAGER] --- Credential [1] ---
[CREDMANAGER]   Target: fileserver
[CREDMANAGER]   User:   alice
[CREDMANAGER]   Secret: PasswordOne
[CREDMANAGER] --- Credential [2] ---
[CREDMANAGER]   Target: mailserver
[CREDMANAGER]   Secret: PasswordTwo
[CREDMANAGER] --- Credential [3] ---
[CREDMANAGER]   User:   carol
[CREDMANAGER]   Secret: <empty or protected>
[CREDMANAGER] Enumeration complete: 3 credential(s) found
""", "DUMMY")

        privcheck_results = sorted(
            [c for c in result if c.source == "SAL-BOF Privcheck"],
            key=lambda c: c.system)
        self.assertEqual(3, len(privcheck_results))

        dummy_cred = next(c for c in privcheck_results if c.system == "DUMMY")
        self.assertEqual("carol", dummy_cred.account)
        self.assertIsNone(dummy_cred.secret)

        file_cred = next(c for c in privcheck_results if c.system == "fileserver")
        self.assertEqual("alice",       file_cred.account)
        self.assertEqual("PasswordOne", file_cred.secret)

        mail_cred = next(c for c in privcheck_results if c.system == "mailserver")
        self.assertIsNone(mail_cred.account)
        self.assertEqual("PasswordTwo", mail_cred.secret)
