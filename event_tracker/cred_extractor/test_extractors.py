import django.test

from event_tracker.cred_extractor.extractor import extract
from event_tracker.models import HashCatMode


class MyTestCase(django.test.TestCase):
    def test_netntlmv1(self):
        # Hash from hashcat sample hashes
        result = extract(
            "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c",
            "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual(result[0].system, "kNS")
        self.assertEqual(result[0].account, "u4-netntlm")
        self.assertEqual(result[0].hash_type, HashCatMode.NetNTLMv1)

    def test_netntlmv2(self):
        # Hash from hashcat sample hashes
        result = extract(
            "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030",
            "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual(result[0].system, "N46iSNekpT")
        self.assertEqual(result[0].account, "admin")
        self.assertEqual(result[0].hash_type, HashCatMode.NetNTLMv2)


    def test_dcc2(self):
        # Hash from hashcat sample hashes, embedded in secrets dump output
        result = extract(
            """
[*] Dumping cached domain logon information (domain/username:hash)
DOMAIN.COMPANY.COM/tom:$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f: (2024-10-17 12:31:41)
""",
            "DUMMY")

        self.assertEqual(1, len(result))
        self.assertEqual("DOMAIN.COMPANY.COM", result[0].system)
        self.assertEqual("tom", result[0].account)
        self.assertEqual(result[0].hash_type, HashCatMode.Domain_Cached_Credentials_2)

