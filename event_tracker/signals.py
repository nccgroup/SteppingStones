import logging
import re
import time
from datetime import datetime, timezone
from typing import List, Optional

import dateparser
import neo4j
import requests
from background_task import background
from django.db import transaction
from django.db.models import CharField, Value
from django.db.models.functions import Length, StrIndex
from django.db.models.signals import post_save
from django.dispatch import receiver
from neo4j import GraphDatabase, Driver

import cobalt_strike_monitor.models
from cobalt_strike_monitor.models import Listener, Beacon, BeaconLog
from cobalt_strike_monitor.poll_team_server import recent_checkin
from event_tracker.libs.outflank.ticket_to_hashcat import TicketConverter
from event_tracker.models import Context, Credential, File, HashCatMode, Webhook, BloodhoundServer, Event
from event_tracker.utils import split_path


@receiver(post_save, sender=Listener)
def cs_listener_to_context(sender, instance: Listener, **kwargs):
    created = False
    context = None

    if instance.althost:
        context, created = Context.objects.get_or_create(host=instance.althost, user="", process="")
    elif instance.host:
        context, created = Context.objects.get_or_create(host=instance.host, user="", process="")
    # else, may be an SMB listener - do nothing

    if created:
        context.save()

    return context


@receiver(post_save, sender=Beacon)
def cs_beacon_to_context(sender, instance: Beacon, **kwargs):
    context, created = Context.objects.get_or_create(process=f"{instance.process.lower()} (PID: {instance.pid})",
                                                     user=instance.user_human,
                                                     host=instance.computer)
    if created:
        context.save()

    return context


@receiver(post_save, sender=cobalt_strike_monitor.models.Credential)
def cs_credential_listener(sender, instance: cobalt_strike_monitor.models.Credential, **kwargs):
    if len(instance.password) > 50 or re.fullmatch("[0-9a-f]{16,}", instance.password, flags=re.IGNORECASE):
        # The "password" in CS looks like a hash

        if len(instance.password) == 32:
            # Looks like a NTLM hash
            hash_type = HashCatMode.NTLM
            credential, created = Credential.objects.get_or_create(
                system=instance.realm,
                account=instance.user,
                hash=instance.password,
                hash_type=hash_type,
                purpose="Windows Login"
            )
        else:
            # Couldn't determine hash type
            credential, created = Credential.objects.get_or_create(
                system=instance.realm,
                account=instance.user,
                hash=instance.password
            )
    else:
        # The "password" in CS is probably truly a password
        credential, created = Credential.objects.get_or_create(
            system=instance.realm,
            account=instance.user,
            secret=instance.password
        )

    if created:
        credential.source = f"{instance.source} {instance.host}"
        credential.source_time = instance.added
        credential.save()

    return credential


browser_cred_regex = re.compile(r"^(.:[^?*,]+),https?://[^\s]+,(https?://[^\s]+),(\d+/\d+/\d+ \d+:\d+:\d+ ?[AP]?M?),\d{16,},([^,]*),([^,\r\n]*)", flags=re.MULTILINE)
netntlmv1_regex = re.compile(r'(?P<hash>(?P<account>.+)::(?P<system>.+):[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16})')
netntlmv2_regex = re.compile(r"(?P<hash>(?P<account>[\w\.]+)::(?P<system>.+):[A-Fa-f0-9]{16}:[A-Fa-f0-9]{32}:[A-Fa-f0-9]+)", flags=re.MULTILINE)
askcreds_regex = re.compile(r"\[\+] Username: (?:(?P<system>.*)\\)?(?P<account>.*)\n\[\+] Password: (?P<secret>.*)\n", flags=re.MULTILINE)
credphisher_regex = re.compile(r"\[\+] Collected Credentials:\nUsername: (?:(?P<system>.*)\\)?(?P<account>.*)\nPassword: (?P<secret>.*)\n", flags=re.MULTILINE)
credenum_regex = re.compile(r"  Target {14}: (?P<system>.+)\n  UserName {12}: (?P<account>.+)\n  Password {12}: (?P<secret>.+)\n", flags=re.MULTILINE)

outflank_kerberoast_regex = re.compile(r'<TICKET>\s+(?P<ticket>sAMAccountName = (?P<account>\S+\n)[^<]*)</TICKET>')
rubeus_kerberoast_regex = re.compile(r'\[\*] SamAccountName {9}: (?P<account>.+)\r?\n.*\n\[\*] ServicePrincipalName   : (?P<purpose>.+)\r?\n(?:\[\*].*\n)*?\[\*] Hash {19}: (?P<hash>\$krb5tgs\$.+\$(?P<system>.*?)(?<!\*)\$[^$]+\$.+\n(?:.{29}.+\n)+)')
plain_kerberoast_regex = re.compile(r"(?P<hash>\$krb5tgs\$\d\d\$\*?(?P<account>.+?)\$(?P<system>.+?)\$(?P<purpose>.+?)\*\$.{1000,})")

rubeus_asrep_regex = re.compile(r'(?P<hash>\$krb5asrep\$(?P<account>.+?)@(?P<system>.+?):[A-F0-9$\s]{500,})')
rubeus_u2u_ntlm_regex = re.compile(r'^  UserName                 :  (?P<account>\S+).*^  UserRealm                :  (?P<system>\S+).+\[*] Getting credentials using U2U.*NTLM              : (?P<hash>\S+)', flags=re.DOTALL + re.MULTILINE)

snaffler_finding = re.compile(r'\[.+] \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z \[(File|Share)\] \{(Red|Yellow|Green)\}<(?P<ainfo>.+?)>\((?P<binfo>.+?)\) (?P<cinfo>.*)')
net_user_add_command = re.compile(r'net user /add (?P<account>\S+) (?P<secret>\S+)')
net_use_command = re.compile(r'net use (?:\S+) (?P<purpose>\\\S+)(?=.*/user)(?: /user:(?P<account>\S+)| (?P<secret>[^/]\S+)| /\S+){2,}', re.IGNORECASE + re.MULTILINE)

valid_windows_domain = r'[^,~:!@#$%^&\')(}{_ ]{2,155}'
valid_windows_username = r'[^"/\\[\]\:;|=,+*?<>]+'
secretsdump_dcsync_regex = re.compile(rf'^(?:(?P<system>{valid_windows_domain}?)\\)?(?P<account>{valid_windows_username}):\d+:(?P<lmhash>[a-f0-9]{{32}}):(?P<ntlmhash>[a-f0-9]{{32}}):::', flags=re.MULTILINE)
EMPTY_LMHASH = "AAD3B435B51404EEAAD3B435B51404EE"
EMPTY_NTLMHASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

domain_cached_credential2_regex = re.compile(r'(?P<system>[^\s/\:]+)/[^\s/\:]+:(?P<hash>\$DCC2\$\d+#(?P<account>[^#]+)#[0-9a-f]{32})')

def cs_beaconlog_to_file(log_data):
    md5_hash, size, path = re.match(r"file: ([a-f0-9]{32}) (\d+) bytes (.*)", log_data).groups()
    directory, sep, filename = split_path(path)
    file, created = File.objects.get_or_create(size=size,
                                               md5_hash=md5_hash,
                                               filename=filename)
    if created:
        file.save()

    return file, directory


@receiver(post_save, sender=BeaconLog)
def cs_beaconlog_parser(sender, instance: BeaconLog, **kwargs):
    if instance.data.startswith("file: "):
        cs_beaconlog_to_file(instance.data)
    elif instance.type == "output":
        message = instance.data
        extract_creds(message, default_system=instance.beacon.computer)


def convert_tgs_to_hashcat_format(hash):
    return re.sub(r"\$\*.*?\*\$", "$", hash)


def remove_quotes(input_dict):
    result = input_dict.copy()
    for key, value in input_dict.items():
        if (value.startswith('"') and value.endswith('"')) or value.startswith("'") and value.endswith("'"):
            result[key] = value[1:-1]
    return result


@transaction.atomic
def extract_creds(input_text: str, default_system: str):
    # Remove CS timestamps
    input_text = re.sub(r'\r?\n\[\d\d\/\d\d \d\d:\d\d:\d\d] \[\+] ', '', input_text)
    # Remove inline execute assembly output noise
    input_text = re.sub(r'received output:\r?\n', '', input_text)

    # A list of Credentials with hashes to add in bulk. As bulk actions don't trigger the post-save action
    # (i.e. credential_save_listener) we shouldn't put Credential objects with secrets in here
    hashes_to_add_in_bulk = []

    # Look for creds
    for match in browser_cred_regex.finditer(input_text):
        date_str = match.group(3)
        date_parsed = dateparser.parse(date_str, settings={'TO_TIMEZONE': 'UTC'}).replace(tzinfo=timezone.utc)

        credential, created = Credential.objects.get_or_create(source=match.group(1), system=match.group(2),
                                                               source_time=date_parsed,
                                                               account=match.group(4), secret=match.group(5),
                                                               purpose="Web Login")

    for match in netntlmv1_regex.finditer(input_text):
        hashes_to_add_in_bulk.append(Credential(**match.groupdict(), purpose="Windows Login", hash_type=HashCatMode.NetNTLMv1))

    for match in netntlmv2_regex.finditer(input_text):
        hashes_to_add_in_bulk.append(Credential(**match.groupdict(), purpose="Windows Login", hash_type=HashCatMode.NetNTLMv2))

    for match in domain_cached_credential2_regex.finditer(input_text):
        hashes_to_add_in_bulk.append(Credential(**match.groupdict(), purpose="Windows Login",
                                       hash_type=HashCatMode.Domain_Cached_Credentials_2))

    for match in askcreds_regex.finditer(input_text):
        credential, created = Credential.objects.get_or_create(**match.groupdict(),
                                                               purpose="Windows Login", source="AskCreds")

    for match in credphisher_regex.finditer(input_text):
        credential, created = Credential.objects.get_or_create(**match.groupdict(),
                                                               purpose="Windows Login", source="CredPhisher")
    for match in rubeus_u2u_ntlm_regex.finditer(input_text):
        credential, created = Credential.objects.get_or_create(**match.groupdict(), hash_type=HashCatMode.NTLM,
                                                               purpose="Windows Login", source="Rubeus U2U")

    for match in snaffler_finding.finditer(input_text):
        if match["ainfo"].startswith("KeepCmdCredentials|"):
            content = (bytes(match["cinfo"], "utf-8")
                       .replace(br'\\', br'\\\\')  # Fix snaffler not escaping the escape char
                       .decode("unicode_escape"))
            for innermatch in net_user_add_command.finditer(content):
                credential, created = Credential.objects.get_or_create(**innermatch.groupdict(),
                                                                       purpose="Automated user creation",
                                                                       source=match['binfo'],
                                                                       source_time=match['ainfo'].split('|')[-1])
            for innermatch in net_use_command.finditer(content):
                innermatch_dict = remove_quotes(innermatch.groupdict())
                credential, created = Credential.objects.get_or_create(**innermatch_dict,
                                                                       source=match['binfo'],
                                                                       source_time=match['ainfo'].split('|')[-1])



    for match in credenum_regex.finditer(input_text):
        # Teams stores creds hex encoded in the cred store, so decode
        secret = match.groupdict().pop("secret")
        if secret and re.match("^([0-9A-f]{2} )+[0-9A-f]{2}$", secret, re.IGNORECASE):
            secret = bytes.fromhex(secret).decode("utf-8")

        credential, created = Credential.objects.get_or_create(**match.groupdict(), secret=secret,
                                                               purpose="Stored Credentials", source="Seatbelt CredEnum")

    for match in outflank_kerberoast_regex.finditer(input_text):
        hash_type, hash, system, purpose = TicketConverter.convert_ticket(match.groupdict()["ticket"])
        hashes_to_add_in_bulk.append(Credential(hash=hash, account=match.groupdict()["account"],
                                       hash_type=hash_type, system=system,
                                       purpose=f"Windows Login (used by SPN: {purpose})",
                                       source="Outflank Kerberoasting"))

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

        hashes_to_add_in_bulk.append(Credential(hash=hash_str, account=match.groupdict()["account"],
                                       hash_type=hash_type, system=match.groupdict()["system"] or default_system,
                                       purpose=f"Windows Login (used by SPN: {match.groupdict()['purpose'].strip()})",
                                       source="Rubeus Kerberoasting"))

        # Remove any similar but truncated hashes which haven't cracked, these are a result of stream processing kicking
        # in before the multiline kerberos ticket has been fully parsed from CS logs
        CharField.register_lookup(Length)
        Credential.objects.filter(account=match.groupdict()["account"],
                               hash_type=hash_type, system=match.groupdict()["system"] or default_system,
                               purpose=f"Windows Login (used by SPN: {match.groupdict()['purpose'].strip()})",
                               source="Rubeus Kerberoasting")\
                             .filter(hash__length__lt=len(hash_str), secret__isnull=True)\
                             .annotate(stri=StrIndex(Value(hash_str), "hash")).filter(stri=1)\
                             .delete()

    for match in rubeus_asrep_regex.finditer(input_text):
        hash_str = match.groupdict()["hash"].replace(" ", "").replace("\n", "").replace("\r", "")\
            .replace("$krb5asrep$", "$krb5asrep$23$")

        hashes_to_add_in_bulk.append(Credential(hash=hash_str, account=match.groupdict()["account"],
                                       hash_type=18200, system=match.groupdict()["system"] or default_system,
                                       purpose="Windows Login",
                                       source="Rubeus ASREPRoasting"))

    for match in plain_kerberoast_regex.finditer(input_text):
        hash_str = match.groupdict()["hash"]

        hash_type = -1
        if hash_str.startswith("$krb5tgs$23$"):
            hash_type = 13100
        elif hash_str.startswith("$krb5tgs$18$"):
            hash_type = 19700
            hash_str = convert_tgs_to_hashcat_format(hash_str)
        elif hash_str.startswith("$krb5tgs$17$"):
            hash_type = 19600

        hashes_to_add_in_bulk.append(Credential(hash=hash_str.rstrip(), account=match.groupdict()["account"],
                                       hash_type=hash_type, system=match.groupdict()["system"] or default_system,
                                       purpose=f"Windows Login (used by SPN: {match.groupdict()['purpose']})",
                                       source="Kerberoasting"))

    for match in secretsdump_dcsync_regex.finditer(input_text):
        lmhash = match.groupdict()["lmhash"]
        if lmhash.upper() != EMPTY_LMHASH:
            hashes_to_add_in_bulk.append(Credential(hash=lmhash, system=match.groupdict()["system"] or default_system,
                               account=match.groupdict()["account"], hash_type=HashCatMode.LM,
                               purpose="Windows Login", source="Impacket secretsdump.py"))

        ntlmhash = match.groupdict()["ntlmhash"]
        if ntlmhash != EMPTY_NTLMHASH:
            hashes_to_add_in_bulk.append(Credential(hash=ntlmhash,
                                                    system=match.groupdict()["system"] or default_system,
                                                    account=match.groupdict()["account"], hash_type=HashCatMode.NTLM,
                                                    purpose="Windows Login", source="Impacket secretsdump.py"))

    Credential.objects.bulk_create(hashes_to_add_in_bulk, ignore_conflicts=True,
                                   unique_fields=["hash", "hash_type", "account", "system"])

@receiver(post_save, sender=Beacon)
def notify_webhooks_new_beacon(sender, instance: Beacon, **kwargs):
    # Only fire webhooks if the beacon passes exclusion rules
    if Beacon.visible_beacons().filter(id=instance.id).exists():
        if Beacon.objects.filter(user=instance.user, host=instance.host, process=instance.process)\
                .exclude(id=instance.id).exists():
            # We've already seen a beacon for this user, host & process combo:
            for webhook in Webhook.objects.all():
                notify_webhook(webhook.url,
                               "respawned beacon",
                               f"Respawned beacon for {instance} received on {instance.team_server.description}")
        else:
            # This is a new beacon:
            for webhook in Webhook.objects.all():
                notify_webhook_new_beacon(webhook, instance)


def notify_webhook_new_beacon(webhook, beacon: Beacon):
    """
    Used for new beacons and the test notification process, hence a function in its own right.
    """
    notify_webhook(webhook.url,
                   "new beacon",
                   f"New beacon for {beacon} received on {beacon.team_server.description}")


@background(schedule=0)
def notify_webhook(url, type, message):
    requests.post(url=url, json={
        "type": type,
        "message": message
    })


@receiver(recent_checkin)
def checkin_handler(sender, beacon, metadata, **kwargs):
    if beacon.beaconreconnectionwatcher_set.exists():
        for webhook in Webhook.objects.all():
            notify_webhook(webhook.url,
                           "returned beacon",
                           f"Beacon returned: {beacon} on {beacon.team_server.description}")

        # Now we've spawned off some notification tasks, remove the DB entry
        beacon.beaconreconnectionwatcher_set.all().delete()


neo4j_driver_dict = dict()

def get_driver_for(bloodhound_server) -> Optional[Driver]:
    if not bloodhound_server.active:
        if bloodhound_server in neo4j_driver_dict:
            del neo4j_driver_dict[bloodhound_server]
        return None

    if bloodhound_server not in neo4j_driver_dict:
        driver = GraphDatabase.driver(bloodhound_server.neo4j_connection_url,
                                      auth=(bloodhound_server.username, bloodhound_server.password),
                                      connection_acquisition_timeout=2, connection_timeout=2,
                                      max_transaction_retry_time=2, resolver=custom_resolver)
        try:
            driver.verify_connectivity()
        except:
            # Dirty hack to turn off cert validation, required for Ubuntu client for unknown reason
            logging.warning("Falling back to unverified SSL connections to neo4j")
            driver = GraphDatabase.driver(bloodhound_server.neo4j_connection_url.replace("+s://", "+ssc://"),
                                          auth=(bloodhound_server.username, bloodhound_server.password),
                                          connection_acquisition_timeout=2, connection_timeout=2,
                                          max_transaction_retry_time=2, resolver=custom_resolver)

        neo4j_driver_dict[bloodhound_server] = driver

    candidate = neo4j_driver_dict[bloodhound_server]

    try:
        # Ensure the pool connection is still valid
        candidate.verify_connectivity()
        return candidate
    except Exception:
        del neo4j_driver_dict[bloodhound_server]
        return None


def custom_resolver(socket_address):
    # Quickly resolve localhost to avoid timeouts caused by slow DNS failures
    if socket_address[0] == "localhost":
        yield neo4j.Address(("127.0.0.1", socket_address[1]))
    else:
        yield neo4j.Address.parse(format(socket_address))
