import time
from datetime import datetime

import requests
from background_task import background
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q, Count, Value
from django.db.models.functions import Substr, Upper, Concat
from neo4j.exceptions import ClientError

from event_tracker.models import BloodhoundServer, Credential, HashCatMode, Event, Context
from event_tracker.signals import get_driver_for


def _count_disabled_accounts(tx):
    query = ("""MATCH (n:User) where 
             n.enabled=false
             return count(n)"""
             )

    return tx.run(query).single()


def _get_disabled_accounts(tx):
    query = ("""MATCH (n:User) where 
             n.enabled=false
             with split(n.name, '@') as a
             return a[1], a[0]"""
             )

    result = tx.run(query)

    return [record.values() for record in result]

@background(schedule=5)
def sync_pwnedpasswords():
    query = Credential.objects.exclude(hash__isnull=True).exclude(hash="")\
        .filter(hash_type=HashCatMode.NTLM, haveibeenpwned_count__isnull=True)\
        .values("hash")\
        .annotate(group_by=Count("hash"), prefix=Substr("hash", 1, 5), suffix=Upper(Substr("hash", 6)))

    if not query.exists():
        return

    start = time.time()
    print("Starting sync of haveibeenpwned hashes")

    db_hash_count = 0
    for db_hash in query.all():
        db_hash_count += 1
        response = requests.get(f'https://api.pwnedpasswords.com/range/{db_hash["prefix"]}?mode=ntlm')
        if response.ok:
            count = 0
            for line in response.text.split("\n"):
                if line.startswith(db_hash["suffix"]):
                    suffix, count = line.strip().split(":", 1)
                    break
            Credential.objects.filter(hash_type=HashCatMode.NTLM, hash=db_hash["hash"]).update(haveibeenpwned_count=count)
            print(f"Hash {db_hash['hash']} {'not ' if count == 0 else ''}found at pwnedpasswords.com")
        else:
            print(f"Error {response.status_code} from pwnedpasswords.com: {response.text}")

    print(f"Done sync of {db_hash_count:,} haveibeenpwned hashes in {time.time() - start:.2f} seconds")


@background(schedule=5)
def sync_disabled_users():
    """
    Syncs users marked as disabled in Bloodhound with the users in the Credentials table
    """

    cached_total_users_in_local_database = cache.get("total_users_in_local_database", 0)
    actual_total_users_in_local_database = Credential.objects.count()
    cache.set("total_users_in_local_database", actual_total_users_in_local_database)

    # Disabled accounts
    for server in BloodhoundServer.objects.filter(active=True).all():
        driver = get_driver_for(server)

        if driver:
            with driver.session() as session:  # Neo4j Session
                cached_disabled_users_in_neo4j = cache.get(f"disabled_users_in_{server.neo4j_connection_url}", 0)
                actual_disabled_users_in_neo4j = len(session.execute_read(_get_disabled_accounts))
                cache.set(f"disabled_users_in_{server.neo4j_connection_url}", actual_disabled_users_in_neo4j)

            # If the neo4j or local_database has changed since last invocation, or the cache is empty suggesting a restart:
            if cached_disabled_users_in_neo4j != actual_disabled_users_in_neo4j \
                    or cached_total_users_in_local_database != actual_total_users_in_local_database:
                start = time.time()
                print("Starting local copy of disabled users")
                with transaction.atomic():  # SQLite transaction
                    with driver.session() as session:  # Neo4j Session
                        try:
                            disabled_accounts = session.execute_read(_get_disabled_accounts)

                            system_account_dict = dict()

                            for acc in disabled_accounts:
                                if acc[0] not in system_account_dict:
                                    system_account_dict[acc[0]] = list()

                                system_account_dict[acc[0]].append(acc[1])

                            for system in system_account_dict:
                                system_filter = Credential.objects.filter(system__iexact=system, enabled=True)
                                account_q = Q()
                                account_count = 0
                                for account in system_account_dict[system]:
                                    account_count += 1
                                    if account_count % 900 == 0:
                                        # Flush query
                                        system_filter.filter(account_q).update(enabled=False)
                                        account_q = Q()
                                    else:
                                        # Build query
                                        account_q |= Q(account__iexact=account)

                                # Final flush
                                system_filter.filter(account_q).update(enabled=False)
                        except ClientError:
                            pass  # Likely caused by no accounts being enabled for this system
                print(f"Done local copy of {actual_disabled_users_in_neo4j:,} disabled users in {time.time() - start:.2f} seconds")
            else:
                print(f"No changes in disabled user count detected ({actual_disabled_users_in_neo4j:,} disabled users)")


@background(schedule=5)
def sync_bh_owned():
    bh_servers = BloodhoundServer.objects.filter(active=True).all()

    # Mark source host as owned if we are running things in a system context
    source_hosts = (Context.objects.filter(id__in=Event.objects.all().values_list("source", flat=True))
                    .filter(user__iexact="system").values_list('host', flat=True))
    for bloodhound_server in bh_servers:
        for source_hosts_page in Paginator(source_hosts, 1000):
            update_owned_hosts(bloodhound_server, list(source_hosts_page.object_list))

    # Mark source user as owned if we are running things in that user's context
    source_users = (Context.objects.filter(id__in=Event.objects.all().values_list("source", flat=True))
                    .exclude(user__iexact="system").values_list('user', flat=True))
    for bloodhound_server in bh_servers:
        for source_users_page in Paginator(source_users, 1000):
            update_owned_users(bloodhound_server, list(source_users_page.object_list))

    # Only mark as owned if we have a plain-text secret in the credential, not just a hash
    credentials = Credential.objects.filter(secret__isnull=False).order_by('account').distinct()\
        .annotate(bhname=Upper(Concat('account', Value('@'), 'system'))).values_list('bhname', flat=True)
    for bloodhound_server in bh_servers:
        for credentials_page in Paginator(credentials, 1000):
            update_owned_credentials(bloodhound_server, list(credentials_page.object_list))


def update_owned_credentials(bloodhound_server, credentials):
    driver = get_driver_for(bloodhound_server)
    if driver:
        with driver.session() as session:
            session.write_transaction(set_owned_bloodhound_users_with_domain, credentials)


def update_owned_hosts(bloodhound_server, hosts):
    driver = get_driver_for(bloodhound_server)
    if driver:
        with driver.session() as session:
            session.write_transaction(set_owned_bloodhound_hosts_without_domain, hosts)


def update_owned_users(bloodhound_server, users):
    driver = get_driver_for(bloodhound_server)
    if driver:
        with driver.session() as session:
            session.write_transaction(set_owned_bloodhound_users_without_domain, users)


def set_owned_bloodhound_users_with_domain(tx, users: list[str]):
    """
    Bulk mark of Bloodhound users as owned.

    :param users List of uppercase UPNs to mark as owned, e.g. ['USER1@MY.DOMAIN.LOCAL', 'USER2@MY.DOMAIN.LOCAL']
    """
    if not users:
        return

    print(f"Marking {len(users)} users as owned")

    return tx.run(
        f'''unwind $users as ownedUser
        match (n) where (n:User or n:AZUser) and n.name = ownedUser and (n.owned = False or not n:Tag_Owned)
        set n.owned=True, n:Tag_Owned, n.notes="Marked as Owned by Stepping Stones at {datetime.now():%Y-%m-%d %H:%M:%S%z}"''',
        users=users)


def set_owned_bloodhound_hosts_without_domain(tx, hosts):
    """
    Bulk mark of Bloodhound hosts as owned, regardless of the domain they are on.

    :param hosts List of computer names (case-insensitive) to mark as owned, e.g. ['host1', 'host2']
    """
    if not hosts:
        return

    print(f"Marking {len(hosts)} hosts as owned ignoring domain")

    return tx.run(
        f'''unwind $hosts as ownedHost
        match (n) where (n:Computer or n:AZDevice) and toLower(split(split(n.name, "@")[1], ".")[0]) = toLower(ownedHost) and (u.owned = False or not u:Tag_Owned) 
        set n.owned=True, n:Tag_Owned, n.notes="Marked as Owned by Stepping Stones at {datetime.now():%Y-%m-%d %H:%M:%S%z}"''',
        hosts=hosts)


def set_owned_bloodhound_users_without_domain(tx, users):
    """
    Bulk mark of Bloodhound users as owned, regardless of the domain they are on.

    :param users List of usernames (case-insensitive) to mark as owned, e.g. ['user1', 'user2']
    """
    if not users:
        return

    print(f"Marking {len(users)} users as owned ignoring domain")

    return tx.run(
        f'''unwind $users as ownedUser
        match (n) where (n:User or n:AZUser) and toLower(split(n.name, "@")[0]) = toLower(ownedUser) and (n.owned = False or not n:Tag_Owned) 
        set n.owned=True, n:Tag_Owned, n.notes="Marked as Owned by Stepping Stones at {datetime.now():%Y-%m-%d %H:%M:%S%z}"''',
        users=users)

