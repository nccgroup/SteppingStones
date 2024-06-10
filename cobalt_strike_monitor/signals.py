import re
from datetime import timedelta

from django.db.models import Q
from django.db.models.signals import post_save
from django.dispatch import receiver

from cobalt_strike_monitor.models import TeamServer, BeaconPresence, BeaconLog
from cobalt_strike_monitor.poll_team_server import TeamServerPoller, recent_checkin


@receiver(post_save, sender=TeamServer)
def team_server_listener(sender, instance: TeamServer, **kwargs):
    if instance.active:
        TeamServerPoller().add(instance.pk)


sleep_regex = re.compile(r"Tasked beacon to sleep for (?P<sleep>\d+)s(?: \((?P<jitter>\d+)% jitter\))?")
sleep_metadata_regex = re.compile(r"@\((?P<sleep>[-\d]+)L?, (?P<jitter>[-\d]+)L?, ([-\d]+)L?\)")


@receiver(recent_checkin)
def checkin_handler(sender, beacon, metadata, **kwargs):
    if "sleep" in metadata and metadata["sleep"]:  # Parse the new sleep metadata in CS 4.7
        for match in sleep_metadata_regex.finditer(metadata["sleep"]):
            sleep = int(match.group("sleep") or '0')
            jitter = int(match.group("jitter") or '0') / 100

            if sleep < 0 or jitter < 0:
                return  # This happens when a beacon is deemed to have gone away by CS, lets not overwrite our data
    else:  # Try and determine the sleep params from log entries
        # Relies on beacon logs being ingested before this signal fires
        last_acknowledged_sleep = BeaconLog.objects\
            .filter(beacon=beacon)\
            .filter(Q(data__startswith="Tasked beacon to sleep for ", type="task")
                    | Q(data="Tasked beacon to become interactive", type="task")
                    | Q(data__startswith="started SOCKS4a server on: ", type="output"))\
            .order_by("when").last()

        sleep = 0
        jitter = 0.0

        if not last_acknowledged_sleep:
            # New beacons will use the sleep params from the CS Profile, but we can't see those settings
            print(f"Can not find previous sleep command for {beacon}, assuming its interactive")
        else:
            print(f"{beacon.user} {last_acknowledged_sleep.data}")
            # This won't match if there's an explict interactive tasking or SOCKS start, but that's fine as interactive is
            # our default assumption
            for match in sleep_regex.finditer(last_acknowledged_sleep.data):
                sleep = int(match.group("sleep") or '0')
                jitter = int(match.group("jitter") or '0') / 100

    last_presence = beacon.beaconpresence_set.last()

    # The maximum amount of time between checkins we would expect based on the previously configured sleep params.
    if last_presence:
        max_sleep_fuzzy = last_presence.max_sleep + timedelta(seconds=60)  # Plus 60 seconds to allow for inherent jitter
    else:
        # If no prior config is found, set max_sleep_period to 0 to let the missing previous checkin result in a
        # new presence tracker.
        max_sleep_fuzzy = timedelta(seconds=60)

    # Update a presence tracker if it's recent (i.e. 2 * max_sleep_periods ago)
    active_presence = BeaconPresence.objects.filter(beacon=beacon,
                                                    last_checkin__gte=beacon.last
                                                                      - max_sleep_fuzzy
                                                                      - max_sleep_fuzzy).last()

    if active_presence:
        # This beacon has been active recently, extend its activity window upto now
        active_presence.last_checkin = beacon.last
        active_presence.save()

    if not active_presence or active_presence.sleep_seconds != sleep or active_presence.sleep_jitter != jitter:
        # Create a new presence tracker because there wasn't one, or sleep params have changed
        BeaconPresence(beacon=beacon,
                       first_checkin=beacon.last,
                       last_checkin=beacon.last,
                       sleep_seconds=sleep,
                       sleep_jitter=jitter).save()

