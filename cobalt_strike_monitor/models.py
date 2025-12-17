from datetime import timedelta


from django.contrib.contenttypes.fields import GenericRelation
from django.db import models
from django.db.models import Q, ForeignKey, BooleanField
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.utils.timezone import now


class TeamServer(models.Model):
    hostname = models.CharField(max_length=100, verbose_name="Hostname or IP")
    port = models.IntegerField(default=50050)
    password = models.CharField(max_length=100)
    description = models.CharField(max_length=200, null=True, blank=True)
    active = models.BooleanField(default=True)


class Listener(models.Model):
    team_server = models.ForeignKey(TeamServer, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, primary_key=True)
    proxy = models.CharField(max_length=100)
    payload = models.CharField(max_length=100)
    port = models.CharField(max_length=100)
    profile = models.CharField(max_length=100)
    host = models.CharField(max_length=100)
    althost = models.CharField(max_length=100)
    strategy = models.CharField(max_length=100)
    beacons = models.CharField(max_length=100)
    bindto = models.CharField(max_length=100)
    status = models.CharField(max_length=100)
    maxretry = models.CharField(max_length=100)
    localonly = models.BooleanField(default=False)
    guards = models.CharField(max_length=100, default="")  # Tab seperated list of guardrails values

    @property
    def beacons_list(self):
        return [beacon.strip() for beacon in self.beacons.split(",")]

    @property
    def listener_type(self):
        if self.payload == "windows/beacon_bind_pipe":
            return "SMB"
        elif self.payload == "windows/beacon_https/reverse_https":
            return "HTTPS"
        elif self.payload == "windows/beacon_http/reverse_http":
            return "HTTP"
        elif self.payload == "windows/foreign/reverse_https":
            return "Foreign HTTPS"
        elif self.payload == "windows/foreign/reverse_http":
            return "Foreign HTTP"
        elif self.payload == "windows/beacon_bind_tcp":
            return "TCP"
        elif self.payload == "windows/beacon_dns/reverse_dns_txt":
            return "DNS"
        elif self.payload == "windows/beacon_extc2":
            return "External C2"
        else:
            return f"Unknown ({self.payload})"

    def __str__(self):
        return f"{self.listener_type} listener - \"{self.name}\""

    @property
    def html(self):
        result = f"{escape(self)} "
        if self.althost and self.name != self.althost:
            result += f" hosted at {escape(self.althost)}"

        if len(self.beacons_list) > 1:
            result += " accessed via: <ul>"
            for accessed_via in self.beacons_list:
                result += f"<li>{escape(accessed_via)}</li>"
            result += "</ul>"

        return mark_safe(result)

class Beacon(models.Model):
    team_server = models.ForeignKey(TeamServer, on_delete=models.CASCADE)
    id = models.IntegerField(primary_key=True)  # ID used internally by a Team Server to refer to the beacon
    note = models.CharField(max_length=100)  # Notes added by the user in the UI
    charset = models.CharField(max_length=100)  # Character set in use by the host, e.g. windows-1252

    listener = models.ForeignKey(Listener, on_delete=models.CASCADE, null=True, blank=True)  # Name of listener being called back to (only applicable to beacon sessions, not SSH)
    parent_beacon = models.ForeignKey("Beacon", on_delete=models.DO_NOTHING, default=None, null=True, blank=True)  # The parent beacon ID, only present when chaining together beacons

    internal = models.CharField(max_length=45)  # Internal IP of the host
    external = models.CharField(max_length=45)  # External IP of the host
    computer = models.CharField(max_length=100)  # Preferred hostname
    host = models.CharField(max_length=45)  # Preferred IP of the host

    session = models.CharField(max_length=50)  # SSH or Beacon
    process = models.CharField(max_length=100)  # Process name hosting the beacon
    pid = models.CharField(max_length=20)  # Process ID of the beacon
    barch = models.CharField(max_length=20)  # Beacon architecture e.g. x64
    is64 = models.BooleanField(),  # Flag for if the beacon is 64 bit

    os = models.CharField(max_length=20)  # Operating system name
    ver = models.CharField(max_length=20)  # Operating system version
    build = models.CharField(max_length=20)  # Operating system build
    arch = models.CharField(max_length=20)  # Operating system architecture e.g. x64

    user = models.CharField(max_length=100)  # User the beacon is running as

    opened = models.DateTimeField()  # Timestamp of the initial connection
    last = models.DateTimeField(null=True)  # Timestamp of the last time this beacon checked in

    event_mappings = GenericRelation("event_tracker.EventMapping", related_query_name='beacon')

    @property
    def os_human(self):
        if self.os == "Windows":
            if int(self.build) < 50:  # We're dealing with Emerald
                return f"MacOS {self.ver}.{self.build}"
            else:  # A regular beacon
                if self.ver == "10.0":
                    if self.build == "14393":
                        return "Windows 10 (1607) / Windows Server 2016"
                    elif self.build == "15063":
                        return "Windows 10 (1703)"
                    elif self.build == "17763":
                        return "Windows 10 (1809) / Windows Server 2019"
                    elif self.build == "18363":
                        return "Windows 10 / Windows Server (1909)"
                    elif self.build == "19041":
                        return "Windows 10 / Windows Server (2004)"
                    elif self.build == "19042":
                        return "Windows 10 / Windows Server (20H2)"
                    elif self.build == "19043":
                        return "Windows 10 / Windows Server (21H1)"
                    elif self.build == "19044":
                        return "Windows 10 (21H2)"
                    elif self.build == "19045":
                        return "Windows 10 (22H2)"
                    elif self.build == "20348":
                        return "Windows Server 2022 (21H2)"
                    elif self.build == "22000":
                        return "Windows 11 (21H2)"
                    elif self.build == "22621":
                        return "Windows 11 (22H2)"
                    elif self.build == "22631":
                        return "Windows 11 (23H2)"
                elif self.ver == "6.3":
                    return "Windows 8.1 / Windows Server 2012 R2"
                elif self.ver == "6.2":
                    if self.build == "9200":
                        # Might be lying, hence the ">="
                        # see https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversion
                        return "Windows >= 8 / Windows Server >= 2012"
                    else:
                        return "Windows 8 / Windows Server 2012"
                elif self.ver == "6.1":
                    if self.build == "7600":
                        return "Windows 7"
                    elif self.build == "7601":
                        return "Windows 7 SP1"
        elif self.os == "Linux":
            if self.ver != "0.0":  # We're dealing with Emerald
                return f"Linux (Kernel {self.ver}.{self.build})"
            else:
                return "Linux"

        return f"Unknown {self.os} {self.ver} {self.build}"

    @property
    def user_human(self):
        """
        Strips off the * suffix for admin users
        """
        return self.user.removesuffix(" *")

    @property
    def next_checkin_estimate(self):
        presence = self.beaconpresence_set.last()
        return self.last + presence.max_sleep if presence else None

    @property
    def missed_checkins(self):
        presence = self.beaconpresence_set.last()
        if presence:
            delta_since_last = now() - self.last
            if delta_since_last > presence.max_sleep:
                return delta_since_last / presence.max_sleep
            else:
                return 0
        else:
            return -1

    def __str__(self):
        result = self.user
        result += ' on ' if (self.user and self.computer) else ''
        result += self.computer
        result += f' ({self.process})' if self.process else ''
        return result

    @classmethod
    def visible_beacons(cls):
        return cls.objects.exclude(computer__in=BeaconExclusion.objects.filter(computer__isnull=False).values_list("computer", flat=True))\
            .exclude(user__in=BeaconExclusion.objects.filter(user__isnull=False).values_list("user", flat=True))\
            .exclude(process__in=BeaconExclusion.objects.filter(process__isnull=False).values_list("process", flat=True)) \
            .exclude(id__in=BeaconExclusion.objects.filter(beacon_id__isnull=False).values_list("beacon_id", flat=True)) \
            .exclude(internal__in=BeaconExclusion.objects.filter(internal__isnull=False).values_list("internal", flat=True)) \
            .exclude(external__in=BeaconExclusion.objects.filter(external__isnull=False).values_list("external", flat=True))



class BeaconExclusion(models.Model):
    """
    Model to hold exclusions, e.g. for test beacons. Any individual field match
    should be excluded from the default list of beacons in the UI.
    """
    beacon_id = models.IntegerField(null=True)
    user = models.CharField(max_length=100, null=True)  # User the beacon is running as
    computer = models.CharField(max_length=100, null=True)  # Preferred hostname
    process = models.CharField(max_length=100, null=True)  # Process name hosting the beacon
    internal = models.CharField(max_length=45, null=True)  # Internal IP of the host
    external = models.CharField(max_length=45, null=True)  # External IP of the host

    def __str__(self):
        if self.beacon_id:
            return f"Exclude beacon with ID: {self.beacon_id}"
        elif self.computer:
            return f"Exclude all beacons on host: {self.computer}"
        elif self.user:
            return f"Exclude all beacons from user: {self.user}"
        elif self.process:
            return f"Exclude all beacons spawned as: {self.process}"
        elif self.internal:
            return f"Exclude all beacons with internal IP: {self.internal}"
        elif self.external:
            return f"Exclude all beacons with external IP: {self.external}"


class CSAction(models.Model):
    start = models.DateTimeField()  # Timestamp of the entry
    beacon = models.ForeignKey(Beacon, on_delete=models.CASCADE, null=True)
    event_mappings = GenericRelation("event_tracker.EventMapping", related_query_name='cs_action')
    accept_output = BooleanField(default=True)

    @property
    def operator(self):
        log_with_operator = self.beaconlog_set.filter(operator__isnull=False).first()
        if log_with_operator:
            return log_with_operator.operator
        else:
            return None

    @property
    def tactic(self):
        archive_with_tactic = self.archive_set.filter(tactic__isnull=False).first()
        if archive_with_tactic:
            return archive_with_tactic.tactic
        else:
            return None

    @property
    def description(self):
        return ", ".join(self.archive_set.filter(type="task").exclude(data="").values_list('data', flat=True))

    @property
    def input(self):
        return chr(10).join(self.archive_set.filter(type="input").exclude(data="").values_list('data', flat=True))

    @property
    def output(self):
        return chr(10).join(self.beaconlog_set
                            .filter(Q(type__startswith="output") | Q(type="error")).exclude(data="")
                            .values_list('data', flat=True)).rstrip("\n")

    @property
    def indicators(self):
        return self.archive_set.filter(type="indicator")


class Archive(models.Model):
    team_server = models.ForeignKey(TeamServer, on_delete=models.CASCADE)
    id = models.IntegerField(primary_key=True)  # ID used internally by a Team Server to refer to this archive entry

    when = models.DateTimeField()  # Timestamp of the entry
    beacon = models.ForeignKey(Beacon, on_delete=models.CASCADE, null=True) # May be null for "webhit" events

    type = models.CharField(max_length=20)  # One of: initial, input, task, checkin, output, indicator
    data = models.CharField(max_length=100)  # The content of the log
    tactic = models.CharField(max_length=100, null=True)  # One or more (comma seperated) MITRE tactics

    cs_action = ForeignKey(CSAction, on_delete=models.CASCADE, null=True)

    @property
    def indicator_hash(self):
        if self.type == "indicator" and self.data.startswith("file:"):
            return self.data.split(" ", 4)[1]
        else:
            return None

    @property
    def indicator_size(self):
        if self.type == "indicator" and self.data.startswith("file:"):
            return int(self.data.split(" ", 4)[2])
        else:
            return None

    @property
    def indicator_path(self):
        if self.type == "indicator" and self.data.startswith("file:"):
            return self.data.split(" ", 4)[4]
        else:
            return None


class BeaconLog(models.Model):
    team_server = models.ForeignKey(TeamServer, on_delete=models.CASCADE)
    id = models.IntegerField(primary_key=True)  # ID used internally by a Team Server to refer to this archive entry

    when = models.DateTimeField()  # Timestamp of the entry
    beacon = models.ForeignKey(Beacon, on_delete=models.CASCADE)

    type = models.CharField(max_length=25)  # One of: input, task, checkin, output, output_ps, error, note, indicator, output_job_registered, output_job_completed
    data = models.TextField()  # The content of the log
    output_job = models.IntegerField(null=True)

    operator = models.CharField(max_length=100, null=True)  # The user initiating the request
    cs_action = ForeignKey(CSAction, on_delete=models.CASCADE, null=True)


class Credential(models.Model):
    team_server = models.ForeignKey(TeamServer, on_delete=models.CASCADE)
    user = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    host = models.CharField(max_length=100)
    realm = models.CharField(max_length=100)
    added = models.DateTimeField()
    source = models.CharField(max_length=100)


class BeaconPresence(models.Model):
    beacon = models.ForeignKey(Beacon, on_delete=models.CASCADE)
    first_checkin = models.DateTimeField()
    last_checkin = models.DateTimeField()
    sleep_seconds = models.IntegerField()
    sleep_jitter = models.FloatField()  # Jitter % as a decimal

    @property
    def max_sleep(self):
        return timedelta(seconds=(self.sleep_seconds + (self.sleep_seconds * self.sleep_jitter)))


class Download(models.Model):
    team_server = models.ForeignKey(TeamServer, on_delete=models.CASCADE)
    beacon = models.ForeignKey(Beacon, on_delete=models.CASCADE)
    date = models.DateTimeField()  # The date it was downloaded, not the timestamp of the original file
    size = models.IntegerField()
    path = models.CharField(max_length=1000)
    name = models.CharField(max_length=100)

    event_mappings = GenericRelation("event_tracker.EventMapping", related_query_name='beacon')
