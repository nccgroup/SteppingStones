import json
import os
import platform
import re
import socket
import subprocess
import traceback
from io import BufferedReader

import psutil
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import time_ns

from background_task import background
from background_task.models import Task
from dateutil.tz import UTC
from django.db.models import Q
from django.dispatch import Signal
from django.template import Engine, Context
from django.utils import timezone
from datetime import timedelta

from cobalt_strike_monitor.models import TeamServer, Beacon, Archive, BeaconLog, Listener, Credential, Download

from background_task.admin import TaskAdmin, CompletedTaskAdmin

from django.core.cache import cache  # We use the "default" cache for tracking team server enablement

# Monkey Patch the background_task library so that the function containing kill(PID, 0),
# which kills the background task on Windows, isn't called by the admin UI
fields = ['task_name', 'task_params', 'run_at', 'priority', 'attempts', 'has_error', 'locked_by', ]
TaskAdmin.list_display = fields
CompletedTaskAdmin.list_display = fields


class TeamServerPoller:
    def initialise(self):
        # Clear out any orphan tasks
        for task in Task.objects.all():
            if task.locked_by is not None and not psutil.pid_exists(int(task.locked_by)):
                task.delete()

        # Spawn some new tasks
        for server in TeamServer.objects.filter(active=True).all():
            self.add(server.id)

    def add(self, serverid):
        # Check there's nothing already scheduled for this server:
        if not Task.objects.filter(
                task_name="cobalt_strike_monitor.poll_team_server.poll_teamserver",
                task_params__startswith=f"[[{serverid}], ").exists():
            poll_teamserver(serverid, schedule=timezone.now())


def healthcheck_teamserver(serverid):
    server = TeamServer.objects.get(pk=serverid)
    tcp_error = None
    aggressor_output = None

    try:
        with socket.socket() as sock:
            sock.connect((server.hostname, server.port))
    except Exception as e:
        tcp_error = e

    if not tcp_error:
        with NamedTemporaryFile(mode="w", delete=False) as tempfile:
            tempfile.write("""
println("Connected OK. Synchronizing...");
            
on ready {
   println("Synchronized OK.");
   closeClient();
}""")
            tempfile.close()
            jar_path = _get_jar_path()
            try:
                p = subprocess.Popen(["java",
                                      "-XX:ParallelGCThreads=4",
                                      "-XX:+AggressiveHeap",
                                      "-XX:+UseParallelGC",
                                      "-Xmx128M",
                                      "-classpath",
                                      str(jar_path),
                                      "aggressor.headless.Start",
                                      server.hostname,
                                      str(server.port),
                                      f"ssbot{int(time_ns() / 1_000_000_000)}",
                                      server.password,
                                      tempfile.name],
                                     cwd=str(jar_path.parent),
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
                aggressor_output = p.stdout.read().decode("unicode_escape")
            except FileNotFoundError as e:
                aggressor_output = f"Java Virtual Machine not found in $PATH"
            except NotADirectoryError as e:
                aggressor_output = f"No such JAR directory: {jar_path.parent}"
            finally:
                os.unlink(tempfile.name)

            if "Could not find or load main class aggressor.headless.Start" in aggressor_output:
                aggressor_output += "\nTry (re-)running Cobalt Strike's update script"
    try:
        p = subprocess.Popen(["systemctl",
                              "status",
                              "ssbot"],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        ssbot_status = p.stdout.read().decode("unicode_escape")
    except FileNotFoundError as e:
        ssbot_status = None

    found_jvm = False
    for p in psutil.process_iter(["cmdline"]):
        if p.info['cmdline'] and \
                "java" in p.info['cmdline'][0] and \
                len(p.info['cmdline']) > 11 and server.password == p.info['cmdline'][11]:
            found_jvm = True

    return tcp_error, aggressor_output, ssbot_status, found_jvm

@background(schedule=5)
def poll_teamserver(serverid):
    server = TeamServer.objects.get(pk=serverid)

    if not server.active:
        print(f"[i] {server.description} ({server.hostname}:{server.port}) is disabled")
        return

    try:
        if server.beacon_set.exists():
            last_session_timestamp = server.beacon_set.latest("opened").opened.timestamp() * 1000
        else:
            last_session_timestamp = 0

        if server.archive_set.exists():
            last_archive_timestamp = server.archive_set.latest("when").when.timestamp() * 1000
        else:
            last_archive_timestamp = 0

        if server.beaconlog_set.exists():
            last_beaconlog_timestamp = server.beaconlog_set.latest("when").when.timestamp() * 1000
        else:
            last_beaconlog_timestamp = 0

        if server.credential_set.exists():
            last_credential_timestamp = server.credential_set.latest("added").added.timestamp() * 1000
        else:
            last_credential_timestamp = 0

        if server.download_set.exists():
            last_download_timestamp = server.download_set.latest("date").date.timestamp() * 1000
        else:
            last_download_timestamp = 0

        with NamedTemporaryFile("w", delete=False) as tempfile:
            template = Engine.get_default().get_template("dump.cna")
            context = Context({"last_session_timestamp": last_session_timestamp,
                               "last_archive_timestamp": last_archive_timestamp,
                               "last_beaconlog_timestamp": last_beaconlog_timestamp,
                               "last_credential_timestamp": last_credential_timestamp,
                               "last_download_timestamp": last_download_timestamp})
            tempfile.write(template.render(context))  # Render the dump.cna as a template so it includes the counts
            tempfile.close()

            print(f"Generated aggressor script for {server.description} to: {tempfile.name}")

            jar_path = _get_jar_path()

            try:
                p = subprocess.Popen(["java",
                                         "-XX:ParallelGCThreads=4",
                                         "-XX:+AggressiveHeap",
                                         "-XX:+UseParallelGC",
                                         "-Xmx128M",
                                         "-classpath",
                                         str(jar_path),
                                         "aggressor.headless.Start",
                                         server.hostname,
                                         str(server.port),
                                         f"ssbot{int(time_ns() / 1_000_000_000)}",
                                         server.password,
                                         tempfile.name],
                                         cwd=str(jar_path.parent),
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT)

                parse(p, server)

            finally:
                os.remove(tempfile.name)
    except BaseException as e:
        print(f"[{server.description}] [!] Exception in ssbot:")
        traceback.print_exc()
        raise e  # Rethrow the exception so background tasks recognises an error occurred


def _get_jar_path():
    if platform.system() == "Windows":
        jar_path = Path(r"C:\Tools\cobaltstrike\cobaltstrike.jar")
    else:
        jar_path = Path(r"/opt/cobaltstrike/cobaltstrike.jar")
    cs46_jar_path = jar_path.parent / "cobaltstrike-client.jar"
    if cs46_jar_path.exists():
        jar_path = cs46_jar_path
    cs49_jar_path = jar_path.parent / "client" / "cobaltstrike-client.jar"
    if cs49_jar_path.exists():
        jar_path = cs49_jar_path
    return jar_path


# A signal which will fire no more than once a minute when a beacon checks in
recent_checkin = Signal()

def parse_line(line):
    """
    Returns tuple of ID and parsed representation of data
    """
    line_parts = re.search(r"^\[.\] \[([^\]]+)\] (.*)$", line)
    if not line_parts:
        print(f"Could not parse: {line}")
        return "", ""
    return line_parts.group(1), json.loads(line_parts.group(2))

def parse(p, server):
    try:
        reader = BufferedReader(p.stdout)

        pending_beacon_log = None

        for line in iter(reader.readline, b''):
            # We don't need to check the TS is enabled every line, but should do so every few seconds
            # So use Django's caching function...
            ts_state = cache.get(f"TS_STATE_{server.pk}")
            if ts_state is None:  # i.e. never cached, or expired
                server.refresh_from_db(fields=['active'])
                ts_state = server.active
                cache.set(f"TS_STATE_{server.pk}", ts_state, 5)  # Cache this for 5 seconds

            # Check if we're still processing output from this TS
            if not ts_state:
                print(f"{server.description} marked inactive - exiting", flush=True)
                p.kill()
                return

            line = line.decode("ascii").rstrip()
            print(f"[{server.description}] {line}")
            # Skip connection status messages
            if any(msg in line for msg in [
                "Loading Windows error codes",
                "Windows error codes loaded",
                "Connected OK",
                "Synchronizing",
                "Synchronized OK",
                "shutting down client",
                "Disconnected from team server"
            ]):
                continue

            try:
                line_id, line_data = parse_line(line)

                # First, lets flush the pending Beacon Log if we've moved onto a processing different type of line:
                if not line.startswith("[B]"):
                    if pending_beacon_log:
                        # Our regexes rely on a \n to find ends of passwords etc, so ensure there's always 1
                        pending_beacon_log.data = pending_beacon_log.data.rstrip("\n") + "\n"
                        pending_beacon_log.save()
                        pending_beacon_log = None

                # Now lets process the current line
                if line.startswith("[L]"):  # Listeners
                    # TCP Listeners can be configured to only bind to localhost
                    if "localonly" in line_data:
                        line_data["localonly"] = (line_data["localonly"] == "true")
                    listener = Listener(**dict(filter(
                        lambda elem: elem[0] in ["name", "proxy", "payload", "port", "profile", "host",
                                                 "althost", "strategy", "beacons", "bindto", "status", "maxretry",
                                                 "guards", "localonly"],
                        line_data.items())))
                    listener.team_server = server
                    listener.save()
                elif line.startswith("[M]"):  # Beacon Metadata
                    delta = timedelta(milliseconds=int(line_data["last"]))
                    approx_last_seen = (datetime.now(tz=UTC)-delta)  # Only approx, as time has passed since
                                                                              # the "X milliseconds ago" figure was
                                                                              # generated
                    # Only update beacons if their last seen was over a minute since the current value to reduce DB load
                    # and compensate for constantly changing values due to the approximation error
                    beacons_to_update = Beacon.objects.filter(Q(pk=int(line_id)),
                                                   Q(last__lte=approx_last_seen-timedelta(minutes=1)) | Q(last__isnull=True))

                    # Sanity check that it's worth locking the DB for
                    if beacons_to_update.exists():
                        update_count = beacons_to_update.update(last=approx_last_seen)

                        if update_count > 0 and delta < timedelta(minutes=1):
                            beacon_to_update = Beacon.objects.get(pk=int(line_id))
                            recent_checkin.send_robust(sender="ssbot", beacon=beacon_to_update, metadata=line_data)

                elif line.startswith("[S]"):  # Beacon sessions
                    beacon = Beacon(**dict(filter(
                        lambda elem: elem[0] in ["id", "note", "charset", "internal", "external", "computer",
                                                 "host", "process", "pid", "barch", "os", "ver", "build", "arch",
                                                 "user",  "session"],
                        line_data.items())))
                    beacon.is64 = (line_data["is64"] == "1")
                    beacon.opened = datetime.fromtimestamp(int(line_data["opened"]) / 1000, tz=UTC)
                    if "pbid" in line_data and line_data["pbid"] != "":
                        beacon.parent_beacon = get_beacon_for_bid(line_data["pbid"], server)
                        if beacon.session == "beacon":  # SSH sessions also have a pbid, so ensure it's a beacon-beacon connection
                            # A bit of an assumption that the SMB listener in play is the first one configured, but we
                            # don't have anything else to go on.
                            beacon.listener = Listener.objects.filter(team_server=server, payload="windows/beacon_bind_pipe").first()
                    else:
                        beacon.listener = Listener.objects.get(name=line_data["listener"], team_server=server)
                    beacon.team_server = server
                    beacon.save()
                elif line.startswith("[A]"):  # Archives
                    temp_dict = dict()
                    temp_dict.update(line_data)
                    archive = Archive(**dict(filter(
                        lambda elem: elem[0] in ["data", "tactic"],
                        temp_dict.items())))
                    archive.type = clean_type(temp_dict["type"])
                    archive.when = datetime.fromtimestamp(int(temp_dict["when"].rstrip("L")) / 1000, tz=UTC)
                    if "bid" in temp_dict:
                        archive.beacon = get_beacon_for_bid(temp_dict["bid"], server)
                    archive.team_server = server
                    archive.save()
                elif line.startswith("[B]"):  # Beacon Logs
                    # Example:
                    # [B] [1263] {"data":"received output:\n[+] roborg Runtime Initalized, assembly size 488960, .NET Runtime Version: 4.0.30319.42000 in AppDomain qiBsaBzIc\r\n", "type":"beacon_output", "bid":"270632664", "when":"1741168779890"}
                    # To avoid hammering the DB and rerunning lots of regexes, we first try and buffer sequential output
                    # logs in memory, but this only works for those logs read in a single non-blocking read, so
                    # eventually we also have to attempt a DB level merge too.
                    beacon_log = BeaconLog(**dict(filter(
                        lambda elem: elem[0] in ["data", "operator", "output_job"],
                        line_data.items())))

                    beacon_log.type = clean_type(line_data["type"])
                    beacon_log.beacon = get_beacon_for_bid(line_data["bid"], server)
                    beacon_log.team_server = server

                    # Work back from the end of line_data, as there may (or may not) be an operator element in the
                    # middle which messes up later offsets
                    beacon_log.when = datetime.fromtimestamp(int(line_data["when"]) / 1000, tz=UTC)

                    if "data" in line_data:
                        # Trim prefix added by NCC custom tooling
                        if beacon_log.data.startswith("received output:"):
                            beacon_log.data = beacon_log.data[17:]

                    # Beacon Logs output types are special in that we try and merge adjacent output lines into a single DB row.
                    # This is done by storing the DB row in a "pending" variable which is either appended to, or
                    # flushed if appending doesn't make sense because the current and pending lines aren't related.
                    # Lines will not be merged if there is too much of a time difference between each line, or if other
                    # concurrent events are occurring on the team server.
                    # So there remains the need to do additional processing to collate the output/errors associated with an input/task.
                    if pending_beacon_log:
                        # Does current entry fit with pending beacon log?
                        if beacon_log.type == pending_beacon_log.type and \
                                beacon_log.output_job == pending_beacon_log.output_job and \
                                beacon_log.beacon_id == pending_beacon_log.beacon_id and \
                                beacon_log.team_server_id == pending_beacon_log.team_server_id and \
                                beacon_log.when - pending_beacon_log.when <= timedelta(milliseconds=15):
                            # Merge current with pending and discard current
                            pending_beacon_log.data += beacon_log.data
                            pending_beacon_log.when = beacon_log.when # Update the time for use in subsequent time comparisons
                        else:
                            # Flush pending beacon log and save current one

                            # Our regexes rely on a \n to find ends of passwords etc, so ensure there's always 1
                            pending_beacon_log.data = pending_beacon_log.data.rstrip("\n") + "\n"
                            pending_beacon_log.save()
                            pending_beacon_log = None
                            beacon_log.save()
                    else:
                        if beacon_log.type == "output":
                            pending_beacon_log = beacon_log
                        else:
                            # There's no pending beacon log, just save this non-output log straight to the DB
                            beacon_log.save()
                elif line.startswith("[C]"):  # Credentials
                    credential = Credential(**dict(filter(
                        lambda elem: elem[0] in ["user", "password", "host", "realm", "source"],
                        line_data.items())))
                    credential.added = datetime.fromtimestamp(int(line_data["added"]) / 1000, tz=UTC)
                    credential.team_server = server
                    credential.save()
                elif line.startswith("[D]"):  # Downloads
                    download = Download(**dict(filter(
                        lambda elem: elem[0] in ["size", "path", "name"],
                        line_data.items())))
                    download.date = datetime.fromtimestamp(int(line_data["date"]) / 1000, tz=UTC)
                    download.team_server = server
                    if "bid" in line_data:
                        download.beacon = get_beacon_for_bid(line_data["bid"], server)
                    download.save()
                elif "illegal subarray" in line:
                    # Indicator that the DB and TS are out of sync, likely due to a Model Reset on the TS
                    print(f"[{server.description}] Deleting local copy of {server} data - we are ahead of it")
                    clear_local_copy(server)
                    return
                elif "read [Manage: unauth'd user]: null" in line:
                    print(f"[{server.description}] Error suggests version mismatch between Team Server and local CS Client")
            except BaseException as ex:
                print(f"[{server.description}] [!] Error parsing {line}")
                traceback.print_exc()
                # If things have gone so wrong we need to rebuild the DB, uncomment the following line:
                # clear_local_copy(server)
    except BaseException as e:
        print(f"[{server.description}] [!] Exception in background task:")
        traceback.print_exc()
        raise e  # Rethrow the exception so background tasks recognises an error occurred


def get_beacon_for_bid(bid, team_server):
    # Cope with beacon IDs as strings, or wrapped in single item arrays
    # (resulting from a bug in the NCC menu)
    bid = re.match(r"(?:@\(')?(\d+)(?:'\))?", bid).group(1)

    return Beacon.objects.get(id=bid, team_server=team_server)


def clear_local_copy(team_server):
    Archive.objects.filter(team_server=team_server).delete()
    BeaconLog.objects.filter(team_server=team_server).delete()
    Beacon.objects.filter(team_server=team_server).delete()
    Listener.objects.filter(team_server=team_server).delete()
    Credential.objects.filter(team_server=team_server).delete()
    Download.objects.filter(team_server=team_server).delete()


def clean_type(input_string):
    return input_string.removeprefix("beacon_").replace("tasked", "task").removesuffix("_alt")
