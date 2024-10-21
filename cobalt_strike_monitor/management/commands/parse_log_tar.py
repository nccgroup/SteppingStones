from datetime import datetime
import pathlib
import re
import tarfile
from functools import partial

import dateparser
from django.core.management import BaseCommand

from cobalt_strike_monitor.models import Beacon, TeamServer, Listener, Download, BeaconLog, Archive


def get_pseudo_ctime(root, tarinfo):
    if tarinfo.isfile() and tarinfo.name.endswith('.log'):
        if match := re.search(r"\d{6}", tarinfo.name):
            file_date = datetime.strptime(match[0], "%y%m%d")
        else:
            file_date = None

        buffer = root.extractfile(tarinfo)
        try:
            lines = buffer.readlines()
            first_line = lines[0].decode("utf-8")
        except UnicodeError:
            print(f"[E] Could not decode {lines[0]} in {tarinfo.name}")

        if match := re.search(r"^(?P<date>\d{2}/\d{2}) (?P<time>.+? .+?)\s", first_line):
            line_datetime = dateparser.parse(match[0])
            line_datetime.replace(day=file_date.day, month=file_date.month, year=file_date.year)

            ctime = line_datetime.timestamp()

            if tarinfo.name.endswith("downloads.log"):
                ctime += 86400  # Add a day onto the download log time to ensure they are processed after that days' beacons
            elif "[metadata]" not in first_line:
                ctime += 1 # Add a second onto beacon logs that lack metadata to cover the case of 2 logs in the same instant, we want to process the metadata one first

            print(f"Treating {tarinfo.name} as starting on {line_datetime}")
            return ctime
        else:
            print(f"Can't determine ctime for {tarinfo.name}")

    # default case:
    return 0


class Command(BaseCommand):
    help = 'Parse a tar file of CS logs, created with `tar cvfz cslogs.tar.gz /opt/cobaltstrike/logs`'

    def add_arguments(self, parser):
        parser.add_argument('tar_file', type=pathlib.Path)

    def handle(self, *args, **options):
        filename = options["tar_file"]

        team_server, _ = TeamServer.objects.get_or_create(hostname="n/a", description=filename, active=False)
        listener, _ = Listener.objects.get_or_create(team_server=team_server, name=f"Listener for {filename}", payload="Dummy")

        with tarfile.open(filename) as root:
            for file in sorted(root.getmembers(), key=partial(get_pseudo_ctime, root)):
                if file.isfile():
                    if re.match(r".*downloads.log$", file.name):
                        print(f"Processing {file.name}")
                        self.parse_downloads(root, file, team_server)
                    elif re.match(r".*(?P<session>beacon|ssh)_(?P<id>\d+).log$", file.name):
                        print(f"Processing {file.name}")
                        self.parse_cslog_file(root, file, listener, team_server)

    def parse_cslog_file(self, root, file, listener, team_server):
        path = pathlib.Path(file.name)
        file_date = datetime.strptime(path.parent.parent.name, "%y%m%d")

        buffer = root.extractfile(file)
        buffer_str = buffer.read().decode("utf-8")

        filename_parts = re.match(r".*(?P<session>beacon|ssh)_(?P<id>\d+).log", file.name).groupdict()

        beacon = None
        logevent = None

        for logevent in re.finditer(r"(^\d{2}/\d{2}.+?)(?=\n\d{2}/\d{2})", buffer_str, re.MULTILINE + re.DOTALL):
            beacon = self.parse_cslog_generic_event(logevent[0].strip(), file_date, filename_parts, beacon, listener, team_server)

        if logevent:
            # Handle remainder of the file
            self.parse_cslog_generic_event(buffer_str[logevent.end():].strip(), file_date, filename_parts, beacon, listener, team_server)
        else:
            # Handle whole of file
            self.parse_cslog_generic_event(buffer_str.strip(), file_date, filename_parts, beacon, listener, team_server)


    def parse_cslog_generic_event(self, line, file_date, filename_parts, beacon, listener, team_server):
        try:
            open_bracket = line.index("[")
            close_bracket = line.index("]", open_bracket)
        except ValueError:
            # We are trying to process a line which does not have a type defined, likely an overflow from an earlier log
            # drop this line
            return beacon
        line_type = line[open_bracket + 1:close_bracket]

        time = re.search(r"^\d{2}/\d{2} (?P<time>.+?) \[", line)["time"]
        line_time = dateparser.parse(time)
        line_datetime = datetime.combine(file_date, line_time.timetz())

        if line_type == "metadata":
            beacon = self.parse_cslog_metadata_event(line[close_bracket + 2:], line_datetime, filename_parts, listener, team_server)
        elif line_type in ["input", "output", "task", "error", "indicator"]:
            if not beacon:
                try:
                    beacon = Beacon.objects.get(id=filename_parts["id"], team_server=team_server)
                except Beacon.DoesNotExist as dne:
                    print(f"Beacon not found: {filename_parts['id']}: {dne}")
            self.parse_cslog_data_event(line_type, line[close_bracket + 2:], line_datetime, beacon, team_server)

        return beacon

    def parse_cslog_data_event(self, line_type, body, line_datetime, beacon, team_server):
        operator = None
        tactic = None

        if line_type == "input":
            open_bracket = body.index("<")
            close_bracket = body.index(">", open_bracket)
            operator = body[open_bracket + 1:close_bracket]
            body = body[close_bracket + 2:]
        elif line_type == "task":
            open_bracket = body.index("<")
            close_bracket = body.index(">", open_bracket)
            tactic = body[open_bracket + 1:close_bracket]
            body = body[close_bracket + 2:]

        body = body.replace("received output:\n", "")
        body = re.sub(r"\x03[0-9A-F]+", "", body)

        BeaconLog.objects.get_or_create(team_server=team_server,
                                        when=line_datetime,
                                        beacon=beacon,
                                        type=line_type,
                                        data=body,
                                        operator=operator)

        Archive.objects.get_or_create(team_server=team_server,
                                        when=line_datetime,
                                        beacon=beacon,
                                        type=line_type,
                                        data=body,
                                        tactic=tactic)

    def parse_cslog_metadata_event(self, body, line_datetime, filename_parts, listener, team_server):
        beacon_metadata = {"listener": listener}
        beacon_metadata |= filename_parts

        try:
            body_parts = re.match(
                r"^(?P<parent>.+?) (?P<direction><-|->) (?P<host>.+?); (?P<pairs>.*)$",
                body)

            beacon_metadata["host"] = body_parts["host"]
            if parent_beacon := re.match(r"beacon_(?P<bid>\d+)", body_parts["parent"]):
                parent_bid = parent_beacon["bid"]
                if Beacon.objects.filter(id=parent_bid).exists():
                    beacon_metadata["parent_beacon"] = Beacon.objects.get(id=parent_bid)

            pairs_list = body_parts["pairs"].split(";")
            for pair in pairs_list:
                name, value = pair.split(":", 1)
                beacon_metadata[name.strip()] = value.strip()

            if Beacon.objects.filter(id=beacon_metadata['id']).exists():
                existing_beacon = Beacon.objects.get(id=beacon_metadata['id'])
                if existing_beacon.opened > line_datetime:
                    # existing is newer than parsed
                    existing_beacon.opened = line_datetime
                elif existing_beacon.last < line_datetime:
                    # existing is older than parsed
                    existing_beacon.last = line_datetime
                existing_beacon.save()

                return existing_beacon
            else:
                # CLean up the metadata dict to match a Beacon kwargs
                if beacon_metadata["session"] == "beacon":
                    arch_str = beacon_metadata.pop('beacon arch')
                else:
                    arch_str = None

                if "version" in beacon_metadata:
                    beacon_metadata["ver"] = beacon_metadata.pop("version")

                if "port" in beacon_metadata:
                    del beacon_metadata["port"]
                    beacon_metadata["ver"] = "0.0"

                beacon = Beacon(team_server=team_server,
                                opened=line_datetime,
                                last=line_datetime,
                                **beacon_metadata)

                if arch_str:
                    beacon.arch = arch_str.split(' ')[0]
                    beacon.is64 = "(x64)" in arch_str
                beacon.save()

                return beacon
        except Exception as e:
            print(f"[!] Unable to parse metadata line: {body}: {e}")

    def parse_downloads(self, root, file, team_server):
        path = pathlib.Path(file.name)
        file_date = datetime.strptime(path.parent.name, "%y%m%d")

        buffer = root.extractfile(file)
        for line in buffer.readlines():
            line = line.decode("utf-8")
            match = re.match(
                r"^(?P<date>\d{2}/\d{2}) (?P<time>.+)\t(?P<host>[^\t]+)\t(?P<bid>[^\t]+)\t(?P<size>[^\t]+)\t(?P<localpath>[^\t]+)\t(?P<name>[^\t]+)\t(?P<path>[^\t]+)",
                line)
            if match:
                beacon = Beacon.objects.get(id=match["bid"])

                line_time = dateparser.parse(match["time"])
                line_datetime = datetime.combine(file_date, line_time.timetz())

                Download.objects.get_or_create(
                    team_server=team_server,
                    beacon=beacon,
                    date=line_datetime,
                    size=match["size"],
                    path=match["path"].strip(),
                    name=match["name"].strip())
