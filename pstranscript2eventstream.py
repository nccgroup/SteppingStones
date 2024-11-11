import argparse
import datetime
import json
import re

# Parses a log created with the following powershell command:
# Start-Transcript -path c:\temp\pslog.txt -IncludeInvocationHeader -Append
#
# Or always log with a registry mod: https://adamtheautomator.com/powershell-logging-2/#How_to_Turn_on_Transcripts_with_the_Registry

def dump_to_json(eventstream_file, timestamp, user, host, evidence):
    eventstream_file.write(json.dumps({"ts": timestamp.isoformat(), "s": {"u": user, "h": host}, "e": evidence}))
    eventstream_file.write("\n")

def main(transcript_file, eventstream_file):
    local_timezone = datetime.UTC
    in_section = True
    evidence = ""
    for line in transcript_file:
        if line == "**********************\n":
            in_section = not in_section
            if in_section:
                dump_to_json(eventstream_file, timestamp, user, host, evidence)
                evidence = ""

        elif in_section:
            if line.startswith("Command start time: "):
                timestamp = datetime.datetime.strptime(line[20:], '%Y%m%d%H%M%S\n')
                timestamp = timestamp.replace(tzinfo=local_timezone)
            elif line.startswith("Start time: "):
                timestamp = datetime.datetime.strptime(line[12:], '%Y%m%d%H%M%S\n')
                timestamp = timestamp.replace(tzinfo=local_timezone)
            elif line.startswith("Machine: "):
                host = re.match(r"Machine: (.+) \(", line)[1]
            elif line.startswith("RunAs User: "):
                user = re.match(r"RunAs User: .+\\(.+)$", line)[1]
        else:
            evidence += line

    dump_to_json(eventstream_file, timestamp, user, host, evidence)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('transcript_file', type=argparse.FileType('r', encoding="utf-8"))
    parser.add_argument('eventstream_file', type=argparse.FileType('a'))
    args = parser.parse_args()

    main(args.transcript_file, args.eventstream_file)
