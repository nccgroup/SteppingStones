#!/usr/bin/env python3
"""
Convert Outflank C2 JSON implant logs to EventStream JSONL format.

Each implant log file contains one JSON event per line, prefixed with a
timestamp: "2026-07-10 14:42:49 UTC {json...}"

Event types handled:
  - new_implant    → EventStream entry describing implant check-in
  - task_request   → EventStream entry when a task is issued to an implant
  - task_response  → EventStream entry pairing request/response as a single event

Only task_response events (state=500, completed) produce the primary output
entries, since they represent a completed action with both the command and its
output.  new_implant events produce a single "implant registered" entry.
task_request events with no matching response are also emitted (incomplete tasks).
"""

import argparse
import base64
import json
import os
import re
import struct
import sys
from datetime import datetime, timezone

# Log line format: "2026-07-10 14:42:49 UTC {json}"
LOG_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \w+) (\{.+\})$")

MAX_FIELD_BYTES = 4096


def truncate(value: str, max_bytes: int = MAX_FIELD_BYTES) -> str:
    """Truncate a string so its UTF-8 encoding does not exceed max_bytes.

    When the value has more than 10 lines, retains the first 5 and last 5
    lines with a marker for the removed middle.  Otherwise truncates from
    the end at the byte boundary.
    """
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value

    original_bytes = len(encoded)
    lines = value.splitlines()

    if len(lines) > 10:
        removed = len(lines) - 10
        marker = f"[... {removed} lines omitted, {original_bytes} bytes total ...]"
        candidate = "\n".join(lines[:5]) + "\n" + marker + "\n" + "\n".join(lines[-5:])
        if len(candidate.encode("utf-8")) <= max_bytes:
            return candidate

    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated + f"... [truncated, original {original_bytes} bytes]"


def parse_timestamp(ts_str: str) -> str:
    """Parse OC2 log-line timestamp to ISO 8601 string."""
    # ts_str: "2026-07-10 14:42:49 UTC"
    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S %Z")
    return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def iso_from_oc2(ts: str) -> str:
    """Convert OC2 ISO timestamps (may have microseconds) to plain ISO 8601."""
    # e.g. "2026-07-10T14:42:49.851113" → "2026-07-10T14:42:49"
    return ts[:19] if ts else ts


def privilege_label(priv_code: int) -> str:
    # OC2 privilege codes observed: 100=user, 200=admin/system
    return {100: "Low", 200: "Medium", 300: "High"}.get(priv_code, str(priv_code))


def arch_label(arch_code: int) -> str:
    return {32: "x86", 64: "x64", 100: "x86", 200: "x64"}.get(arch_code, str(arch_code))


def decode_bof_args(b64_str: str) -> list[tuple[str, str]]:
    """Decode Outflank C2 exec_bof argument blob into a list of (type_char, value) pairs.

    Format (little-endian):
        uint32  total_size
        for each parameter:
            uint32  param_size
            byte    param_data[param_size]

    Type heuristics (no type tags stored in blob):
        Z (wide string)   — even psize ≥ 6, UTF-16LE null-terminated, printable content;
                            or psize=2 \x00\x00 (empty string)
        z (narrow string) — UTF-8 null-terminated, printable content
        i (int32)         — psize=4, fallback when z check doesn't match
        s (short)         — psize=2, fallback when Z/z checks don't match
        b (binary)        — everything else

    Empty strings (Z "" = b"\\x00\\x00", z "" = b"\\x00") are handled:
      Z "" explicitly (psize=2, \\x00\\x00 check before the general Z rule).
      z "" naturally by the z rule (pdata[:-1] decodes to "", which passes isprintable).
    """
    try:
        data = base64.b64decode(b64_str)
    except Exception:
        return [("b", f"<base64 error: {b64_str}>")]

    if len(data) < 4:
        return [("b", f"<too short: {data.hex()}>")]

    offset = 4  # skip total_size field
    params: list[tuple[str, str]] = []

    while offset < len(data):
        if offset + 4 > len(data):
            # Fewer than 4 bytes remain — can't read a psize header.
            # Two trailing bytes are treated as a bare uint16 (defensive fallback).
            if len(data) - offset == 2:
                params.append(("s", str(struct.unpack_from("<H", data, offset)[0])))
            break

        psize = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if offset + psize > len(data):
            # The 4 bytes we read as psize are likely a raw int32 value — OC2 stores
            # i-type args without a psize header (the value sits directly in the stream).
            # E.g. i=1433 → \x99\x05\x00\x00 is misread as psize=1433.
            params.append(("i", str(struct.unpack_from("<i", data, offset - 4)[0])))
            continue
        pdata = data[offset : offset + psize]
        offset += psize

        if psize == 0:
            continue  # skip zero-size padding

        # Z (wide string): even psize, UTF-16LE null-terminated.
        # Empty Z "" (psize=2, \x00\x00) is handled explicitly.
        # Non-empty Z requires psize >= 6 (at least 2 characters) to prevent
        # 4-byte integers like port numbers from being misread — e.g. i=1433
        # encodes as \x99\x05\x00\x00 which is a printable Unicode char (U+0599).
        if psize == 2 and pdata == b"\x00\x00":
            params.append(("Z", ""))
            continue
        if psize % 2 == 0 and psize >= 6 and pdata[-2:] == b"\x00\x00":
            try:
                s = pdata[:-2].decode("utf-16-le")
                if s.isprintable():
                    params.append(("Z", s[:117] + "..." if len(s) > 117 else s))
                    continue
            except UnicodeDecodeError:
                pass

        # z (narrow string): UTF-8 null-terminated.
        # Empty string z "" (psize=1, \x00) passes naturally for the same reason.
        if pdata[-1:] == b"\x00":
            try:
                s = pdata[:-1].decode("utf-8")
                if not s or s.isprintable():
                    params.append(("z", s[:117] + "..." if len(s) > 117 else s))
                    continue
            except UnicodeDecodeError:
                pass

        # i (int32) or s (short) — reached when Z/z checks don't match
        if psize == 4:
            params.append(("i", str(struct.unpack_from("<i", pdata)[0])))
        elif psize == 2:
            params.append(("s", str(struct.unpack_from("<h", pdata)[0])))
        else:
            params.append(("b", f"0x{pdata.hex()}"))

    return params


def build_source(implant: dict) -> dict:
    """Build EventStream 's' (source) object from implant metadata."""
    s = {}
    hostname = implant.get("hostname")
    username = implant.get("username")
    proc_name = implant.get("proc_name")
    pid = implant.get("pid")

    if hostname:
        s["h"] = hostname[:100]
    if username:
        s["u"] = username[:100]
    if proc_name:
        proc_str = proc_name
        if pid:
            proc_str = f"{proc_name} (PID: {pid})"
        s["p"] = proc_str[:100]

    return s if s else None


def new_implant_entry(log_ts: str, event: dict) -> dict:
    implant = event["implant"]
    uid = implant.get("uid", "?")
    os_name = implant.get("os", "")
    priv = privilege_label(implant.get("privilege", 0))
    arch = arch_label(implant.get("arch", 0))
    proc_name = implant.get("proc_name", "")
    pid = implant.get("pid", "")
    ppid = implant.get("ppid", "")
    recipe = implant.get("recipe", "")
    version = implant.get("version", "")

    description = (
        f"Outflank C2 implant {uid} checked in. "
        f"OS: {os_name}, Arch: {arch}, Privilege: {priv}, "
        f"Process: {proc_name} (PID: {pid}, PPID: {ppid}), "
        f"Recipe: {recipe}, Version: {version}"
    ).strip()

    entry = {
        "ts": log_ts,
        "d": description[:1000],
    }

    s = build_source(implant)
    if s:
        entry["s"] = s

    return entry


def build_command_line(task: dict) -> str:
    """Build a human-readable command line from a task object, decoding exec_bof args."""
    task_name = task.get("out_name") or task.get("name", "")
    arguments = task.get("out_arguments") or task.get("arguments", "")

    if task_name in ("exec_bof", "exec_bof_async") and arguments:
        parts = arguments.split(None, 1)  # "exec_bof <b64>" or just "<b64>"
        decoded = decode_bof_args(parts[-1].strip())
        if decoded:
            types, formatted = [], []
            for t, v in decoded:
                types.append(t)
                formatted.append(f'"{v}"' if t in ("z", "Z") else v)
            return f"{task_name} {''.join(types)} {' '.join(formatted)}"
        return task_name

    return f"{task_name} {arguments}" if arguments else task_name


def task_completed_entry(request_ts: str, response_ts: str, event: dict) -> dict:
    """Build an EventStream entry for a completed task (request + response pair)."""
    implant = event["implant"]
    task = event["task"]

    operator = task.get("operator", "")
    response = task.get("response") or ""
    command_line = build_command_line(task)

    # Evidence = command + output (if any)
    if response:
        evidence = f"> {command_line}\n{response}"
    else:
        evidence = f"> {command_line}"

    entry = {
        "ts": request_ts,
        "te": response_ts,
        "e": truncate(evidence),
    }

    if operator:
        entry["op"] = operator[:256]

    s = build_source(implant)
    if s:
        entry["s"] = s

    return entry


def task_incomplete_entry(log_ts: str, event: dict) -> dict:
    """Build an EventStream entry for a task that was requested but never completed."""
    implant = event["implant"]
    task = event["task"]

    operator = task.get("operator", "")
    command_line = build_command_line(task)

    entry = {
        "ts": log_ts,
        "e": truncate(f"> {command_line}"),
    }

    if operator:
        entry["op"] = operator[:256]

    s = build_source(implant)
    if s:
        entry["s"] = s

    return entry


def process_implant_file(filepath: str) -> list[dict]:
    """Parse one OC2 implant JSON log file and return EventStream entries."""
    entries = []
    # task_uid → (request_log_ts, request_event)
    pending_tasks: dict[str, tuple[str, dict]] = {}

    with open(filepath, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            match = LOG_LINE_RE.match(line)
            if not match:
                print(f"  WARNING: skipping unparseable line {lineno} in {os.path.basename(filepath)}", file=sys.stderr)
                continue

            log_ts_raw, json_str = match.group(1), match.group(2)
            log_ts = parse_timestamp(log_ts_raw)

            try:
                event = json.loads(json_str)
            except json.JSONDecodeError as exc:
                print(f"  WARNING: JSON parse error on line {lineno} in {os.path.basename(filepath)}: {exc}", file=sys.stderr)
                continue

            event_type = event.get("event_type")

            if event_type == "new_implant":
                entries.append((log_ts, new_implant_entry(log_ts, event)))

            elif event_type == "task_request":
                task = event.get("task", {})
                task_uid = task.get("uid")
                if task_uid:
                    pending_tasks[task_uid] = (log_ts, event)

            elif event_type == "task_response":
                task = event.get("task", {})
                task_uid = task.get("uid")
                state = task.get("state")

                if state == 500 and task_uid:
                    # Completed task — pair with request if we have it
                    response_ts_raw = task.get("response_timestamp") or log_ts
                    response_ts = iso_from_oc2(response_ts_raw)

                    if task_uid in pending_tasks:
                        request_log_ts, _ = pending_tasks.pop(task_uid)
                    else:
                        # Response without a seen request — use task timestamp
                        task_ts_raw = task.get("timestamp")
                        request_log_ts = iso_from_oc2(task_ts_raw) if task_ts_raw else log_ts

                    entries.append((request_log_ts, task_completed_entry(request_log_ts, response_ts, event)))
                else:
                    # Non-completed response (error, cancelled, etc.) — emit as-is
                    if task_uid and task_uid in pending_tasks:
                        pending_tasks.pop(task_uid)
                    # Skip non-completed responses to avoid duplicates

            else:
                print(f"  WARNING: unknown event_type {event_type!r} on line {lineno} in {os.path.basename(filepath)}", file=sys.stderr)

    # Emit any tasks that were requested but never got a response in this file
    for task_uid, (request_log_ts, event) in pending_tasks.items():
        entries.append((request_log_ts, task_incomplete_entry(request_log_ts, event)))

    return [entry for _, entry in entries]


def main():
    parser = argparse.ArgumentParser(
        description="Convert Outflank C2 implant JSON logs to EventStream JSONL format."
    )
    parser.add_argument(
        "log_dir",
        help="Directory containing OC2 per-implant JSON log files",
    )
    parser.add_argument(
        "eventstream_file",
        type=argparse.FileType("a"),
        help="EventStream JSONL output file (appended to)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.log_dir):
        print(f"ERROR: '{args.log_dir}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    json_files = sorted(
        f for f in os.listdir(args.log_dir)
        if f.endswith(".json") and not f.startswith(".")
    )

    if not json_files:
        print(f"No .json files found in {args.log_dir}", file=sys.stderr)
        sys.exit(1)

    # Collect all entries from all implant files, then sort globally by ts
    all_entries: list[tuple[str, dict]] = []

    for filename in json_files:
        filepath = os.path.join(args.log_dir, filename)
        print(f"Processing {filename} ...", file=sys.stderr)
        try:
            file_entries = process_implant_file(filepath)
            for entry in file_entries:
                all_entries.append((entry["ts"], entry))
        except Exception as exc:
            print(f"  ERROR processing {filename}: {exc}", file=sys.stderr)

    all_entries.sort(key=lambda x: x[0])

    for _, entry in all_entries:
        args.eventstream_file.write(json.dumps(entry, ensure_ascii=False))
        args.eventstream_file.write("\n")

    total = len(all_entries)
    print(f"\nDone. {total} EventStream entries written.", file=sys.stderr)


if __name__ == "__main__":
    main()
