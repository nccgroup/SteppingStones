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
BOF_FMT_RE = re.compile(r"[iszZb]+")

MAX_FIELD_BYTES = 4096
MAX_PARAM_CHARS = 117


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


def decode_bof_args(b64_str: str, fmt: str = "") -> list[tuple[str, str]]:
    """Decode Outflank C2 exec_bof argument blob into a list of (type_char, value) pairs.

    The blob layout (little-endian):
        uint32  total_size
        for each parameter:
            s (int16)  — 2 raw bytes, no size prefix
            i (int32)  — 4 raw bytes, no size prefix
            z (narrow) — uint32 size prefix + UTF-8 bytes (null-terminated)
            Z (wide)   — uint32 size prefix + UTF-16LE bytes (null-terminated)
            b (binary) — uint32 size prefix + raw bytes

    If fmt is provided (e.g. "Zi"), it drives parsing exactly.
    Without fmt, type heuristics are applied (works for z/Z/b args and i/s values
    large enough that their bytes can't be mistaken for a valid size prefix).
    """
    try:
        data = base64.b64decode(b64_str)
    except Exception:
        return [("b", f"<base64 error: {b64_str}>")]

    if len(data) < 4:
        return [("b", f"<too short: {data.hex()}>")]

    offset = 4  # skip total_size field
    params: list[tuple[str, str]] = []

    if fmt:
        for type_char in fmt:
            if offset >= len(data):
                break
            if type_char == "s":
                if offset + 2 > len(data):
                    break
                params.append(("s", str(struct.unpack_from("<h", data, offset)[0])))
                offset += 2
            elif type_char == "i":
                if offset + 4 > len(data):
                    break
                params.append(("i", str(struct.unpack_from("<i", data, offset)[0])))
                offset += 4
            elif type_char in ("z", "Z", "b"):
                if offset + 4 > len(data):
                    break
                psize = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                if offset + psize > len(data):
                    break
                pdata = data[offset : offset + psize]
                offset += psize
                if type_char == "z":
                    try:
                        s = pdata[:-1].decode("utf-8") if psize >= 1 else ""
                        params.append(("z", s[:MAX_PARAM_CHARS] + "..." if len(s) > MAX_PARAM_CHARS else s))
                    except UnicodeDecodeError:
                        params.append(("b", f"0x{pdata.hex()}"))
                elif type_char == "Z":
                    try:
                        s = pdata[:-2].decode("utf-16-le") if psize >= 2 else ""
                        params.append(("Z", s[:MAX_PARAM_CHARS] + "..." if len(s) > MAX_PARAM_CHARS else s))
                    except UnicodeDecodeError:
                        params.append(("b", f"0x{pdata.hex()}"))
                else:
                    params.append(("b", f"0x{pdata.hex()}"))
        return params

    # Heuristic fallback (no format string available).
    # Works reliably for z/Z/b args and for i/s values whose bytes exceed the
    # remaining data length (so they can't be mistaken for a valid size prefix).
    while offset < len(data):
        if offset + 4 > len(data):
            if len(data) - offset == 2:
                params.append(("s", str(struct.unpack_from("<H", data, offset)[0])))
            break

        psize = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if offset + psize > len(data):
            params.append(("i", str(struct.unpack_from("<i", data, offset - 4)[0])))
            continue
        pdata = data[offset : offset + psize]
        offset += psize

        if psize == 0:
            continue

        if psize == 2 and pdata == b"\x00\x00":
            params.append(("Z", ""))
            continue
        if psize % 2 == 0 and psize >= 6 and pdata[-2:] == b"\x00\x00":
            try:
                s = pdata[:-2].decode("utf-16-le")
                if s.isprintable():
                    params.append(("Z", s[:MAX_PARAM_CHARS] + "..." if len(s) > MAX_PARAM_CHARS else s))
                    continue
            except UnicodeDecodeError:
                pass

        if pdata[-1:] == b"\x00":
            try:
                s = pdata[:-1].decode("utf-8")
                if not s or s.isprintable():
                    params.append(("z", s[:MAX_PARAM_CHARS] + "..." if len(s) > MAX_PARAM_CHARS else s))
                    continue
            except UnicodeDecodeError:
                pass

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
    orig_args = task.get("arguments") or ""
    b64 = task.get("out_arguments") or ""

    if task_name in ("exec_bof", "exec_bof_async") and (b64 or orig_args):
        # 'arguments' is the original operator command, e.g. "sis 1 17432 0"
        # 'out_arguments' is the b64-encoded arg blob.
        # Extract the format string from arguments (if present) and decode the blob.
        fmt_parts = orig_args.split(None, 1)
        fmt = fmt_parts[0] if fmt_parts and BOF_FMT_RE.fullmatch(fmt_parts[0]) else ""
        if b64:
            decoded = decode_bof_args(b64.strip(), fmt)
            if decoded:
                types, formatted = [], []
                for t, v in decoded:
                    types.append(t)
                    formatted.append(f'"{v}"' if t in ("z", "Z") else v)
                return f"{task_name} {''.join(types)} {' '.join(formatted)}"
        return f"{task_name} {orig_args}".strip()

    arguments = b64 or orig_args
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
