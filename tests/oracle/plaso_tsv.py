"""One TSV line per event plaso's winevt parser produced, sorted.

Usage: python3 -I tests/oracle/plaso_tsv.py out.jsonl > tests/oracle/plaso.tsv

Columns: offset, record number, which time (creation for the time generated,
written), the time (Unix seconds), event identifier (low 16 bits), message
identifier (all 32), facility, severity, event type, category, source name,
computer name, user SID, number of strings, the strings. Text is escaped
(backslash, tab, CR, LF, "|", unpaired surrogates as \\u{xxxx}) and the
strings are joined with "|".
"""

import json
import sys

KINDS = {"Creation Time": "creation", "Content Modification Time": "written"}


def escape(text):
    out = []
    for char in text:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == "\t":
            out.append("\\t")
        elif char == "\r":
            out.append("\\r")
        elif char == "\n":
            out.append("\\n")
        elif char == "|":
            out.append("\\|")
        elif 0xD800 <= code <= 0xDFFF:
            out.append("\\u{%04x}" % code)
        else:
            out.append(char)
    return "".join(out)


def line(event):
    strings = event.get("strings") or []
    fields = [
        event["offset"],
        event["record_number"],
        KINDS[event["timestamp_desc"]],
        event["date_time"]["timestamp"],
        event["event_identifier"],
        event["message_identifier"],
        event["facility"],
        event["severity"],
        event["event_type"],
        event["event_category"],
        escape(event.get("source_name") or ""),
        escape(event.get("hostname") or ""),
        event.get("user_sid") or "",
        len(strings),
        "|".join(escape(s) for s in strings),
    ]
    return "\t".join(str(f) for f in fields)


def main(path):
    with open(path, encoding="utf-8") as jsonl:
        lines = sorted(line(json.loads(row)) for row in jsonl if row.strip())
    sys.stdout.reconfigure(encoding="utf-8", errors="surrogatepass", newline="\n")
    for text in lines:
        print(text)


if __name__ == "__main__":
    main(sys.argv[1])
