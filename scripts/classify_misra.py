#!/usr/bin/env python3
"""Classify cppcheck MISRA output without suppressing any rule."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


DIAGNOSTIC_RE = re.compile(
    r"^(?P<path>[^:]+):(?P<line>[0-9]+):(?P<column>[0-9]+):.*"
    r"\[misra-c2012-(?P<rule>[0-9]+\.[0-9]+)\]$"
)
DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--unresolved", required=True)
    parser.add_argument("--deviated", required=True)
    parser.add_argument("--limitations", required=True)
    return parser.parse_args()


def source_lines(root, relpath):
    return (root / relpath).read_text(encoding="utf-8").splitlines()


def find_anchor_lines(root, deviation):
    lines = source_lines(root, deviation["path"])
    symbol_re = re.compile(r"\b" + re.escape(deviation["symbol"]) + r"\b")
    if not any(symbol_re.search(line) for line in lines):
        raise ValueError(f"{deviation['id']}: symbol not found")
    found = []
    for anchor in deviation["anchors"]:
        matches = [
            idx + 1 for idx, line in enumerate(lines)
            if line.strip() == anchor.strip()
        ]
        if len(matches) != 1:
            raise ValueError(
                f"{deviation['id']}: anchor must occur once: {anchor!r}"
            )
        found.append(matches[0])
    if len(found) != deviation["expected"]:
        raise ValueError(f"{deviation['id']}: expected count does not match anchors")
    if "range_sha256" in deviation:
        first = min(found) - 1
        last = max(found)
        source_range = "\n".join(lines[first:last]) + "\n"
        digest = hashlib.sha256(source_range.encode("utf-8")).hexdigest()
        if digest != deviation["range_sha256"]:
            raise ValueError(f"{deviation['id']}: approved source range changed")
    return found


def macro_has_directive_use(root, macro, definition_path, definition_line):
    directive_re = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef|elif)\b")
    token_re = re.compile(r"\b" + re.escape(macro) + r"\b")

    for base in ("include", "src", "tests", "examples"):
        for path in (root / base).rglob("*"):
            if path.suffix not in (".c", ".h"):
                continue
            relpath = path.relative_to(root).as_posix()
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if (relpath == definition_path) and (lineno == definition_line):
                    continue
                if (
                    (relpath == definition_path)
                    and (lineno + 1 == definition_line)
                    and re.match(
                        r"^\s*#\s*ifndef\s+" + re.escape(macro) + r"\s*$",
                        line,
                    )
                ):
                    continue
                if directive_re.match(line) and token_re.search(line):
                    return f"{relpath}:{lineno}"
    return None


def write_report(path, lines):
    text = "".join(line + "\n" for line in lines)
    Path(path).write_text(text, encoding="utf-8")


def main():
    args = parse_args()
    # Remove stale results before any validation that can raise. The workflow
    # records this process's exit status separately and never treats empty
    # reports from an aborted classification as a clean result.
    write_report(args.unresolved, [])
    write_report(args.deviated, [])
    write_report(args.limitations, [])

    root = Path(__file__).resolve().parent.parent
    manifest_path = root / "scripts" / "misra-deviations.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1:
        raise ValueError("unsupported MISRA deviation manifest schema")

    deviation_locations = {}
    expected_deviations = set()
    for deviation in manifest["deviations"]:
        for line in find_anchor_lines(root, deviation):
            key = (deviation["path"], line, deviation["rule"])
            if key in deviation_locations:
                raise ValueError(f"duplicate deviation location: {key}")
            deviation_locations[key] = deviation["id"]
            expected_deviations.add(key)

    unresolved = []
    deviated = []
    limitations = []
    observed_deviations = set()

    for raw_line in Path(args.input).read_text(encoding="utf-8").splitlines():
        match = DIAGNOSTIC_RE.match(raw_line)
        if match is None:
            unresolved.append(raw_line)
            continue

        relpath = match.group("path")
        lineno = int(match.group("line"))
        rule = match.group("rule")
        key = (relpath, lineno, rule)
        if key in deviation_locations:
            deviated.append(f"{deviation_locations[key]}: {raw_line}")
            observed_deviations.add(key)
            continue

        if rule == "2.5":
            lines = source_lines(root, relpath)
            if (lineno <= 0) or (lineno > len(lines)):
                unresolved.append(raw_line)
                continue
            define_match = DEFINE_RE.match(lines[lineno - 1])
            if define_match is not None:
                macro = define_match.group(1)
                evidence = macro_has_directive_use(root, macro, relpath, lineno)
                if evidence is not None:
                    limitations.append(f"{raw_line} [directive use: {evidence}]")
                    continue

        unresolved.append(raw_line)

    stale = sorted(expected_deviations - observed_deviations)
    if stale:
        for relpath, lineno, rule in stale:
            unresolved.append(
                f"{relpath}:{lineno}:0: stale approved deviation "
                f"[misra-c2012-{rule}]"
            )

    write_report(args.unresolved, unresolved)
    write_report(args.deviated, deviated)
    write_report(args.limitations, limitations)
    return 1 if unresolved else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"MISRA classifier error: {error}", file=sys.stderr)
        sys.exit(2)
