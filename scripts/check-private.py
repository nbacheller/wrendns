#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fails when a tracked or built file matches a maintainer's private denylist (DOC-006).

Maintainers keep a private list of identifiers that must never appear in the repository, the
built site or the generated docs (personal names, home addresses and networks, device names,
private hostnames and so on). The list is not in the repository, and this script contains none
of its entries: it reads them at run time from

    WRENDNS_PRIVACY_DENYLIST       a path to the denylist file
    WRENDNS_PRIVACY_DENYLIST_TEXT  the denylist itself (how CI passes a secret)

Both may be set; their patterns are combined (the file's first). With neither set, the check
is skipped with a notice and exits 0, so contributors without the list are not blocked, unless
`--require` is given or WRENDNS_PRIVACY_REQUIRED is `true`: then a missing list fails (exit 2).
CI requires it on the maintainers' own repository and before every site deploy.

Denylist format, one pattern per line:

    some literal text          matched exactly (case-sensitive)
    regex:PATTERN              a Python regular expression (put (?i) in it for case-insensitive)
    # a comment                ignored, as are blank lines

What is scanned: every file `git ls-files` lists, plus the built site in site/_site when it
exists, plus every JSON file under docs/ (the generated API, MCP, config and help files), even
before it is committed. Binary files are skipped. Each line is matched as written and, when it has
backslash escapes, once more with them removed, so an identifier written inside a regular
expression or an escaped string (each dot written as backslash-dot) is still found.

A hit is reported as `path:line: pattern #N`, where N is the 1-based position of the pattern
among the loaded patterns (comments and blank lines are not counted). The pattern and the
matched text are never printed, so the report can sit in a public CI log.

With `--history` the script scans the repository's history instead of the working tree (the two
modes are run separately; `--extra` does not apply to `--history`). It reads, from every ref
(`git log --all`, which includes HEAD): (1) every added line of every commit, (2) every commit message,
(3) every branch and tag name, local and remote-tracking, and (4) every file path that appears in
the history. Lines and messages are matched like the tree scan matches a line: as written and with
backslash escapes removed. Binary changes carry no text and are skipped (so is a file that
`.gitattributes` marks `-diff`, because git then prints no text for it). Git's output is streamed
and never held whole.

Merge commits are read with `-c` (combined diff): only lines the merge adds relative to every one
of its parents count, which is exactly the text a conflict resolution can introduce. A line that
a merge merely brings in from one parent was added by an ordinary commit on that side, and that
commit is scanned in its own right, so `-m` (a full diff against each parent, repeated per merge)
would only add duplicate work.

History hits are reported without the pattern, the matched text, the line, the commit subject, the
ref name or a path that itself matched, any of which can be the private string:

    commit <12 hex> <path>: pattern #N           an added line (the path is `<path withheld>`
                                                 when the path itself matches a pattern)
    commit <12 hex> message: pattern #N          a commit message
    ref -> <12 hex of its target>: pattern #N    a branch, tag or other ref name

One line is printed per distinct (commit, path, pattern), and the run ends with a count. A shallow
clone cannot prove a clean history, so `--history` fails on one (exit 2), as it does when git itself
fails (git's own messages are not passed on: they can quote a path or a ref).

Usage: python3 scripts/check-private.py [--root DIR] [--extra DIR ...] [--require] [--history]
(exit 1 on any hit, 2 on a missing or unusable list when required, a git failure, a shallow clone
in --history mode, or a bad argument)
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

ENV_FILE = "WRENDNS_PRIVACY_DENYLIST"
ENV_TEXT = "WRENDNS_PRIVACY_DENYLIST_TEXT"
ENV_REQUIRED = "WRENDNS_PRIVACY_REQUIRED"
REGEX_PREFIX = "regex:"
# Built or generated output that is scanned even though git does not track it.
EXTRA_TREES = ("site/_site",)
EXTRA_GLOBS = (("docs", "**/*.json"),)
# How much of a file is sniffed for a NUL byte to decide it is binary.
SNIFF = 8192
# Starts the one line git prints per commit in the history output; a random token follows it at
# run time, so no file content can imitate it (content lines carry a diff prefix in any case).
MARKER = "wrendns-history-commit:"
WITHHELD = "<path withheld>"


class DenylistError(Exception):
    """A denylist that cannot be used. The message never contains a pattern."""


def parse_denylist(text: str, start: int = 1) -> list[re.Pattern[str]]:
    """Compiles one pattern per non-blank, non-comment line. `start` numbers the first one."""
    patterns: list[re.Pattern[str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        index = start + len(patterns)
        if line.startswith(REGEX_PREFIX):
            source = line[len(REGEX_PREFIX):]
            if not source:
                raise DenylistError(f"pattern #{index} is an empty regex")
            try:
                patterns.append(re.compile(source))
            except re.error:
                # The re.error text quotes the pattern, so it is not passed on.
                raise DenylistError(f"pattern #{index} is not a valid regular expression") from None
        else:
            patterns.append(re.compile(re.escape(line)))
    return patterns


def load_patterns(env: dict[str, str]) -> list[re.Pattern[str]] | None:
    """The combined patterns from the environment, or None when neither variable is set."""
    path = env.get(ENV_FILE, "").strip()
    text = env.get(ENV_TEXT, "")
    if not path and not text.strip():
        return None
    patterns: list[re.Pattern[str]] = []
    if path:
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError:
            raise DenylistError(f"{ENV_FILE} names a file that cannot be read") from None
        patterns += parse_denylist(content)
    if text.strip():
        patterns += parse_denylist(text, start=len(patterns) + 1)
    if not patterns:
        raise DenylistError("the denylist has no patterns")
    return patterns


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p]


def extra_files(root: Path, extra_dirs: list[str]) -> list[str]:
    found: list[str] = []
    root = root.resolve()
    for tree in list(EXTRA_TREES) + extra_dirs:
        base = (root / tree).resolve()
        if not base.is_relative_to(root):
            raise DenylistError("an --extra directory must be inside --root")
        if base.is_dir():
            found += [p.relative_to(root).as_posix() for p in base.rglob("*") if p.is_file()]
    for directory, pattern in EXTRA_GLOBS:
        base = root / directory
        if base.is_dir():
            found += [p.relative_to(root).as_posix() for p in base.glob(pattern) if p.is_file()]
    return found


def files_to_scan(root: Path, extra_dirs: list[str]) -> list[str]:
    return sorted(set(tracked_files(root)) | set(extra_files(root, extra_dirs)))


def read_text(path: Path) -> str | None:
    """The file's text, or None for a binary, missing or unreadable file."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:SNIFF]:
        return None
    return data.decode("utf-8", errors="replace")


# One or more backslashes before punctuation, as in a regular expression or an escaped string.
ESCAPED = re.compile(r"\\+([^\w\s\\])")


def spellings(line: str) -> list[str]:
    """The line as written, plus the line with escapes removed when it has any, so an
    identifier written inside a regex or a JSON string is still found."""
    plain = ESCAPED.sub(r"\1", line)
    return [line] if plain == line else [line, plain]


def scan_text(text: str, patterns: list[re.Pattern[str]]) -> list[tuple[int, int]]:
    """(line number, pattern number) for every pattern that matches a line, both 1-based."""
    hits: list[tuple[int, int]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        forms = spellings(line)
        for index, pattern in enumerate(patterns, 1):
            if any(pattern.search(form) for form in forms):
                hits.append((lineno, index))
    return hits


def scan(root: Path, files: list[str], patterns: list[re.Pattern[str]]) -> list[str]:
    report: list[str] = []
    for rel in files:
        text = read_text(root / rel)
        if text is None:
            continue
        for lineno, index in scan_text(text, patterns):
            report.append(f"{rel}:{lineno}: pattern #{index}")
    return report


class GitError(Exception):
    """A git command that failed. The message never contains git's own output."""


def git_chunks(root: Path, args: list[str]) -> Iterator[bytes]:
    """Streams git's stdout in chunks and raises GitError when git fails. Git's stderr is
    discarded: it can quote a path or a ref name that is itself the private string."""
    cmd = ["git", "--no-replace-objects", "-C", str(root), *args]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL
        )
    except OSError:
        raise GitError("git could not be run") from None
    assert proc.stdout is not None
    try:
        while chunk := proc.stdout.read(1 << 16):
            yield chunk
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        code = proc.wait()
    if code != 0:
        raise GitError(f"git {args[0]} failed (exit {code})")


def git_lines(root: Path, args: list[str]) -> Iterator[bytes]:
    """git's stdout, one line at a time, without the newline."""
    rest = b""
    for chunk in git_chunks(root, args):
        rest += chunk
        *lines, rest = rest.split(b"\n")
        yield from lines
    if rest:
        yield rest


def git_records(root: Path, args: list[str]) -> Iterator[bytes]:
    """git's NUL-terminated output (`-z`), one record at a time."""
    rest = b""
    for chunk in git_chunks(root, args):
        rest += chunk
        *records, rest = rest.split(b"\0")
        yield from records
    if rest:
        yield rest


def git_text(root: Path, args: list[str]) -> str:
    return b"".join(git_chunks(root, args)).decode("utf-8", errors="replace").strip()


def check_not_shallow(root: Path) -> None:
    answer = git_text(root, ["rev-parse", "--is-shallow-repository"])
    if answer == "true":
        raise GitError("the repository is a shallow clone, which cannot prove a clean history")
    if answer != "false":
        raise GitError("cannot tell whether the repository is a shallow clone")


def match_indices(text: str, patterns: list[re.Pattern[str]]) -> list[int]:
    """The 1-based numbers of the patterns that match any line of text, as the tree scan does."""
    return sorted({index for _, index in scan_text(text, patterns)})


class HistoryReport:
    """Distinct hit lines, in the order found."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self._seen: set[str] = set()

    def add(self, line: str) -> None:
        if line not in self._seen:
            self._seen.add(line)
            self.lines.append(line)


_QUOTED = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}


def unquote_path(raw: str) -> str:
    """Undoes git's C-style quoting of a path (a backslash-t for a tab, octal for non-ASCII)."""
    if not (len(raw) >= 2 and raw.startswith('"') and raw.endswith('"')):
        return raw
    out = bytearray()
    body = raw[1:-1]
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            octal = re.match(r"[0-7]{1,3}", body[i + 1:])
            if octal:
                out.append(int(octal.group(), 8) & 0xFF)
                i += 1 + len(octal.group())
                continue
            if body[i + 1] in _QUOTED:
                out.append(_QUOTED[body[i + 1]])
                i += 2
                continue
        out += ch.encode("utf-8", errors="replace")
        i += 1
    return out.decode("utf-8", errors="replace")


def diff_path(header: str) -> str | None:
    """The path in a `+++ ` header line, or None for /dev/null."""
    path = unquote_path(header[4:].rstrip("\t"))
    if path == "/dev/null":
        return None
    return path[2:] if path.startswith("b/") else path


HUNK = re.compile(r"^(@{2,}) ")
RAW_META = re.compile(r"^\n?:\d{6} \d{6} [0-9a-f]+ [0-9a-f]+ [A-Z]\d*$")


def scan_commit_messages(
    root: Path, revs: list[str], patterns: list[re.Pattern[str]], report: HistoryReport
) -> int:
    """Scans every commit message and returns the number of commits. A message cannot hold a
    NUL byte, so the `-z` records are unambiguous."""
    commits = 0
    args = ["log", *revs, "--no-show-signature", "-z", "--format=%H%n%B"]
    for record in git_records(root, args):
        commit, _, message = record.decode("utf-8", errors="replace").partition("\n")
        commits += 1
        for index in match_indices(message, patterns):
            report.add(f"commit {commit.strip()[:12]} message: pattern #{index}")
    return commits


def scan_ref_names(root: Path, patterns: list[re.Pattern[str]], report: HistoryReport) -> None:
    """Scans every ref name (branches, tags, remote-tracking), in full and without `refs/<kind>/`."""
    args = ["for-each-ref", "--format=%(objectname) %(*objectname) %(refname)"]
    for raw in git_lines(root, args):
        parts = raw.decode("utf-8", errors="replace").split(" ", 2)
        if len(parts) != 3:
            raise GitError("unexpected for-each-ref output")
        target = (parts[1] or parts[0])[:12]
        ref = parts[2]
        names = [ref] + ([ref.split("/", 2)[2]] if ref.count("/") >= 2 else [])
        found = {index for name in names for index in match_indices(name, patterns)}
        for index in sorted(found):
            report.add(f"ref -> {target}: pattern #{index}")


def scan_added_lines(
    root: Path, revs: list[str], patterns: list[re.Pattern[str]], report: HistoryReport
) -> None:
    """Scans the lines every commit added. A merge is shown as a combined diff, where only a
    line with `+` in every parent column (text the merge itself introduced) counts."""
    token = secrets.token_hex(16)
    marker = (MARKER + token).encode()
    args = [
        "log", *revs, "-p", "-c", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
        "--no-renames", "--no-show-signature", "--src-prefix=a/", "--dst-prefix=b/",
        f"--format={MARKER}{token}%H",
    ]
    commit = ""
    path: str | None = None
    columns = 1
    in_hunk = False
    path_matches: dict[str, bool] = {}

    def label() -> str:
        if path is None:
            return WITHHELD
        if path not in path_matches:
            path_matches[path] = bool(match_indices(path, patterns))
        return WITHHELD if path_matches[path] else path

    for raw in git_lines(root, args):
        if raw.startswith(marker):
            commit = raw[len(marker):].decode("ascii", errors="replace").strip()[:12]
            path, in_hunk = None, False
            continue
        line = raw.decode("utf-8", errors="replace")
        # Inside a hunk every line starts with a diff prefix, so nothing in a file's content can
        # be taken for a header or for the commit marker.
        if in_hunk and line[:1] in (" ", "+", "-", "\\"):
            if line[:columns] == "+" * columns:
                for index in match_indices(line[columns:], patterns):
                    report.add(f"commit {commit} {label()}: pattern #{index}")
            continue
        in_hunk = False
        hunk = HUNK.match(line)
        if hunk:
            columns, in_hunk = len(hunk.group(1)) - 1, True
        elif line.startswith("diff "):
            path = None
        elif line.startswith("+++ "):
            path = diff_path(line)


def scan_paths(
    root: Path, revs: list[str], patterns: list[re.Pattern[str]], report: HistoryReport
) -> None:
    """Scans every path that appears in the history, deleted ones included. The raw `-z` output
    is read by position (a path always follows its metadata record), so a path cannot be taken
    for a commit marker."""
    token = secrets.token_hex(16)
    marker = (MARKER + token).encode()
    args = [
        "log", *revs, "--raw", "-z", "--no-abbrev", "--no-renames", "--no-show-signature",
        f"--format={MARKER}{token}%H",
    ]
    commit = ""
    want_path = False
    matches: dict[str, list[int]] = {}
    for record in git_records(root, args):
        if want_path:
            want_path = False
            text = record.decode("utf-8", errors="replace")
            if text not in matches:
                matches[text] = match_indices(text, patterns)
            for index in matches[text]:
                report.add(f"commit {commit} {WITHHELD}: pattern #{index}")
        elif RAW_META.match(record.decode("ascii", errors="replace")):
            want_path = True
        elif record.startswith(marker):
            commit = record[len(marker):].decode("ascii", errors="replace").strip()[:12]
        else:
            raise GitError("unexpected log output")
    if want_path:
        raise GitError("unexpected end of log output")


def scan_history(root: Path, patterns: list[re.Pattern[str]]) -> tuple[HistoryReport, int]:
    """Runs the four history scans; returns the report and the commit count, or raises GitError."""
    check_not_shallow(root)
    revs = ["--all"]  # every ref, and HEAD too (a detached checkout may be on no ref)
    report = HistoryReport()
    commits = scan_commit_messages(root, revs, patterns, report)
    scan_ref_names(root, patterns, report)
    scan_added_lines(root, revs, patterns, report)
    scan_paths(root, revs, patterns, report)
    return report, commits


def main(argv: list[str] | None = None, env: dict[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=None, help="repository root (default: the git top level)")
    parser.add_argument(
        "--extra", action="append", default=[], help="another directory to scan (repeatable)"
    )
    parser.add_argument(
        "--require",
        action="store_true",
        help=f"fail when no denylist is set (also: {ENV_REQUIRED}=true)",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="scan the git history (added lines, messages, ref names, paths) instead of the tree",
    )
    args = parser.parse_args(argv)
    if args.history and args.extra:
        parser.error("--extra does not apply to --history")
    env = dict(os.environ) if env is None else env

    try:
        patterns = load_patterns(env)
    except DenylistError as err:
        print(f"check-private: {err}", file=sys.stderr)
        return 2
    required = args.require or env.get(ENV_REQUIRED, "").strip().lower() == "true"
    if patterns is None and required:
        message = f"check-private: required, but neither {ENV_FILE} nor {ENV_TEXT} is set"
        print(f"::error::{message}" if env.get("GITHUB_ACTIONS") == "true" else message, file=sys.stderr)
        return 2
    if patterns is None:
        message = f"check-private: skipped, neither {ENV_FILE} nor {ENV_TEXT} is set"
        # A GitHub Actions notice, so a run without the secret says so on the summary page.
        print(f"::notice::{message}" if env.get("GITHUB_ACTIONS") == "true" else message)
        return 0

    if args.root:
        root = Path(args.root).resolve()
    else:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], check=True, capture_output=True, text=True
        ).stdout.strip()
        root = Path(top)

    if args.history:
        try:
            history, commits = scan_history(root, patterns)
        except GitError as err:
            print(f"check-private: {err}", file=sys.stderr)
            return 2
        if history.lines:
            print("\n".join(history.lines))
            print(
                f"check-private: {len(history.lines)} history hit(s) in {commits} commit(s)"
                f" against {len(patterns)} pattern(s); the numbers are the denylist's",
                file=sys.stderr,
            )
            return 1
        print(f"check-private: history of {commits} commit(s) clean against {len(patterns)} pattern(s)")
        return 0

    try:
        files = files_to_scan(root, args.extra)
    except DenylistError as err:
        print(f"check-private: {err}", file=sys.stderr)
        return 2
    report = scan(root, files, patterns)
    if report:
        print("\n".join(report))
        print(
            f"check-private: {len(report)} hit(s) in {len({r.rsplit(':', 2)[0] for r in report})}"
            f" file(s) against {len(patterns)} pattern(s); generalize them (see CONTRIBUTING.md)",
            file=sys.stderr,
        )
        return 1
    print(f"check-private: {len(files)} file(s) clean against {len(patterns)} pattern(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
