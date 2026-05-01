#!/usr/bin/env python3
"""
Export a LastPass vault (via ``lpass``) into the 1Password Unencrypted Export
(1PUX) ZIP format described at https://support.1password.com/1pux-format/

Requirements:
  - Authenticated LastPass CLI: ``lpass`` on PATH.

Security:
  Produces **unencrypted** vault data and attachment bytes. Protect the output.

Usage:
  python3 lastpass_to_1pux.py -o migration.1pux

  # Optional labeling for the synthetic 1Password account record in export.data:
  python3 lastpass_to_1pux.py -o migration.1pux --email you@example.com --account-name \"My Vault\"
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import uuid
import zipfile
from pathlib import Path
from typing import Any, Callable, Iterable

# Official item type codes used in exported 1PUX (see 1Password support article).
CAT_LOGIN = "001"
CAT_SECURE_NOTE = "003"

SYNTHETIC_DOMAIN = "https://imports.lastpass.local/"


def _rand_word26(chars: str) -> str:
    return "".join(secrets.choice(chars) for _ in range(26))


def gen_item_uuid() -> str:
    return _rand_word26(string.ascii_lowercase + string.digits)


def gen_account_uuid() -> str:
    return _rand_word26(string.ascii_uppercase + string.digits)


def gen_vault_uuid() -> str:
    return gen_item_uuid()


# Some pipelines corrupt UTF-8 (e.g. æ = C3 A6) into U+FFFD + literal "ff" + hex digits.
# Example: ``L\ufffdffc3\ufffdffa6gehuset`` → ``Lægehuset``.
# Require ``\ufffd`` before the first ``ff`` so random hex-like passwords are not touched.
_PAT_MANGLED_HEX_UTF8 = re.compile(
    r"\ufffd+f+(?P<b1>[0-9A-Fa-f]{2})\ufffd+f+(?P<b2>[0-9A-Fa-f]{2})"
)


def repair_mangled_ff_hex_utf8(s: str) -> str:
    def repl(m: re.Match[str]) -> str:
        try:
            return bytes.fromhex(m.group("b1") + m.group("b2")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return m.group(0)

    prev = ""
    while prev != s:
        prev = s
        s = _PAT_MANGLED_HEX_UTF8.sub(repl, s)
    return s


def repair_mojibake_latin1_utf8(s: str) -> str:
    """Undo UTF-8 bytes mis-read as Latin-1 (``Ã¦`` → ``æ``), possibly repeated."""
    for _ in range(5):
        if "Ã" not in s and "Â" not in s:
            break
        try:
            t = s.encode("latin-1").decode("utf-8")
            if t == s or "\ufffd" in t:
                break
            s = t
        except (UnicodeDecodeError, UnicodeEncodeError):
            break
    return s


def decode_lpass_text(raw: bytes | None) -> str:
    """Decode bytes from ``lpass`` stdout/stderr without mangling Nordic / Unicode text.

    - Prefer strict UTF-8 (no ``U+FFFD`` substitution from invalid sequences).
    - Fall back to Windows-1252 / Latin-1 when the CLI emits non-UTF-8 bytes.
    - Repair common *mojibake*: UTF-8 sequences wrongly interpreted as Latin-1
      (e.g. ``KÃ¸benhavn`` → ``København``), which otherwise surfaces as odd
      characters or replacement glyphs in downstream apps.
    """
    if not raw:
        return ""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = raw.decode("cp1252")
        except UnicodeDecodeError:
            s = raw.decode("latin-1")
        return repair_lp_unicode(s)

    s = repair_mangled_ff_hex_utf8(s)
    s = repair_mojibake_latin1_utf8(s)
    try:
        s = unicodedata.normalize("NFC", s)
    except Exception:
        pass
    return s


def repair_lp_unicode(s: str) -> str:
    """Normalize Nordic / Unicode text for JSON and CSV-derived strings."""
    if not s:
        return s
    s = repair_mangled_ff_hex_utf8(s)
    s = repair_mojibake_latin1_utf8(s)
    try:
        s = unicodedata.normalize("NFC", s)
    except Exception:
        pass
    return s


# Module-level toggle: when True, lpass is allowed to interactively
# prompt for the master password (pinentry / TTY / askpass). When False,
# every channel `lpass` could use to ask is closed, so reprompt-protected
# items fail fast instead of blocking the migration on a dialog.
ALLOW_REPROMPT_PROMPTS = True


def _lpass_env(*, allow_prompt: bool) -> dict[str, str]:
    """Build subprocess env for child `lpass` invocations.

    - Always keeps the agent alive (LPASS_AGENT_TIMEOUT=0) so a single
      successful master-password entry covers the whole run.
    - When allow_prompt is False, *also* disables every avenue lpass uses
      to ask for a password: pinentry binary, askpass binary, and reading
      from a TTY. Combined with stdin=DEVNULL on the subprocess that means
      a reprompt-protected item simply errors out and we record it.
    """
    env = dict(os.environ)
    env.setdefault("LANG", "C.UTF-8")
    env.setdefault("LC_ALL", "C.UTF-8")
    env["LPASS_AGENT_TIMEOUT"] = "0"
    env.pop("LPASS_AGENT_DISABLE", None)

    if not allow_prompt:
        env["LPASS_DISABLE_PINENTRY"] = "1"
        env.pop("LPASS_PINENTRY", None)
        env.pop("LPASS_ASKPASS", None)
        env.pop("SSH_ASKPASS", None)
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
        env["GPG_TTY"] = ""
    return env


def run_lpass(
    argv: list[str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    allow_prompt: bool | None = None,
    binary_stdout: bool = False,
) -> subprocess.CompletedProcess:
    """Run ``lpass`` and return the CompletedProcess.

    By default we honor :data:`ALLOW_REPROMPT_PROMPTS`. Pass allow_prompt=True
    explicitly to override (the CLI does this when --include-reprompt is set).
    """
    if allow_prompt is None:
        allow_prompt = ALLOW_REPROMPT_PROMPTS
    env = _lpass_env(allow_prompt=allow_prompt)
    stdin_arg = None if (allow_prompt and input_bytes is None) else subprocess.DEVNULL
    if input_bytes is not None:
        stdin_arg = subprocess.PIPE

    common_kwargs: dict[str, Any] = {
        "check": False,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": stdin_arg,
        "cwd": cwd,
        "env": env,
    }
    if binary_stdout:
        # Caller is responsible for decoding bytes (used for attachment data).
        common_kwargs["input"] = input_bytes
        common_kwargs["text"] = False
    else:
        common_kwargs["text"] = False
        common_kwargs["input"] = input_bytes

    try:
        proc = subprocess.run(["lpass", *argv], **common_kwargs)
    except FileNotFoundError as e:
        raise SystemExit(
            "`lpass` was not found on PATH. Install lastpass-cli and log in with `lpass login`.\n"
            "Upstream: https://github.com/lastpass/lastpass-cli/tree/master"
        ) from e

    if binary_stdout:
        return proc

    out_b = proc.stdout if isinstance(proc.stdout, (bytes, bytearray)) else b""
    err_b = proc.stderr if isinstance(proc.stderr, (bytes, bytearray)) else b""
    return subprocess.CompletedProcess(
        proc.args,
        proc.returncode,
        decode_lpass_text(out_b),
        decode_lpass_text(err_b),
    )


def require_status() -> None:
    """Best-effort login check.

    `lpass status --quiet` queries the running agent only and returns nonzero
    when the agent's cache has been flushed, even if a master password (or
    plaintext key) would let the next real command succeed. So we warn rather
    than bail, and let the first real command surface a hard error if needed.
    """
    p = run_lpass(["status", "--color=never", "--quiet"])
    if p.returncode != 0:
        sys.stderr.write(
            "warning: `lpass status` reports not-logged-in (agent cache empty).\n"
            "         Continuing — the first export call will re-prompt or fail with a clearer error.\n"
        )


EXPORT_FIELDS = "id,name,grouping,url,username,password,extra,fav,attachpresent,last_modified_gmt"


def _read_export_csv(sync: str) -> list[list[str]]:
    p = run_lpass(
        [
            "export",
            f"--sync={sync}",
            "--color=never",
            f"--fields={EXPORT_FIELDS}",
        ]
    )
    if p.returncode != 0:
        raise SystemExit(f"lpass export failed ({p.returncode}):\n{p.stderr or p.stdout}")
    rows: list[list[str]] = []
    reader = csv.reader(io.StringIO(p.stdout))
    for row in reader:
        if row:
            rows.append(row)
    return rows


def parse_export_ids(sync: str) -> list[str]:
    """Enumerate credential items (``lpass export`` skips ``http://group`` rows)."""
    rows = _read_export_csv(sync)
    if len(rows) < 2:
        return []
    header = rows[0]
    try:
        idx = header.index("id")
    except ValueError as e:
        raise SystemExit(
            "`lpass export` CSV missing `id` column even though it was requested via --fields."
        ) from e
    ids: list[str] = []
    for row in rows[1:]:
        if idx >= len(row):
            continue
        ident = row[idx].strip()
        if ident:
            ids.append(ident)
    return ids


REPROMPT_HINT_PHRASES = (
    "Could not authenticate for protected entry",
    "Current key is not on-disk key",
    "Failed to enter correct password",
    "PIN entry process",
    "Inappropriate ioctl for device",
    "/dev/tty",
    "stdin: it is not a TTY",
    "DISABLE_PINENTRY",
)


def looks_unprompted_failure(err: str) -> bool:
    """Heuristic: did lpass die because we deliberately starved it of a prompt?"""
    if not err:
        return False
    return any(sig in err for sig in REPROMPT_HINT_PHRASES)


def lp_show_json(ident: str, sync: str, *, include_reprompt: bool = False) -> dict[str, Any]:
    p = run_lpass(["show", f"--sync={sync}", "--color=never", "--json", ident], allow_prompt=include_reprompt)
    if p.returncode != 0:
        err = (p.stderr or "") + (p.stdout or "")
        # When prompts are disabled, treat any "needs a password" failure as a
        # clean reprompt-skip signal so the caller records and moves on.
        if looks_like_pwprotect_error(err) or (
            not include_reprompt and looks_unprompted_failure(err)
        ):
            raise SkipReprompt("password reprompt blocked by --no-prompt mode")
        raise RuntimeError(f"lpass show --json '{ident}' failed:\n{err}")
    data = json.loads(p.stdout)
    if isinstance(data, list):
        if not data:
            raise RuntimeError(f"Empty JSON response for `{ident}`")
        return data[0]
    if isinstance(data, dict):
        return data
    raise RuntimeError(f"Unexpected JSON shape for `{ident}`")


def lp_attachment_bytes(ident: str, attach_full_id: str, sync: str) -> bytes:
    att = attach_full_id.strip()
    if not att.startswith("att-"):
        att = "att-" + att
    p = run_lpass(
        ["show", f"--sync={sync}", "--color=never", "--quiet", f"--attach={att}", ident],
        binary_stdout=True,
    )
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", errors="replace") if p.stderr else ""
        raise RuntimeError(f"lpass attachment failed for `{ident}` {att}:\n{err}")

    # `--quiet` writes raw decrypted attachment bytes — must be binary.
    return p.stdout if isinstance(p.stdout, (bytes, bytearray)) else b""


def parse_attach_lines(show_text: str) -> list[tuple[str, str]]:
    """Pairs of ``(att-xxxx, displayed_filename_hint)`` from ``lpass show --all`` output."""
    out: list[tuple[str, str]] = []
    for line in show_text.splitlines():
        line = strip_ansi(line).strip()
        m = re.match(r"^(att-[^:\s]+)\s*:\s*(.*)$", line)
        if not m:
            continue
        out.append((m.group(1), m.group(2).strip()))
    return out


def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", s)


def parse_show_plain_map(show_text: str) -> dict[str, str]:
    """Best-effort key/value map from colored ``lpass show --all`` output."""
    found: dict[str, str] = {}
    tail: list[str] = []
    in_notes = False
    skip_keys = {}

    lines = strip_ansi(show_text).splitlines()
    for i, raw in enumerate(lines):
        line = raw.rstrip()
        if i == 0 and "[id:" in line:
            continue
        if not line.strip():
            if in_notes:
                tail.append("")
            continue
        if ":" in line and not in_notes:
            k, _, rest = line.partition(":")
            key = k.strip()
            rest = rest.lstrip()
            if key == "Notes":
                in_notes = True
                if rest:
                    tail.append(rest)
                continue
            if key.startswith("att-"):
                skip_keys.setdefault(key.split(":", 1)[0], True)
                continue
            found[key] = rest
        else:
            if in_notes or "Notes" in found:
                in_notes = True
                tail.append(line)
            else:
                # Continuation lines are rare outside Notes; stash by last key isn't implemented.
                pass

    notes = "\n".join(tail).strip("\n")
    if notes:
        found["Notes"] = notes

    found.pop("Reprompt", None)
    return found


def lastpass_ts(ts: Any) -> int:
    if ts is None or ts == "":
        return int(time.time())
    try:
        return int(str(ts).strip())
    except ValueError:
        return int(time.time())


def sanitize_filename(name: str) -> str:
    name = os.path.basename(name.strip() or "attachment")
    if not name:
        name = "attachment"
    for bad in ("\x00",):
        name = name.replace(bad, "")
    return name.replace(os.sep, "_").replace("/", "_")


def grouping_to_tags(grouping_val: Any) -> list[str]:
    if not grouping_val:
        return []
    s = repair_lp_unicode(str(grouping_val).replace("/", "\\").strip("\\"))
    if not s:
        return []
    parts = []
    for p in s.split("\\"):
        p = repair_lp_unicode(p.strip())
        if p and p not in parts:
            parts.append(p)
    return parts


def grouping_to_vault_name(grouping_val: Any) -> str:
    """
    Map LastPass grouping path to a vault name for 1PUX consumers that
    preserve vaults but ignore tags (e.g. some third-party importers).
    """
    if not grouping_val:
        return "Imported"
    parts = grouping_to_tags(grouping_val)
    if not parts:
        return "Imported"
    return "/".join(parts)


def item_tags_for_folder_mode(grouped_path: str | None, folder_mode: str) -> list[str]:
    """How ``overview.tags`` should reflect LastPass folder paths."""
    path = grouping_to_vault_name(grouped_path or "")
    parts = grouping_to_tags(grouped_path or "")
    if folder_mode == "tags":
        return parts
    if folder_mode == "path-tag":
        return [path] if path != "Imported" else []
    # ``vaults`` and ``proton-accounts``: many importers (incl. Proton Pass)
    # still flatten vaults — keep the full path as a single tag as a fallback.
    if folder_mode in ("vaults", "proton-accounts"):
        return [path] if path != "Imported" else []
    return parts


def is_secure_note_url(url_val: Any) -> bool:
    return str(url_val or "").strip() == "http://sn"


_REPROMPT_RE = re.compile(r"^\s*Reprompt\s*:\s*Yes\s*$", re.MULTILINE)


def detect_reprompt(plaintext: str) -> bool:
    """Return True if a `lpass show --all` dump indicates Password Reprompt."""
    if not plaintext:
        return False
    return bool(_REPROMPT_RE.search(strip_ansi(plaintext)))


REPROMPT_SIGNATURES = (
    "Could not authenticate for protected entry",
    "Current key is not on-disk key",
)


def looks_like_pwprotect_error(stderr: str) -> bool:
    if not stderr:
        return False
    return any(sig in stderr for sig in REPROMPT_SIGNATURES)


def build_overview(
    title: str,
    *,
    subtitle: str = "",
    url: str | None = None,
    urls: Iterable[dict[str, str]] | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    o: dict[str, Any] = {
        "subtitle": subtitle,
        "title": title,
        "tags": tags or [],
    }
    primary = url.strip() if url else ""
    if primary and primary not in ("http://", "http://sn", "http://group"):
        if urls is None:
            urls_iter = [{"label": "", "url": primary}]
        else:
            urls_iter = list(urls)
            if all(u.get("url") != primary for u in urls_iter):
                urls_iter = [{"label": "", "url": primary}] + urls_iter
    else:
        urls_iter = list(urls) if urls else []
        primary = ""

    if urls_iter:
        o["urls"] = urls_iter

    # Many samples include singular ``url`` when a primary exists.
    if primary:
        o["url"] = primary

    return o


class SkipReprompt(Exception):
    """Raised to short-circuit conversion of a password-reprompt-protected item."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ExportCancelled(Exception):
    """Raised when ``assemble_1pux`` aborts because the caller set ``cancel_event``."""


def lp_item_to_records(
    acc: dict[str, Any],
    *,
    grouping: str | None,
    sync: str,
    export_tmp: Path,
    include_reprompt: bool = False,
    folder_mode: str = "tags",
) -> tuple[list[dict[str, Any]], set[str]]:
    """
    Produce 1Password item dicts (excluding outer ``vaults/items`` wrappers).
    Returns (records, filenames_used_inside_zip_under_files/)

    By default, raises SkipReprompt if the LastPass item has Password Reprompt
    enabled. With include_reprompt=True we proceed normally — the user has
    accepted that lpass may interactively re-prompt for the master password
    once per affected item.
    """
    acc = dict(acc)
    for _k in ("name", "fullname", "username", "password", "note", "url", "group"):
        _v = acc.get(_k)
        if isinstance(_v, str) and _v:
            acc[_k] = repair_lp_unicode(_v)
    if isinstance(acc.get("share"), str) and acc["share"]:
        acc["share"] = repair_lp_unicode(acc["share"])

    ident = acc.get("id") or ""
    title = repair_lp_unicode(str(acc.get("name") or "(untitled)"))

    fav_idx = int(bool(acc.get("fav")))
    fav_index = fav_idx if fav_idx else 0

    grouped_path = grouping if grouping is not None else None
    if grouped_path is None:
        grp = ""
        if acc.get("share"):
            grp = f"{acc.get('share')}\\{acc.get('group', '')}"
        elif acc.get("group"):
            grp = str(acc.get("group"))
        grouped_path = grp

    tags = item_tags_for_folder_mode(grouped_path, folder_mode)

    created = updated = lastpass_ts(acc.get("last_modified_gmt"))

    plaintext = ""
    if ident:
        p = run_lpass(["show", f"--sync={sync}", "--color=never", "--all", ident], allow_prompt=include_reprompt)
        if p.returncode == 0:
            plaintext = p.stdout or ""
        else:
            err = (p.stderr or "") + (p.stdout or "")
            if looks_like_pwprotect_error(err) or (
                not include_reprompt and looks_unprompted_failure(err)
            ):
                if not include_reprompt:
                    raise SkipReprompt(
                        "password reprompt (lpass refused to decrypt without prompt)"
                    )
                sys.stderr.write(
                    f"warning: reprompt-protected `{title}` ({ident}) returned `{err.strip().splitlines()[0] if err.strip() else 'error'}` "
                    f"— continuing with degraded data.\n"
                )
            # Nonfatal: keep plaintext empty and try to use JSON-only data.
            plaintext = ""

    if detect_reprompt(plaintext) and not include_reprompt:
        raise SkipReprompt("password reprompt flag set on item")

    plain_map = parse_show_plain_map(plaintext) if plaintext else {}

    attach_pairs = parse_attach_lines(plaintext) if plaintext else []
    filenames_used: set[str] = set()

    records: list[dict[str, Any]] = []

    url_val = acc.get("url") or ""
    user_val = repair_lp_unicode(str(plain_map.get("Username") or acc.get("username") or ""))
    password_val = repair_lp_unicode(str(plain_map.get("Password") or acc.get("password") or ""))

    notes_from_export = plain_map.get("Notes")
    notes_plain_parts: list[str] = []
    if notes_from_export not in ("", None):
        notes_plain_parts.append(str(notes_from_export))
    extra_note = acc.get("note") or ""
    if str(extra_note).strip() and str(extra_note) not in ("\n".join(notes_plain_parts).strip()):
        notes_plain_parts.append(str(extra_note))
    merged_notes_plain = repair_lp_unicode(
        "\n\n".join(part for part in notes_plain_parts if str(part).strip())
    )

    urls_for_overview = []
    u = str(url_val).strip()
    if u and u not in ("http://", "http://sn", "http://group") and not is_secure_note_url(u):
        urls_for_overview.append({"label": "", "url": u})

    if is_secure_note_url(url_val):
        sec_fields: list[dict[str, Any]] = []
        for k, v in plain_map.items():
            if k in ("Username", "Password", "URL", "Notes", "Application"):
                continue
            if k.startswith("att-"):
                continue
            fk = uuid.uuid4().hex.upper()
            sec_fields.append(
                {
                    "title": k,
                    "id": fk,
                    "value": {"string": repair_lp_unicode(str(v))},
                    "indexAtSource": len(sec_fields),
                    "guarded": False,
                    "multiline": True,
                    "dontGenerate": False,
                    "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"},
                }
            )

        sections = []
        if sec_fields:
            sections.append(
                {
                    "title": "Imported fields",
                    "name": "Section_" + uuid.uuid4().hex,
                    "fields": sec_fields,
                }
            )

        item_uuid = gen_item_uuid()
        details: dict[str, Any] = {
            "loginFields": [],
            "notesPlain": merged_notes_plain,
            "passwordHistory": [],
        }
        if sections:
            details["sections"] = sections

        records.append(
            {
                "uuid": item_uuid,
                "favIndex": fav_index,
                "createdAt": created,
                "updatedAt": updated,
                "state": "active",
                "categoryUuid": CAT_SECURE_NOTE,
                "details": details,
                "overview": build_overview(title, subtitle="", tags=tags),
            }
        )

    elif str(url_val) == "http://group":
        return [], filenames_used

    else:
        login_fields: list[dict[str, Any]] = []
        if user_val != "":
            login_fields.append(
                {
                    "value": user_val,
                    "id": "",
                    "name": "username",
                    "fieldType": "T",
                    "designation": "username",
                }
            )
        if password_val != "":
            login_fields.append(
                {
                    "value": password_val,
                    "id": "",
                    "name": "password",
                    "fieldType": "P",
                    "designation": "password",
                }
            )

        details: dict[str, Any] = {"passwordHistory": []}
        if login_fields:
            details["loginFields"] = login_fields
        else:
            details["loginFields"] = []
        details["notesPlain"] = merged_notes_plain

        app_label = plain_map.get("Application")
        if app_label and str(app_label).strip():
            fk = uuid.uuid4().hex.upper()
            details.setdefault("sections", []).append(
                {
                    "title": "Application",
                    "name": "Section_" + uuid.uuid4().hex,
                    "fields": [
                        {
                            "title": "Application name",
                            "id": fk,
                            "value": {"string": repair_lp_unicode(str(app_label))},
                            "indexAtSource": 0,
                            "guarded": False,
                            "multiline": False,
                            "dontGenerate": False,
                            "inputTraits": {
                                "keyboard": "default",
                                "correction": "default",
                                "capitalization": "default",
                            },
                        }
                    ],
                }
            )

        item_uuid = gen_item_uuid()

        subtitle = ""
        if user_val:
            subtitle = user_val

        records.append(
            {
                "uuid": item_uuid,
                "favIndex": fav_index,
                "createdAt": created,
                "updatedAt": updated,
                "state": "active",
                "categoryUuid": CAT_LOGIN,
                "details": details,
                "overview": build_overview(title, subtitle=subtitle, url=u or None, urls=urls_for_overview, tags=tags),
            }
        )

    if not attach_pairs and acc.get("attachpresent"):
        # Fallback: allow ``lpass export`` boolean without parsed lines only if plaintext failed.
        if not plaintext.strip():
            p2 = run_lpass(["show", f"--sync={sync}", "--color=never", ident], allow_prompt=include_reprompt)
            if p2.returncode == 0:
                attach_pairs = parse_attach_lines(p2.stdout)

    if not records:
        return records, filenames_used

    # Embed attachments on the parent item.
    # Native 1PUX uses ``sections[].fields[].value.file``; many importers (incl. some
    # Proton Pass builds) also expect ``details.documentAttributes`` plus a top-level
    # ``file`` entry pointing at the first blob in ``files/`` (see 1Password export docs).
    parent_details = records[-1]["details"]
    parent_details.setdefault("passwordHistory", [])
    parent_details.setdefault("loginFields", [])
    attach_fields: list[dict[str, Any]] = []
    first_zip_relpath: str | None = None
    first_file_meta: dict[str, Any] | None = None

    for att_full, hinted_name in attach_pairs:
        att_id_digits = att_full.split("-", 1)[-1] if "-" in att_full else att_full
        try:
            data = lp_attachment_bytes(ident, att_full, sync)
        except Exception as e:
            sys.stderr.write(f"Skipping attachment `{att_full}` on `{title}` ({ident}): {e}\n")
            continue

        doc_id = gen_item_uuid()
        fname = hinted_name.strip() if hinted_name.strip() else f"attachment-{att_id_digits}"
        fname = sanitize_filename(repair_lp_unicode(fname))
        inner_name = f"{doc_id}__{fname}"

        clash_key = inner_name.lower()
        n = 1
        while clash_key in filenames_used:
            stem = Path(fname).stem + f"-{n}"
            suf = Path(fname).suffix
            fname2 = sanitize_filename(stem + suf)
            inner_name = f"{doc_id}__{fname2}"
            clash_key = inner_name.lower()
            n += 1
        filenames_used.add(clash_key)

        blob_path = export_tmp / "files" / inner_name
        blob_path.parent.mkdir(parents=True, exist_ok=True)
        blob_path.write_bytes(data)

        rel_zip = f"files/{inner_name}"
        fmeta = {"fileName": fname, "documentId": doc_id, "decryptedSize": len(data)}
        if first_zip_relpath is None:
            first_zip_relpath = rel_zip
            first_file_meta = dict(fmeta)

        attach_fields.append(
            {
                "title": "",
                "id": uuid.uuid4().hex,
                "value": {"file": fmeta},
                "guarded": False,
                "multiline": False,
                "dontGenerate": False,
                "inputTraits": {"keyboard": "default", "correction": "no", "capitalization": "none"},
            }
        )

    if attach_fields:
        attach_section = {
            "title": "Attachments",
            "name": "Section_" + uuid.uuid4().hex,
            "fields": attach_fields,
        }
        # Prefer attachments early in ``sections`` (some importers stop after loginFields).
        parent_details.setdefault("sections", []).insert(0, attach_section)

        if first_file_meta and first_zip_relpath:
            parent_details["documentAttributes"] = dict(first_file_meta)
            records[-1]["file"] = {
                "attrs": {
                    "acl": [],
                    "downloads": [{"date": updated, "name": first_file_meta["fileName"]}],
                },
                "path": first_zip_relpath,
            }

    return records, filenames_used


def build_grouping_lookup(sync: str) -> dict[str, str]:
    """Map LP item id → export ``grouping`` column (preserves SharedFolder\\Foo paths)."""
    rows = _read_export_csv(sync)
    if len(rows) < 2:
        return {}
    header = rows[0]
    try:
        id_idx = header.index("id")
        g_idx = header.index("grouping")
    except ValueError:
        return {}
    lookup: dict[str, str] = {}
    for row in rows[1:]:
        if id_idx >= len(row) or g_idx >= len(row):
            continue
        ident = row[id_idx].strip()
        grp = row[g_idx].strip()
        if ident:
            lookup[ident] = grp
    return lookup


def assemble_1pux(
    out_path: Path,
    *,
    email: str,
    account_label: str,
    sync: str,
    include_reprompt: bool = False,
    folder_mode: str = "tags",
    progress_callback: Callable[[int, int], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> None:
    def _cancelled() -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise ExportCancelled()

    require_status()

    ids = parse_export_ids(sync)
    if not ids:
        raise SystemExit("No items exported from LastPass (empty CSV).")

    grouping_by_id = build_grouping_lookup(sync)

    vault_items: dict[str, list[dict[str, Any]]] = {"Imported": []}
    skipped: list[dict[str, str]] = []

    total_ids = len(ids)
    total_steps = total_ids + 1
    if progress_callback:
        progress_callback(0, total_steps)

    def record_skip(lp_id: str, acc: dict[str, Any] | None, reason: str) -> None:
        a = acc or {}
        share = a.get("share") or ""
        group = a.get("group") or grouping_by_id.get(lp_id, "")
        skipped.append(
            {
                "id": lp_id,
                "name": str(a.get("name") or ""),
                "fullname": str(a.get("fullname") or ""),
                "url": str(a.get("url") or ""),
                "username": str(a.get("username") or ""),
                "group": str(group),
                "share": str(share),
                "reason": reason,
            }
        )

    with tempfile.TemporaryDirectory(prefix="lp-1pux-") as tmp:
        tmpp = Path(tmp)
        tmpp.joinpath("files").mkdir(parents=True, exist_ok=True)

        for idx, lp_id in enumerate(ids):
            skip_progress_tick = False
            try:
                _cancelled()
                try:
                    acc = lp_show_json(lp_id, sync, include_reprompt=include_reprompt)
                except SkipReprompt as e:
                    sys.stderr.write(f"Skipping (reprompt) `{lp_id}`: {e.reason}\n")
                    record_skip(lp_id, None, e.reason)
                except Exception as e:
                    msg = str(e)
                    if looks_like_pwprotect_error(msg) or looks_unprompted_failure(msg):
                        record_skip(lp_id, None, "password reprompt (json fetch refused)")
                    else:
                        sys.stderr.write(f"Skipping id `{lp_id}`: {e}\n")
                        record_skip(lp_id, None, f"json fetch error: {msg.splitlines()[0] if msg else 'unknown'}")
                else:
                    grp = grouping_by_id.get(lp_id)
                    try:
                        recs, _ = lp_item_to_records(
                            acc,
                            grouping=grp,
                            sync=sync,
                            export_tmp=tmpp,
                            include_reprompt=include_reprompt,
                            folder_mode=folder_mode,
                        )
                        if folder_mode == "path-tag":
                            vault_name = "Imported"
                        elif folder_mode in ("vaults", "proton-accounts"):
                            vault_name = grouping_to_vault_name(grp)
                        else:
                            vault_name = "Imported"
                        vault_items.setdefault(vault_name, []).extend(recs)
                    except SkipReprompt as e:
                        sys.stderr.write(f"Skipping (reprompt) `{acc.get('name')}` ({lp_id}): {e.reason}\n")
                        record_skip(lp_id, acc, e.reason)
                    except Exception as e:
                        sys.stderr.write(f"Failed to convert `{lp_id}` ({acc.get('name')}): {e}\n")
                        record_skip(lp_id, acc, f"conversion error: {e}")
            except ExportCancelled:
                skip_progress_tick = True
                raise
            finally:
                if progress_callback and not skip_progress_tick:
                    progress_callback(idx + 1, total_steps)

        _cancelled()

        vault_names = sorted(vault_items.keys())
        if "Imported" in vault_names:
            vault_names.remove("Imported")
            vault_names.insert(0, "Imported")

        if folder_mode == "proton-accounts":
            accounts_list: list[dict[str, Any]] = []
            for vname in vault_names:
                acc_u = gen_account_uuid()
                v_uuid = gen_vault_uuid()
                suffix = "" if vname == "Imported" else f" — {vname}"
                accounts_list.append(
                    {
                        "attrs": {
                            "accountName": account_label + suffix,
                            "name": account_label + suffix,
                            "avatar": "",
                            "email": email,
                            "uuid": acc_u,
                            "domain": SYNTHETIC_DOMAIN,
                        },
                        "vaults": [
                            {
                                "attrs": {
                                    "uuid": v_uuid,
                                    "desc": "Imported from LastPass via lastpass-cli",
                                    "avatar": "",
                                    "name": vname,
                                    "type": "P",
                                },
                                "items": vault_items[vname],
                            }
                        ],
                    }
                )
            export_data = {"accounts": accounts_list}
            acc_uuid = accounts_list[0]["attrs"]["uuid"]
        else:
            acc_uuid = gen_account_uuid()
            vaults_payload = []
            for vname in vault_names:
                vaults_payload.append(
                    {
                        "attrs": {
                            "uuid": gen_vault_uuid(),
                            "desc": "Imported from LastPass via lastpass-cli",
                            "avatar": "",
                            "name": vname,
                            "type": "U" if vname != "Imported" else "P",
                        },
                        "items": vault_items[vname],
                    }
                )
            export_data = {
                "accounts": [
                    {
                        "attrs": {
                            "accountName": account_label,
                            "name": account_label,
                            "avatar": "",
                            "email": email,
                            "uuid": acc_uuid,
                            "domain": SYNTHETIC_DOMAIN,
                        },
                        "vaults": vaults_payload,
                    }
                ]
            }

        attrs = {"version": 3, "description": "1Password Unencrypted Export", "timestamp": int(time.time())}

        out_path.parent.mkdir(parents=True, exist_ok=True)
        _cancelled()
        archive_name = f"{acc_uuid}.1pux"
        inner_root = tmpp / archive_name
        inner_root.mkdir(parents=True, exist_ok=False)
        (inner_root / "export.attributes").write_text(
            json.dumps(attrs, separators=(",", ":"), ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (inner_root / "export.data").write_text(
            json.dumps(export_data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        tmp_zip_path = tmpp / f"{archive_name}.zip.tmp"
        with zipfile.ZipFile(tmp_zip_path, "w", compression=zipfile.ZIP_STORED) as zf:

            def add_tree(base: Path, arc_prefix: Path) -> None:
                for p in sorted(base.rglob("*")):
                    _cancelled()
                    rel = arc_prefix / p.relative_to(base)
                    if p.is_dir():
                        continue
                    zf.write(p, str(rel).replace("\\", "/"))

            # 1Password exports place `export.attributes` / `export.data` at ZIP root
            # (not nested under "<account uuid>.1pux/").
            add_tree(inner_root, Path("."))

            files_root = tmpp / "files"
            if files_root.exists():
                for f in sorted(files_root.rglob("*")):
                    _cancelled()
                    if f.is_file():
                        zf.write(f, f"files/{f.relative_to(files_root)}".replace("\\", "/"))

        if progress_callback:
            progress_callback(total_steps, total_steps)
        _cancelled()
        shutil.move(str(tmp_zip_path), str(out_path))

    # Write the skipped-items report next to the .1pux file (outside the
    # tempdir so it survives cleanup) — even when there are zero skips,
    # an empty report is created so the user knows the migration covered
    # everything.
    report_path = out_path.with_suffix(out_path.suffix + ".skipped.csv")
    with open(report_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["id", "name", "fullname", "group", "share", "url", "username", "reason"])
        for s in skipped:
            writer.writerow(
                [
                    s.get("id", ""),
                    s.get("name", ""),
                    s.get("fullname", ""),
                    s.get("group", ""),
                    s.get("share", ""),
                    s.get("url", ""),
                    s.get("username", ""),
                    s.get("reason", ""),
                ]
            )

    sys.stderr.write(
        "\nDone.\n"
        f"  1PUX archive : {out_path}\n"
        f"  Items written: {sum(len(v) for v in vault_items.values())}\n"
        f"  Vaults written: {len(vault_items)} (mode: {folder_mode})\n"
        f"  Items skipped: {len(skipped)} (see {report_path})\n"
    )
    if skipped:
        sys.stderr.write(
            "\nSkipped items above need to be exported manually from LastPass\n"
            "(typically because Password Reprompt is enabled). Re-run lpass\n"
            "interactively per-item, e.g.:\n"
            "  lpass show --json <id>\n"
            "and add them to 1Password by hand or via a one-off helper run.\n"
        )


def main() -> None:
    ap = argparse.ArgumentParser(description="Export LastPass via lpass to a 1PUX ZIP archive.")
    ap.add_argument(
        "-o",
        "--output",
        dest="output",
        required=True,
        type=Path,
        help="Output path (e.g. ~/lastpass-export.1pux).",
    )
    ap.add_argument(
        "--sync",
        default=os.environ.get("LPASS_SYNC", "auto"),
        help="Passed to ``lpass`` as ``--sync=`` value (default: auto).",
    )
    ap.add_argument("--email", default="imported@placeholder.local", help="Synthetic ``attrs.email`` in export.data.")
    ap.add_argument(
        "--account-name",
        dest="account_name",
        default="LastPass import",
        help="Synthetic ``attrs.accountName`` / ``attrs.name`` in export.data.",
    )
    ap.add_argument(
        "--include-reprompt",
        dest="include_reprompt",
        action="store_true",
        help=(
            "Process LastPass items that have Password Reprompt enabled. "
            "By default these are skipped and listed in <output>.skipped.csv "
            "because lpass may interactively re-prompt for the master password "
            "once per affected item."
        ),
    )
    ap.add_argument(
        "--folder-mode",
        dest="folder_mode",
        choices=("tags", "vaults", "path-tag", "proton-accounts"),
        default="tags",
        help=(
            "How to represent LastPass folders in 1PUX. "
            "`tags` — one vault \"Imported\"; folder path split across overview.tags (default). "
            "`vaults` — one 1PUX vault per folder path; each item also gets the full path as a single tag "
            "(helps when the importer ignores vault boundaries). "
            "`path-tag` — single vault; each item gets one tag with the full \"a/b/c\" path. "
            "`proton-accounts` — one synthetic export.data account per folder, each with a single vault "
            "(try this for Proton Pass if `vaults` still imports flat)."
        ),
    )

    ns = ap.parse_args()
    assemble_1pux(
        ns.output.expanduser(),
        email=ns.email,
        account_label=ns.account_name,
        sync=ns.sync,
        include_reprompt=ns.include_reprompt,
        folder_mode=ns.folder_mode,
    )


if __name__ == "__main__":
    main()
