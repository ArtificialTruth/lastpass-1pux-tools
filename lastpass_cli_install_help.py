#!/usr/bin/env python3
"""LastPass CLI (`lpass`) install notes and upstream links for the GUI."""

from __future__ import annotations

import webbrowser
import tkinter as tk
from tkinter import ttk

# Upstream
LASTPASS_CLI_REPO_TREE = "https://github.com/lastpass/lastpass-cli/tree/master"
LASTPASS_CLI_README = "https://github.com/lastpass/lastpass-cli/blob/master/README.md"

# Certificate / pin issues (distro packages often lag; error text matches many reports)
ISSUE_SSL_PEER_NOT_OK_653 = "https://github.com/lastpass/lastpass-cli/issues/653"
ISSUE_SSL_PEER_NOT_OK_540 = "https://github.com/lastpass/lastpass-cli/issues/540"

SSL_ERROR_LINE = "Error: SSL peer certificate or SSH remote key was not OK."


def _open(url: str) -> None:
    webbrowser.open(url)


def show_lpass_install_help(parent: tk.Misc) -> None:
    win = tk.Toplevel(parent)
    win.title("Install LastPass CLI (lpass)")
    win.minsize(520, 460)
    win.transient(parent.winfo_toplevel())

    body = ttk.Frame(win, padding=8)
    body.pack(fill=tk.BOTH, expand=True)

    ttk.Label(
        body,
        text="Official project (source, README, build steps):",
        font=("TkDefaultFont", 10, "bold"),
    ).pack(anchor="w")

    link_fr = ttk.Frame(body)
    link_fr.pack(fill=tk.X, pady=(4, 12))
    for label, url in (
        ("GitHub — lastpass-cli (master)", LASTPASS_CLI_REPO_TREE),
        ("README (install & build)", LASTPASS_CLI_README),
    ):
        b = ttk.Button(link_fr, text=label, command=lambda u=url: _open(u))
        b.pack(anchor="w", pady=2)

    ttk.Label(
        body,
        text="Quick package installs (see README for your OS):",
        font=("TkDefaultFont", 10, "bold"),
    ).pack(anchor="w", pady=(8, 0))

    blurb = tk.Text(body, height=12, wrap=tk.WORD, font=("TkFixedFont", 9))
    blurb.pack(fill=tk.BOTH, expand=True, pady=4)
    lines = f"""Ubuntu / Debian (package may be older than upstream):

  sudo apt update && sudo apt install lastpass-cli

Fedora:

  sudo dnf install lastpass-cli

macOS (Homebrew):

  brew install lastpass-cli

Build from source (when packages break or lag on SSL pins):

  git clone https://github.com/lastpass/lastpass-cli.git
  cd lastpass-cli
  # Install build deps — full list is in the README link above (cmake, openssl, libcurl, libxml2, …)
  make
  sudo make install

After install, log in:

  lpass login your@email.com
"""
    blurb.insert("1.0", lines)
    blurb.configure(state="disabled")

    ttk.Label(
        body,
        text="If `lpass login` fails with an SSL / certificate error:",
        font=("TkDefaultFont", 10, "bold"),
    ).pack(anchor="w", pady=(12, 0))

    ttk.Label(
        body,
        text=f"  {SSL_ERROR_LINE}",
        font=("TkDefaultFont", 9),
        foreground="#333333",
    ).pack(anchor="w", pady=(2, 4))

    ttk.Label(
        body,
        text=(
            "Distro builds sometimes ship outdated public-key pins (pins.h). "
            "Upstream and GitHub issues discuss fixes: newer releases, or build from current master."
        ),
        wraplength=500,
        justify="left",
    ).pack(anchor="w")

    iss_fr = ttk.Frame(body)
    iss_fr.pack(fill=tk.X, pady=(8, 4))
    ttk.Button(
        iss_fr,
        text="GitHub issue #653 (SSL peer certificate …)",
        command=lambda: _open(ISSUE_SSL_PEER_NOT_OK_653),
    ).pack(anchor="w", pady=2)
    ttk.Button(
        iss_fr,
        text="GitHub issue #540 (same error, earlier thread)",
        command=lambda: _open(ISSUE_SSL_PEER_NOT_OK_540),
    ).pack(anchor="w", pady=2)

    ttk.Button(win, text="Close", command=win.destroy).pack(pady=8)
