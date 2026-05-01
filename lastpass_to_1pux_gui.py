#!/usr/bin/env python3
"""Simple GUI for exporting LastPass to 1PUX via ``lastpass_to_1pux.assemble_1pux``."""

from __future__ import annotations

import contextlib
import io
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from lastpass_cli_install_help import show_lpass_install_help  # noqa: E402
from lastpass_to_1pux import ExportCancelled, assemble_1pux  # noqa: E402

FOLDER_MODES: tuple[tuple[str, str], ...] = (
    ("Tags — one vault, folder path as tags", "tags"),
    ("Vaults — one 1PUX vault per folder", "vaults"),
    ("Path as one tag (flat importers)", "path-tag"),
    ("Proton: one synthetic account per folder", "proton-accounts"),
)

PROTECTED_MODES: tuple[tuple[str, str], ...] = (
    ("Skip protected items (default)", "skip"),
    ("Include protected + non-protected items", "include"),
    ("Only protected items", "only"),
)


def default_output_path() -> Path:
    home = Path.home()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return home / f"lastpass-export-{stamp}.1pux"


class ToolTip:
    """Small hover help (tkinter has no built-in tooltips)."""

    def __init__(self, widget: tk.Misc, text: str, delay_ms: int = 450) -> None:
        self.widget = widget
        self.text = text.strip()
        self.delay_ms = delay_ms
        self._win: tk.Toplevel | None = None
        self._after: str | None = None
        widget.bind("<Enter>", self._schedule, add=True)
        widget.bind("<Leave>", self._hide, add=True)
        widget.bind("<ButtonPress>", self._hide, add=True)

    def _schedule(self, _event: object | None = None) -> None:
        self._cancel_sched()
        self._after = self.widget.after(self.delay_ms, self._show)

    def _cancel_sched(self) -> None:
        if self._after is not None:
            self.widget.after_cancel(self._after)
            self._after = None

    def _show(self) -> None:
        self._after = None
        if not self.text or self._win is not None:
            return
        x = int(self.widget.winfo_rootx()) + 14
        y = int(self.widget.winfo_rooty()) + int(self.widget.winfo_height()) + 6
        self._win = tk.Toplevel(self.widget)
        self._win.wm_overrideredirect(True)
        try:
            self._win.wm_attributes("-topmost", True)
        except tk.TclError:
            pass
        self._win.wm_geometry(f"+{x}+{y}")
        bg = "#ffffe0"
        frame = tk.Frame(self._win, background=bg, borderwidth=1, relief=tk.SOLID)
        frame.pack()
        tk.Label(
            frame,
            text=self.text,
            background=bg,
            justify=tk.LEFT,
            wraplength=400,
            font=("TkDefaultFont", 9),
            padx=8,
            pady=6,
        ).pack()

    def _hide(self, _event: object | None = None) -> None:
        self._cancel_sched()
        if self._win is not None:
            self._win.destroy()
            self._win = None


def _tip(widget: tk.Misc, text: str) -> None:
    ToolTip(widget, text)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("LastPass → 1PUX")
        self.minsize(520, 420)
        self._busy = False
        self._cancel_event: threading.Event | None = None

        pad = {"padx": 8, "pady": 4}
        frm = ttk.Frame(self, padding=8)
        frm.pack(fill=tk.BOTH, expand=True)

        intro_row = ttk.Frame(frm)
        intro_row.grid(row=0, column=0, columnspan=3, sticky="ew", **pad)
        intro_row.columnconfigure(0, weight=1)
        intro_lbl = ttk.Label(
            intro_row,
            text="Requires `lpass` on PATH and an active login (`lpass login`). "
            "Output is an unencrypted 1PUX archive — store it safely.",
            wraplength=400,
        )
        intro_lbl.grid(row=0, column=0, sticky="w")
        install_cli_btn = ttk.Button(
            intro_row,
            text="Install `lpass` help…",
            command=lambda: show_lpass_install_help(self),
        )
        install_cli_btn.grid(row=0, column=1, sticky="e", padx=(12, 0))
        _tip(
            intro_lbl,
            "Prerequisites: install the LastPass CLI (lpass) and run `lpass login` so the vault "
            "is unlocked. This tool reads your vault through lpass and writes a 1Password "
            "Unencrypted Export (.1pux) ZIP. The file contains plaintext passwords, notes, and "
            "attachment bytes — treat it like a secret key: use a private path, avoid cloud sync "
            "folders, and delete it when the import is done.",
        )
        _tip(
            install_cli_btn,
            "Opens a window with links to the official GitHub repo, install commands, and "
            "GitHub issues if login fails with an SSL certificate error.",
        )

        sty = ttk.Style(self)
        try:
            sty.configure("Hint.TLabel", font=("TkDefaultFont", 9), foreground="#505050")
        except tk.TclError:
            pass
        hover_hint = ttk.Label(
            frm,
            text="(i)  Hover labels, fields, or buttons — a short explanation appears after a moment.",
            style="Hint.TLabel",
            wraplength=480,
        )
        hover_hint.grid(row=1, column=0, columnspan=3, sticky="w", padx=8, pady=(0, 4))
        try:
            hover_hint.configure(cursor="hand2")
        except tk.TclError:
            pass
        _tip(
            hover_hint,
            "Pause the pointer on almost any control to open a yellow help popup. "
            "This row is a reminder, not a setting.",
        )

        out_lbl = ttk.Label(frm, text="Output file (i)")
        out_lbl.grid(row=2, column=0, sticky="e", **pad)
        self.out_var = tk.StringVar(value=str(default_output_path()))
        out_entry = ttk.Entry(frm, textvariable=self.out_var, width=48)
        out_entry.grid(row=2, column=1, sticky="ew", **pad)
        browse_btn = ttk.Button(frm, text="Browse… (i)", command=self._browse_out)
        browse_btn.grid(row=2, column=2, **pad)
        out_help = (
            "Full path for the .1pux ZIP the importer will open. A companion CSV is also "
            "written next to it: same name with `.skipped.csv` listing items that were not "
            "exported (for example Password Reprompt entries when that option is off)."
        )
        _tip(out_lbl, out_help)
        _tip(out_entry, out_help)
        _tip(
            browse_btn,
            "Pick where to save the export. Default extension .1pux. Parent folders are "
            "created automatically if needed.",
        )

        email_lbl = ttk.Label(frm, text="Email (synthetic) (i)")
        email_lbl.grid(row=3, column=0, sticky="e", **pad)
        self.email_var = tk.StringVar(value="imported@placeholder.local")
        email_entry = ttk.Entry(frm, textvariable=self.email_var, width=48)
        email_entry.grid(row=3, column=1, columnspan=2, sticky="ew", **pad)
        email_help = (
            "Stored in the synthetic 1Password account record inside export.data "
            "(attrs.email). It does not need to match your LastPass email; importers may "
            "show it as the “account” label. Use your real address if you want consistency "
            "in the destination password manager."
        )
        _tip(email_lbl, email_help)
        _tip(email_entry, email_help)

        acct_lbl = ttk.Label(frm, text="Account name (i)")
        acct_lbl.grid(row=4, column=0, sticky="e", **pad)
        self.account_var = tk.StringVar(value="LastPass import")
        acct_entry = ttk.Entry(frm, textvariable=self.account_var, width=48)
        acct_entry.grid(row=4, column=1, columnspan=2, sticky="ew", **pad)
        acct_help = (
            "Human-readable name for the synthetic export account (attrs.accountName / "
            "attrs.name in export.data). Shown by some importers alongside the vault name."
        )
        _tip(acct_lbl, acct_help)
        _tip(acct_entry, acct_help)

        sync_lbl = ttk.Label(frm, text="Sync (i)")
        sync_lbl.grid(row=5, column=0, sticky="e", **pad)
        self.sync_var = tk.StringVar(value="auto")
        sync_entry = ttk.Entry(frm, textvariable=self.sync_var, width=48)
        sync_entry.grid(row=5, column=1, columnspan=2, sticky="ew", **pad)
        sync_help = (
            "Passed to every lpass invocation as `--sync=VALUE`. Typical values: `auto` "
            "(let lpass decide), `now` (force a sync before reading). Match what you use on "
            "the CLI if you need deterministic behavior; see `lpass help`."
        )
        _tip(sync_lbl, sync_help)
        _tip(sync_entry, sync_help)

        folder_lbl = ttk.Label(frm, text="Folder mode (i)")
        folder_lbl.grid(row=6, column=0, sticky="e", **pad)
        self.folder_combo = ttk.Combobox(
            frm,
            values=[label for label, _ in FOLDER_MODES],
            state="readonly",
            width=44,
        )
        self.folder_combo.grid(row=6, column=1, columnspan=2, sticky="ew", **pad)
        self.folder_combo.current(0)
        folder_help = (
            "Maps LastPass folder paths into 1PUX:\n"
            "• Tags — one vault “Imported”; path segments become item tags.\n"
            "• Vaults — one 1PUX vault per folder path; full path also added as one tag "
            "(helps when the importer ignores vault boundaries).\n"
            "• Path as one tag — single vault; one tag holding the full folder path string "
            "for very flat importers.\n"
            "• Proton accounts — one synthetic export.data account per folder, each with "
            "its own vault (often best for Proton Pass if vaults mode still imports flat)."
        )
        _tip(folder_lbl, folder_help)
        _tip(self.folder_combo, folder_help)

        protected_lbl = ttk.Label(frm, text="Protected items (i)")
        protected_lbl.grid(row=7, column=0, sticky="e", **pad)
        self.protected_combo = ttk.Combobox(
            frm,
            values=[label for label, _ in PROTECTED_MODES],
            state="readonly",
            width=44,
        )
        self.protected_combo.grid(row=7, column=1, columnspan=2, sticky="ew", **pad)
        self.protected_combo.current(0)
        protected_help = (
            "How to handle LastPass Password Reprompt entries:\n"
            "• Skip protected items (default) — fastest, writes skipped list to .skipped.csv.\n"
            "• Include protected + non-protected — may prompt for master password per protected item.\n"
            "• Only protected items — exports just reprompt-protected entries (useful for follow-up runs)."
        )
        _tip(protected_lbl, protected_help)
        _tip(self.protected_combo, protected_help)

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=8, column=0, columnspan=3, **pad)
        self.export_btn = ttk.Button(btn_row, text="Export to 1PUX (i)", command=self._start_export)
        self.export_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.cancel_btn = ttk.Button(btn_row, text="Cancel", command=self._cancel_export, state="disabled")
        self.cancel_btn.pack(side=tk.LEFT, padx=(0, 8))
        clear_btn = ttk.Button(btn_row, text="Clear log (i)", command=self._clear_log)
        clear_btn.pack(side=tk.LEFT)
        _tip(
            self.export_btn,
            "Start the export. Work runs in the background so the window stays responsive; "
            "messages from the exporter appear in the log. You need a working lpass session "
            "(LPASS_AGENT_TIMEOUT=0 in the environment can help long runs).",
        )
        _tip(
            self.cancel_btn,
            "Request stop. The worker checks between vault items and while building the ZIP; "
            "a slow `lpass` call for one item cannot be interrupted until it returns. "
            "Cancelled runs do not produce a complete .1pux file.",
        )
        _tip(clear_btn, "Erase the log text only; it does not undo a finished export.")

        prog_fr = ttk.Frame(frm)
        prog_fr.grid(row=9, column=0, columnspan=3, sticky="ew", **pad)
        self.progress_bar = ttk.Progressbar(prog_fr, mode="determinate", maximum=1, value=0)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.progress_label_var = tk.StringVar(value="")
        prog_lbl = ttk.Label(prog_fr, textvariable=self.progress_label_var, width=14)
        prog_lbl.pack(side=tk.RIGHT)
        _tip(
            self.progress_bar,
            "Progress while reading vault items (and one final step while writing the ZIP). "
            "The bar may stay still while `lpass` is slow on a single entry.",
        )
        _tip(prog_lbl, "Completed steps versus total (items plus final packaging).")

        log_frame = ttk.LabelFrame(frm, text="Log  (i)", padding=4)
        log_frame.grid(row=10, column=0, columnspan=3, sticky="nsew", **pad)
        frm.rowconfigure(10, weight=1)
        frm.columnconfigure(1, weight=1)

        self.log = tk.Text(log_frame, height=14, wrap="word", state="disabled", font=("TkFixedFont", 10))
        scroll = ttk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.status_var = tk.StringVar(value="Ready.")
        status_lbl = ttk.Label(frm, textvariable=self.status_var)
        status_lbl.grid(row=11, column=0, columnspan=3, sticky="w", **pad)
        _tip(
            self.log,
            "Standard error from the export process (progress, item counts, paths). "
            "If something fails, the last lines here usually contain the cause.",
        )
        _tip(log_frame, "Scroll to read full exporter output; copy/paste is supported from the log.")
        _tip(
            status_lbl,
            "One-line status: Ready, Exporting…, Finished with path, or Failed. Hover other "
            "fields for detailed help.",
        )

    def _browse_out(self) -> None:
        p = filedialog.asksaveasfilename(
            title="Save 1PUX export",
            defaultextension=".1pux",
            filetypes=[("1Password export", "*.1pux"), ("All files", "*")],
            initialfile=Path(self.out_var.get()).name,
        )
        if p:
            self.out_var.set(p)

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", tk.END)
        self.log.configure(state="disabled")

    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert(tk.END, text)
        self.log.see(tk.END)
        self.log.configure(state="disabled")

    def _folder_mode_value(self) -> str:
        idx = self.folder_combo.current()
        if idx < 0:
            return "tags"
        return FOLDER_MODES[idx][1]

    def _protected_mode_value(self) -> str:
        idx = self.protected_combo.current()
        if idx < 0:
            return "skip"
        return PROTECTED_MODES[idx][1]

    def _apply_progress(self, done: int, total: int) -> None:
        if total <= 0:
            total = 1
        self.progress_bar.configure(maximum=total, value=min(max(done, 0), total))
        self.progress_label_var.set(f"{min(max(done, 0), total)} / {total}")

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.export_btn.configure(state="disabled" if busy else "normal")
        self.cancel_btn.configure(state="normal" if busy else "disabled")

    def _cancel_export(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
            self.status_var.set("Cancelling…")

    def _start_export(self) -> None:
        if self._busy:
            return
        out = Path(self.out_var.get().strip()).expanduser()
        if not str(out):
            messagebox.showerror("Export", "Choose an output file path.")
            return
        out.parent.mkdir(parents=True, exist_ok=True)

        email = self.email_var.get().strip() or "imported@placeholder.local"
        account = self.account_var.get().strip() or "LastPass import"
        sync = self.sync_var.get().strip() or "auto"
        folder_mode = self._folder_mode_value()
        protected_mode = self._protected_mode_value()

        self._cancel_event = threading.Event()
        self._apply_progress(0, 1)
        self._set_busy(True)
        self.status_var.set("Exporting…")
        self._append_log("\n--- export started ---\n")

        def report_progress(done: int, total: int) -> None:
            self.after(0, lambda d=done, t=total: self._apply_progress(d, t))

        def work() -> None:
            buf = io.StringIO()
            err: str | None = None
            cancelled = False
            try:
                with contextlib.redirect_stderr(buf):
                    assemble_1pux(
                        out,
                        email=email,
                        account_label=account,
                        sync=sync,
                        protected_mode=protected_mode,
                        folder_mode=folder_mode,
                        progress_callback=report_progress,
                        cancel_event=self._cancel_event,
                    )
            except ExportCancelled:
                cancelled = True
            except SystemExit as e:
                err = str(e) if e.args else "Aborted."
            except BaseException as e:
                err = f"{type(e).__name__}: {e}"

            captured = buf.getvalue()
            self.after(0, lambda: self._export_done(err, captured, out, cancelled))

        threading.Thread(target=work, daemon=True).start()

    def _export_done(
        self,
        err: str | None,
        log_text: str,
        out: Path,
        cancelled: bool = False,
    ) -> None:
        self._append_log(log_text)
        self._set_busy(False)
        self._cancel_event = None
        self.progress_bar.configure(maximum=1, value=0)
        self.progress_label_var.set("")
        if cancelled:
            self.status_var.set("Cancelled.")
            self._append_log("\nExport cancelled by user.\n")
            messagebox.showinfo("Export", "Export was cancelled. No complete .1pux file was written.")
            return
        if err:
            self.status_var.set("Failed.")
            self._append_log(f"\nError: {err}\n")
            messagebox.showerror("Export failed", err)
        else:
            self.status_var.set(f"Finished: {out}")
            skipped = out.with_suffix(out.suffix + ".skipped.csv")
            self._append_log(f"\nSkipped report (if any): {skipped}\n")
            messagebox.showinfo("Export", f"Wrote:\n{out}")


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
