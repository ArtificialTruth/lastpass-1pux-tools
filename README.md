# LastPass 1PUX Tools 
*Migrate to ProtonPass - with attachments uploaded!*  
Standalone scripts for exporting LastPass data (via `lpass`) to 1Password's `.1pux` format, including attachment handling and a small GUI wrapper.

## Processing and Privacy

- The exporter uses the official LastPass CLI binary (`lpass`) as its data source.
- Vault reads are performed by `lpass` on your machine; this project does not call LastPass APIs directly.
- The scripts run locally and do not upload data by themselves.
- Output `.1pux` archives and `.skipped.csv` reports are written to local disk.
- `.1pux` is unencrypted by design; treat it as sensitive data and delete it after import if no longer needed.

## Files

- `lastpass_to_1pux.py` - CLI exporter
- `lastpass_to_1pux_gui.py` - tkinter GUI wrapper for the exporter
- `lastpass_cli_install_help.py` - install/help dialog content used by the GUI
- `patch.py` - optional binary patch helper for known broken distro `lpass` builds

## Requirements

- Python 3.10+
- LastPass CLI (`lpass`) installed and available on PATH
- Active login for `lpass` (`lpass login your@email.com`)

Python dependencies are stdlib-only (see `requirements.txt`).

## Install LastPass CLI

Official upstream repo:

- https://github.com/lastpass/lastpass-cli/tree/master

Upstream README (install/build instructions):

- https://github.com/lastpass/lastpass-cli/blob/master/README.md

Common installs:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install lastpass-cli

# Fedora
sudo dnf install lastpass-cli

# macOS (Homebrew)
brew install lastpass-cli
```

If distro packages lag, build from source per upstream README.

## SSL login error note

If login fails with:

`Error: SSL peer certificate or SSH remote key was not OK.`

See upstream issue threads:

- https://github.com/lastpass/lastpass-cli/issues/653
- https://github.com/lastpass/lastpass-cli/issues/540

## Usage

```bash
python3 lastpass_to_1pux.py -o ~/lastpass-export.1pux
```

GUI:

```bash
python3 lastpass_to_1pux_gui.py
```

Optional patch helper (only for exact supported `lpass` binary hash):

```bash
python3 patch.py "$(which lpass)"
```
