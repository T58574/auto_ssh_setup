# auto-ssh-setup

SSH toolkit for Claude Code agents and humans. One command to set up SSH access, GitHub keys, and server hardening.

## Install

```bash
pip install paramiko
```

Or install as a CLI tool:

```bash
pip install .
auto-ssh-setup --help
```

## Quick start

```bash
# Full setup: SSH access + GitHub key in one command
python script.py setup-all --host 1.2.3.4 --user root --password "pass" \
    --git-name "Your Name" --git-email "you@example.com"
```

The script will:
1. Generate a local ed25519 SSH key (if missing)
2. Upload it to the server's `authorized_keys`
3. Generate an SSH key on the server for GitHub
4. Configure git on the server
5. Print the public key — add it to [GitHub SSH keys](https://github.com/settings/keys)

## Commands

### `setup-ssh` — Upload local SSH key to server

```bash
python script.py setup-ssh --host 1.2.3.4 --user root --password "pass"
```

After this, password is no longer needed for SSH.

### `setup-github` — Generate GitHub SSH key on server

```bash
python script.py setup-github --host 1.2.3.4 --user root \
    --git-name "Name" --git-email "email@example.com"
```

Generates an SSH key ON the server, configures git, verifies GitHub connectivity. Prints the public key for you to add to GitHub.

### `setup-all` — Full setup in one command

```bash
python script.py setup-all --host 1.2.3.4 --user root --password "pass" \
    --git-name "Name" --git-email "email@example.com"
```

### `harden` — Disable password authentication

```bash
python script.py harden --host 1.2.3.4 --user root
python script.py harden --host 1.2.3.4 --user root --dry-run  # preview changes
```

**WARNING:** This disables password login on the server. The script will refuse to proceed if key-based auth doesn't work yet. Always run `setup-ssh` first. A backup of `sshd_config` is created automatically.

## Flags

| Flag | Description | Default |
|------|------------|---------|
| `--host`, `-H` | Server IP or hostname | required |
| `--user`, `-u` | SSH username | required |
| `--port`, `-p` | SSH port | 22 |
| `--password` | SSH password (or use `SSH_PASSWORD` env var) | none |
| `--key-type` | `ed25519` or `rsa` | ed25519 |
| `--git-name` | git user.name (setup-github/all) | none |
| `--git-email` | git user.email (setup-github/all) | none |
| `--dry-run` | Preview changes without applying (harden) | false |
| `--version` | Show version | — |

## Password handling

To avoid exposing passwords in shell history / process lists:

```bash
# Option 1: env var (recommended)
export SSH_PASSWORD="mypass"
python script.py setup-ssh --host 1.2.3.4 --user root

# Option 2: CLI flag (visible in ps)
python script.py setup-ssh --host 1.2.3.4 --user root --password "mypass"
```

## Output format

Prefixed lines for easy parsing by AI agents:
- `[OK]` — success
- `[SKIP]` — already done (idempotent)
- `[ERROR]` — failure (exit code 1)
- `[INFO]` — progress
- `[WARN]` — non-fatal warning
- `[KEY]` — public key output

## Security

- All shell arguments are escaped with `shlex.quote()` to prevent command injection
- Keys are written via SFTP (not `echo >>`) to avoid shell interpretation
- GitHub host key fingerprint is verified against [official published fingerprint](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)
- `harden` creates a backup of `sshd_config` and verifies key auth works before disabling passwords
- Duplicate key detection prevents bloating `authorized_keys`

## Requirements

- Python 3.8+
- `ssh-keygen` in PATH (pre-installed on Linux/macOS, Windows 10+ with OpenSSH)
- `paramiko` (`pip install paramiko`)

## License

MIT
