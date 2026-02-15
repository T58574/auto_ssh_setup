"""
auto_ssh_setup — SSH toolkit for Claude Code agents and humans.

Subcommands:
  setup-ssh     Upload local SSH key to remote server
  setup-github  Generate SSH key on server for GitHub, configure git
  setup-all     Both of the above in sequence
  harden        Disable password auth on server
"""

__version__ = "1.0.0"

import argparse
import os
import shlex
import subprocess
import sys
from typing import Tuple, Optional

import paramiko


# GitHub's official ed25519 host key fingerprint (SHA256)
# https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
GITHUB_ED25519_FINGERPRINT = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"


# ============================================================
# Exceptions
# ============================================================

class RemoteExecutionError(Exception):
    """Raised when a remote command fails."""
    def __init__(self, command: str, exit_code: int, stderr: str):
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr
        super().__init__(f"Command '{command}' failed (exit {exit_code}): {stderr}")


# ============================================================
# Utilities
# ============================================================

def run_remote(
    ssh: paramiko.SSHClient,
    command: str,
    check: bool = True
) -> Tuple[str, str, int]:
    """Execute command on remote server, capture output.
    Returns (stdout, stderr, exit_code).
    Raises RemoteExecutionError if check=True and exit_code != 0.
    """
    _, stdout, stderr = ssh.exec_command(command)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if check and exit_code != 0:
        raise RemoteExecutionError(command, exit_code, err)
    return out, err, exit_code


def shell_quote(value: str) -> str:
    """Quote a string for safe use in remote shell commands."""
    return shlex.quote(value)


def create_ssh_connection(
    host: str,
    user: str,
    password: Optional[str] = None,
    port: int = 22
) -> paramiko.SSHClient:
    """Create SSH connection. Uses password if provided, otherwise key-based auth.
    Loads system host keys and auto-adds new ones (logged with fingerprint).
    """
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": user,
    }
    if password:
        connect_kwargs["password"] = password
    else:
        connect_kwargs["look_for_keys"] = True

    print(f"[INFO] Connecting to {user}@{host}:{port}...")
    ssh.connect(**connect_kwargs)

    # Log host key fingerprint for transparency
    transport = ssh.get_transport()
    if transport:
        remote_key = transport.get_remote_server_key()
        fingerprint = remote_key.get_fingerprint().hex()
        print(f"[INFO] Host key fingerprint: {remote_key.get_name()} {fingerprint}")

    print(f"[OK] Connected to {user}@{host}")
    return ssh


def resolve_password(args) -> Optional[str]:
    """Resolve password from --password flag or SSH_PASSWORD env var."""
    if args.password:
        return args.password
    return os.environ.get("SSH_PASSWORD")


# ============================================================
# Feature 1: Setup SSH access
# ============================================================

def ensure_local_ssh_key(key_type: str = "ed25519") -> str:
    """Ensure local SSH key exists. Generate if missing.
    Returns path to public key file.
    """
    key_dir = os.path.expanduser("~/.ssh")
    private_key = os.path.join(key_dir, f"id_{key_type}")
    public_key = f"{private_key}.pub"

    if os.path.exists(private_key) and os.path.exists(public_key):
        print(f"[SKIP] Local SSH key already exists: {public_key}")
        return public_key

    print(f"[INFO] Generating local {key_type} SSH key...")
    os.makedirs(key_dir, exist_ok=True)

    cmd = ["ssh-keygen", "-t", key_type, "-f", private_key, "-N", ""]
    if key_type == "rsa":
        cmd.extend(["-b", "4096"])

    subprocess.run(cmd, check=True, capture_output=True)
    print(f"[OK] Local SSH key generated: {public_key}")
    return public_key


def upload_key_to_server(ssh: paramiko.SSHClient, public_key_path: str) -> bool:
    """Upload local public key to server's authorized_keys.
    Uses SFTP to avoid command injection. Checks for duplicates line-by-line.
    Returns True if key was added, False if already existed.
    """
    public_key_path = os.path.expanduser(public_key_path)
    with open(public_key_path, "r") as f:
        pub_key = f.read().strip()

    # Extract the base64 body for comparison (ignore comment)
    key_parts = pub_key.split()
    key_body = key_parts[1] if len(key_parts) >= 2 else pub_key

    # Check if key already exists (line-by-line to avoid substring false positives)
    existing, _, _ = run_remote(ssh, "cat ~/.ssh/authorized_keys 2>/dev/null || true", check=False)
    for line in existing.splitlines():
        line_parts = line.strip().split()
        if len(line_parts) >= 2 and line_parts[1] == key_body:
            print("[SKIP] Key already in authorized_keys")
            return False

    # Ensure .ssh directory exists with correct permissions
    run_remote(ssh, "mkdir -p ~/.ssh && chmod 700 ~/.ssh")

    # Append key via SFTP (no shell injection possible)
    sftp = ssh.open_sftp()
    try:
        home, _, _ = run_remote(ssh, "echo $HOME")
        ak_path = f"{home}/.ssh/authorized_keys"

        try:
            with sftp.open(ak_path, "r") as f:
                content = f.read().decode()
        except (FileNotFoundError, IOError):
            content = ""

        if not content.endswith("\n") and content:
            content += "\n"
        content += pub_key + "\n"

        with sftp.open(ak_path, "w") as f:
            f.write(content.encode())
    finally:
        sftp.close()

    run_remote(ssh, "chmod 600 ~/.ssh/authorized_keys")
    print("[OK] Public key added to authorized_keys")
    return True


# ============================================================
# Feature 2: Setup GitHub SSH key on server
# ============================================================

def generate_remote_ssh_key(
    ssh: paramiko.SSHClient,
    key_type: str = "ed25519",
    comment: str = ""
) -> str:
    """Generate SSH key ON the remote server for GitHub.
    Returns public key content.
    """
    home, _, _ = run_remote(ssh, "echo $HOME")
    private_key = f"{home}/.ssh/id_{key_type}"
    public_key = f"{private_key}.pub"

    # Check if key already exists
    _, _, exit_code = run_remote(ssh, f"test -f {shell_quote(private_key)}", check=False)
    if exit_code == 0:
        print("[SKIP] SSH key already exists on server")
        out, _, _ = run_remote(ssh, f"cat {shell_quote(public_key)}")
        return out

    print(f"[INFO] Generating {key_type} SSH key on server...")
    keygen_cmd = f"ssh-keygen -t {shell_quote(key_type)} -f {shell_quote(private_key)} -N ''"
    if comment:
        keygen_cmd += f" -C {shell_quote(comment)}"
    run_remote(ssh, keygen_cmd)

    out, _, _ = run_remote(ssh, f"cat {shell_quote(public_key)}")
    print("[OK] SSH key generated on server")
    return out


def configure_git_on_server(
    ssh: paramiko.SSHClient,
    name: str,
    email: str
) -> None:
    """Set git user.name and user.email on remote server."""
    run_remote(ssh, f"git config --global user.name {shell_quote(name)}")
    run_remote(ssh, f"git config --global user.email {shell_quote(email)}")
    print(f"[OK] Git configured: {name} <{email}>")


def setup_github_known_hosts(ssh: paramiko.SSHClient) -> None:
    """Add GitHub's SSH host key to known_hosts with fingerprint verification."""
    # Scan GitHub's key
    scanned, _, _ = run_remote(
        ssh,
        "ssh-keyscan -t ed25519 github.com 2>/dev/null",
        check=False
    )
    if not scanned:
        print("[WARN] Could not fetch GitHub host key via ssh-keyscan")
        return

    # Verify fingerprint matches GitHub's published fingerprint
    run_remote(ssh, "mkdir -p ~/.ssh")

    # Write scanned key to a temp file and verify its fingerprint
    run_remote(ssh, f"echo {shell_quote(scanned)} > /tmp/_gh_hostkey_check")
    fp_out, _, _ = run_remote(ssh, "ssh-keygen -lf /tmp/_gh_hostkey_check 2>/dev/null", check=False)
    run_remote(ssh, "rm -f /tmp/_gh_hostkey_check", check=False)

    if GITHUB_ED25519_FINGERPRINT in fp_out:
        run_remote(ssh, f"echo {shell_quote(scanned)} >> ~/.ssh/known_hosts")
        print("[OK] GitHub host key verified and added to known_hosts")
    else:
        print(f"[WARN] GitHub host key fingerprint mismatch! Expected {GITHUB_ED25519_FINGERPRINT}, got: {fp_out}")
        print("[WARN] Skipping known_hosts update — verify your network connection")


def test_github_ssh(ssh: paramiko.SSHClient) -> bool:
    """Test GitHub SSH connectivity from server.
    GitHub returns exit code 1 but prints 'successfully authenticated'.
    """
    print("[INFO] Testing GitHub SSH connection...")
    out, err, _ = run_remote(ssh, "ssh -T git@github.com 2>&1", check=False)
    combined = out + err
    if "successfully authenticated" in combined.lower():
        print("[OK] GitHub SSH connection works")
        return True
    else:
        print(f"[ERROR] GitHub SSH test failed: {combined}")
        return False


# ============================================================
# Feature 3: Harden SSH
# ============================================================

def verify_key_auth_works(host: str, user: str, port: int) -> bool:
    """Verify that key-based SSH auth works before hardening."""
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, port=port, username=user, look_for_keys=True)
        ssh.close()
        return True
    except Exception:
        return False


def harden_ssh_config(ssh: paramiko.SSHClient, dry_run: bool = False) -> None:
    """Disable password authentication and restrict root login.
    Creates a backup of sshd_config before modifying.
    """
    sshd_config = "/etc/ssh/sshd_config"

    if dry_run:
        print("[DRY-RUN] Would modify {sshd_config}:")
        print("[DRY-RUN]   PasswordAuthentication no")
        print("[DRY-RUN]   PermitRootLogin prohibit-password")
        print("[DRY-RUN]   Restart sshd")
        return

    # Backup before modifying
    run_remote(ssh, f"sudo cp {sshd_config} {sshd_config}.bak.$(date +%Y%m%d%H%M%S)")
    print(f"[OK] Backup created: {sshd_config}.bak.*")

    commands = [
        f"sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' {sshd_config}",
        f"sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' {sshd_config}",
        "sudo systemctl restart sshd || sudo service ssh restart",
    ]

    for cmd in commands:
        run_remote(ssh, cmd)

    print("[OK] SSH hardened: password auth disabled, root login restricted")


# ============================================================
# CLI Handlers
# ============================================================

def cmd_setup_ssh(args) -> None:
    password = resolve_password(args)
    pub_key_path = ensure_local_ssh_key(key_type=args.key_type)
    ssh = create_ssh_connection(args.host, args.user, password, args.port)
    try:
        upload_key_to_server(ssh, pub_key_path)
        print(f"\n[OK] SSH setup complete. Connect with: ssh {args.user}@{args.host}")
    finally:
        ssh.close()


def cmd_setup_github(args) -> None:
    password = resolve_password(args)
    ssh = create_ssh_connection(args.host, args.user, password, args.port)
    try:
        comment = f"{args.user}@{args.host}"
        pub_key = generate_remote_ssh_key(ssh, key_type=args.key_type, comment=comment)

        if args.git_name and args.git_email:
            configure_git_on_server(ssh, args.git_name, args.git_email)

        setup_github_known_hosts(ssh)
        test_github_ssh(ssh)

        print(f"\n[KEY] Add this public key to GitHub (Settings > SSH keys):")
        print(pub_key)
    finally:
        ssh.close()


def cmd_setup_all(args) -> None:
    password = resolve_password(args)

    # Step 1: Setup SSH access
    pub_key_path = ensure_local_ssh_key(key_type=args.key_type)
    ssh = create_ssh_connection(args.host, args.user, password, args.port)
    try:
        upload_key_to_server(ssh, pub_key_path)
    finally:
        ssh.close()

    # Step 2: Reconnect (try key auth first, fallback to password)
    ssh = create_ssh_connection(args.host, args.user, password=password, port=args.port)
    try:
        comment = f"{args.user}@{args.host}"
        pub_key = generate_remote_ssh_key(ssh, key_type=args.key_type, comment=comment)

        if args.git_name and args.git_email:
            configure_git_on_server(ssh, args.git_name, args.git_email)

        setup_github_known_hosts(ssh)
        test_github_ssh(ssh)

        print(f"\n[OK] Full setup complete for {args.user}@{args.host}")
        print(f"[KEY] Add this public key to GitHub (Settings > SSH keys):")
        print(pub_key)
    finally:
        ssh.close()


def cmd_harden(args) -> None:
    password = resolve_password(args)

    # Safety check: verify key-based auth works before disabling passwords
    if not args.dry_run:
        print("[INFO] Verifying key-based auth works before hardening...")
        if not verify_key_auth_works(args.host, args.user, args.port):
            print("[ERROR] Key-based auth failed! Run 'setup-ssh' first.")
            print("[ERROR] Refusing to disable password auth — you would be locked out.")
            sys.exit(1)
        print("[OK] Key-based auth verified")

    ssh = create_ssh_connection(args.host, args.user, password, args.port)
    try:
        harden_ssh_config(ssh, dry_run=args.dry_run)
        if not args.dry_run:
            print(f"\n[OK] Server hardened. Password auth is now disabled.")
    finally:
        ssh.close()


# ============================================================
# CLI Parser
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SSH toolkit for Claude Code agents and humans."
    )
    parser.add_argument("--version", action="version", version=f"auto_ssh_setup {__version__}")

    # Common arguments
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", "-H", required=True, help="Server IP or hostname")
    common.add_argument("--user", "-u", required=True, help="SSH username")
    common.add_argument("--port", "-p", type=int, default=22, help="SSH port (default: 22)")
    common.add_argument("--password", default=None, help="SSH password (or set SSH_PASSWORD env var)")
    common.add_argument("--key-type", default="ed25519", choices=["ed25519", "rsa"], help="Key type (default: ed25519)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # setup-ssh
    sub_ssh = subparsers.add_parser("setup-ssh", parents=[common],
        help="Upload local SSH key to server")
    sub_ssh.set_defaults(func=cmd_setup_ssh)

    # setup-github
    sub_github = subparsers.add_parser("setup-github", parents=[common],
        help="Generate GitHub SSH key on server")
    sub_github.add_argument("--git-name", default=None, help="git config user.name")
    sub_github.add_argument("--git-email", default=None, help="git config user.email")
    sub_github.set_defaults(func=cmd_setup_github)

    # setup-all
    sub_all = subparsers.add_parser("setup-all", parents=[common],
        help="Setup SSH access + GitHub key in one go")
    sub_all.add_argument("--git-name", default=None, help="git config user.name")
    sub_all.add_argument("--git-email", default=None, help="git config user.email")
    sub_all.set_defaults(func=cmd_setup_all)

    # harden
    sub_harden = subparsers.add_parser("harden", parents=[common],
        help="Disable password auth on server")
    sub_harden.add_argument("--dry-run", action="store_true", help="Show what would change without modifying")
    sub_harden.set_defaults(func=cmd_harden)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except paramiko.AuthenticationException:
        print("[ERROR] Authentication failed. Check username/password.")
        sys.exit(1)
    except paramiko.SSHException as e:
        print(f"[ERROR] SSH error: {e}")
        sys.exit(1)
    except RemoteExecutionError as e:
        print(f"[ERROR] Remote command failed: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"[ERROR] File not found: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Cancelled.")
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
