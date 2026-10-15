# Fystack Cosigner CLI

A **cosigner** is the part of a [Fystack](https://fystack.io) MPC wallet that runs on your own infrastructure.
It holds your key shares, so Fystack can't sign a transaction without it. Before it signs, it sends the
transaction to your approval callback, and your own policy decides whether it goes through.

`cosigner-cli` installs and runs the cosigner on your host with Docker. It handles:

- **Setup:** pairs the cosigner with Fystack and starts it
- **Verified releases:** checks the signature of every runtime image before running it
- **Day-to-day:** start, stop, status, logs and health checks
- **Recovery:** encrypted backups, restore, and `.mshare` export for Fystack Recovery
- **Updates:** installs new releases after taking a recovery checkpoint

Each instance is one cosigner container with its own identity and an encrypted SQLite database.

- **Platforms:** Linux (production), macOS with Docker Desktop (development), Windows through WSL 2 (development). amd64 and arm64.
- **Nitro enclave deployments** are not covered here. See the runtime repository.

## Prerequisites

You need two tools on the host:

- **Docker** with Compose v2, which runs the cosigner container
- **[Cosign](https://docs.sigstore.dev/cosign/system_config/installation/)**, which verifies the signature of the CLI and every runtime image. The [installer](#install) adds it for you if it's missing.

### Linux

1. Install Docker Engine and the Compose plugin by following the [official guide for your distro](https://docs.docker.com/engine/install/).
2. Install Cosign:

   ```bash
   # Debian, Ubuntu, RHEL, Fedora and most other distros
   ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
   curl -fsSLO "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-$ARCH"
   sudo install -m 0755 "cosign-linux-$ARCH" /usr/local/bin/cosign && rm "cosign-linux-$ARCH"

   # Alpine
   sudo apk add cosign

   # Arch
   sudo pacman -S cosign
   ```

### macOS

1. Install [Docker Desktop](https://docs.docker.com/desktop/setup/install/mac-install/) and start it. Compose v2 is included.
2. Install Cosign with [Homebrew](https://brew.sh):

   ```bash
   brew install cosign
   ```

### Windows

There is no native Windows build. Run everything inside WSL 2:

1. In PowerShell as Administrator, install WSL with Ubuntu, then restart:

   ```powershell
   wsl --install -d Ubuntu
   ```

2. Install [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/). In **Settings → Resources → WSL integration**, turn on integration for Ubuntu.
3. Open the Ubuntu terminal and follow the [Linux](#linux) Cosign steps. Run all `cosigner-cli` commands from that terminal.

### Check your setup

```bash
docker version
docker compose version
cosign version
```

All three should print a version. If `docker` fails with a permission error on Linux, add yourself to the `docker` group (`sudo usermod -aG docker $USER`) and log in again.

## Install

This host will hold a share of your wallet keys, so verify the installer before you run it. Each
release's `install.sh` is built from [`scripts/install.sh.tmpl`](scripts/install.sh.tmpl) and signed by
this repository's release workflow. Download it, check the signature with cosign, then run it:

```bash
V=v1.2.3
curl -fsSLO "https://github.com/fystack/cosigner-cli/releases/download/$V/install.sh"
curl -fsSLO "https://github.com/fystack/cosigner-cli/releases/download/$V/install.sh.sigstore.json"
cosign verify-blob install.sh --bundle install.sh.sigstore.json \
  --certificate-identity "https://github.com/fystack/cosigner-cli/.github/workflows/release.yml@refs/tags/$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sh install.sh
```

Run `sh install.sh` only if `cosign verify-blob` prints `Verified OK`. The installer then checks
`cosigner-cli` against the SHA-256 pinned in the script and its Sigstore signature before it installs it
to `/usr/local/bin`. It also checks Docker and tells you what to fix. To set the install directory, run
`sh install.sh --dir /opt/cosigner-cli/bin`.

[cosigner.fystack.io](https://cosigner.fystack.io) lists every release with its checksums.

**Quick install (not for production hosts).** The command below runs the script that
cosigner.fystack.io serves, before anything is verified. The installer's own checks cover only the binary
it downloads, not the script itself, so this trusts the web host, its DNS and its CDN:

```bash
curl -sSL https://cosigner.fystack.io/install.sh | sh -s -- --version v1.2.3
```

Or build from source (Go 1.26+):

```bash
make build          # -> dist/cosigner-cli
```

## Quick start

**1. Prepare the config**

```bash
mkdir -p /srv/cosigner/secrets && chmod 700 /srv/cosigner/secrets
cp config.manual.example.yaml /secure/config.yaml
```

Edit `/secure/config.yaml`:

- set `callback.url` to your approval callback endpoint
- put the callback credentials in `/srv/cosigner/secrets/` (mode `600`):
  - `cosigner-private.der.hex`
  - `server-public.pem`

**2. Pair and start**

```bash
export COSIGNER_HOME=/srv/cosigner     # or pass --home on every command

cosigner-cli up \
  --apex-endpoint https://YOUR-APEX-HOST \
  --config /secure/config.yaml
```

`up` prompts for the pairing token, then generates a six-word storage passphrase and shows it once, then erases it from the screen after you press Enter so it stays out of scrollback. Write it on paper or save it in a password manager: without it the encrypted MPC key shares can't be decrypted. On `start`/`restart`, paste it or type the six words; spaces or hyphens and any capitalisation work. Scripted installs can still supply their own password via `COSIGNER_PASSWORD_FD`.
It pulls the newest signed release, verifies it and pins its digest.

**3. Check it**

```bash
cosigner-cli status
cosigner-cli doctor
cosigner-cli logs -f
```

## Commands

| Command   | What it does                                                    |
| --------- | --------------------------------------------------------------- |
| `up`      | First-time setup: pair, verify image, start                     |
| `start`   | Start a paired instance (prompts for the storage passphrase)      |
| `stop`    | Stop the container, keep all state                              |
| `restart` | Restart (prompts for the storage passphrase)                      |
| `status`  | Show runtime status                                             |
| `logs`    | Show logs (`-f` to follow, `--tail N`)                          |
| `doctor`  | Check Docker, config, image signature and install state         |
| `info`    | Print the public cosigner identity and callback key             |
| `callback add` | Require approval from a callback server (see below)        |
| `callback remove` | Stop requiring callback approval                        |
| `backup`  | Encrypted backup of the instance (must be stopped)              |
| `restore` | Restore a backup into an empty directory                        |
| `export`  | Write `.mshare` files for Fystack Recovery (must be stopped)    |
| `update`  | Verify and install a newer release                              |
| `version` | Print CLI and runtime versions                                  |

Global flags: `--home DIR` (or `COSIGNER_HOME`), `--docker CMD`.

## Approval callback

`callback add` connects a paired cosigner to your approval callback. It generates the cosigner's
callback key in `secrets/` (reused on later runs), pins the server's public key, writes the
`callback` block into `config.yaml` and restarts a running cosigner. Only public keys are exchanged.

Need a callback server? Start from [`examples/node-callback-server`](examples/node-callback-server):
it generates its own keypair, and its README covers bringing your own keys with OpenSSL, a
secret manager or AWS KMS.

Callback server on the same machine (local development), pointing at its key folder:

```bash
cosigner-cli callback add ./callback-keys
```

It reads `server-public.pem` from the folder, writes the cosigner's key there as
`cosigner-public.pem`, and uses `http://host.docker.internal:8089/cosigner/approve`
(override with `--url`). The [Node.js example](examples/node-callback-server) picks the key up
by itself; restart other callback servers. Folders from older callback servers
(`response-public.pem`) still work: the cosigner's key is then written as `request-public.pem`.

Callback server elsewhere:

```bash
cosigner-cli callback add https://callback.example.com --server-public-key server-public.pem
```

Without `--server-public-key` it asks for the path to the server's public key file (`-----BEGIN PUBLIC KEY-----`; never its private key). It then writes the cosigner's public key to
`cosigner-public.pem` in the instance directory and prints its full path: copy that file to the
callback server (the Node example reads it as `keys/cosigner-public.pem`). `/cosigner/approve` is added when the URL has no path. Use
`--ca ca.pem` if the callback uses a private or self-signed TLS certificate.

Signing requests are rejected until the callback server is reachable and trusts the cosigner's key.
`cosigner-cli info` prints the key again. `callback remove` turns approval off after confirmation.

`start`, `restart`, `up` and `doctor` check the callback files before asking for the password:
keys must exist, be RSA-4096 and live in `secrets/` or `state/`, and the URL must not be
`localhost` (inside the container that is the cosigner itself).

## Profiles

**`manual`** (default): the storage key is protected by a password. Someone must enter it on every `start`/`restart`, and Docker auto-restart is disabled.

**`unattended`**: the storage key is wrapped by AWS KMS, so the cosigner can start on its own.

```bash
cp config.unattended.example.yaml /secure/config.yaml
# fill in region, key_id, and put storage-kek.kms in secrets/
cosigner-cli up --profile unattended --apex-endpoint https://YOUR-APEX-HOST --config /secure/config.yaml
```

You provision the KMS key and IAM role yourself. The CLI does not manage AWS credentials.
To start on boot, adapt [`deploy/cosigner.service`](deploy/cosigner.service) (unattended only).

### Non-interactive passwords

Pass the password on a file descriptor, never as an argument:

```bash
COSIGNER_PASSWORD_FD=3 cosigner-cli start 3< /run/secrets/cosigner-pw
```

| Variable                        | Used by           |
| ------------------------------- | ----------------- |
| `COSIGNER_PASSWORD_FD`          | storage password  |
| `COSIGNER_RECOVERY_PASSWORD_FD` | `backup`/`restore` |

`COSIGNER_PASSWORD` / `COSIGNER_RECOVERY_PASSWORD` also work but leak into the environment. Avoid them.

## Backup, export and restore

```bash
cosigner-cli stop
cosigner-cli backup --out /secure/backups/cosigner.enc
cosigner-cli export --out-dir /secure/exports     # --list to see wallets, --wallet ID to pick
cosigner-cli start
```

- `backup` asks for a separate **recovery password**. Store the archive and the password in different places.
- `export` prints a six-word passphrase once. Store it apart from the `.mshare` files.
- Backup size limit: 128 MiB of data.

Restore into a new, empty directory:

```bash
cosigner-cli --home /srv/cosigner-restored restore --in /secure/backups/cosigner.enc
```

> [!WARNING]
> Shut down or revoke the old instance before starting a restored one. Two hosts running the same MPC shares is unsafe, and the file lock won't stop it.
> Restoring old MPC state may also need coordinator reconciliation.

## Update

```bash
cosigner-cli update --dry-run                                    # preview
cosigner-cli update --backup-out /secure/backups/pre-update.enc  # install newest
cosigner-cli update --version v1.2.3 --backup-out ...            # pin a version
```

- Requires a newer release, a valid signature and a compatible runtime contract.
- Always takes an encrypted checkpoint first. There is no automatic rollback.
- Pulls from the registry the instance was installed from. Switch with `--repository ghcr.io/fystack/cosigner`.
- `start`, `restart`, `status` and `doctor` tell you when a new release exists. Disable with `COSIGNER_NO_UPDATE_CHECK=1`.

## Security notes

- Keep `approval.require_callback: true`. Your callback gets the raw signing bytes and must validate them (chain, destination, amount, fee) before approving. The reference callback server denies everything until you plug in a verifier.
- This is host custody, not enclave isolation. Anyone with root or Docker access on the host is inside the trust boundary.
- Ship the audit log (`audit.jsonl`) off-host. Docker log rotation does not rotate it.
- Before handling real funds: test a clean-host restore, restart/failure scenarios, IAM revocation, and get an independent security review.

## Development

```bash
make build   # local binary
make test    # go vet + race tests
make dist    # linux/darwin × amd64/arm64 binaries
scripts/test-installer.sh   # render, shellcheck and test install.sh under dash
```

Releases: pushing a `vX.Y.Z` tag runs the release workflow. It builds and signs the binaries, renders
`install.sh` from [`scripts/install.sh.tmpl`](scripts/install.sh.tmpl) with their SHA-256s pinned, then
signs `install.sh` and `SHA256SUMS`. [cosigner.fystack.io](https://cosigner.fystack.io) verifies the
signed `install.sh` and serves it unchanged, so installer changes ship with the next CLI release.

The installer must stay POSIX `sh`: `curl | sh` runs it under `dash` on Debian and Ubuntu. To bump the
cosign it installs when a host has none, update [`scripts/cosign.env`](scripts/cosign.env) from that
cosign release's `cosign_checksums.txt` and run `scripts/check-cosign-pin.sh`.

## License

Copyright 2026 Fystack. Licensed under the [Apache License, Version 2.0](LICENSE).
