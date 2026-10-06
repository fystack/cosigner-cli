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

- **Platforms:** Linux (production), macOS with Docker Desktop (development). amd64 and arm64.
- **Nitro enclave deployments** are not covered here. See the runtime repository.

## Prerequisites

- Docker Engine with Compose v2
- [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/), used to verify the CLI and every runtime image

```bash
brew install cosign                                          # macOS
go install github.com/sigstore/cosign/v3/cmd/cosign@latest   # anywhere with Go
cosign version
```

## Install

From a signed release:

```bash
curl -fsSLO https://raw.githubusercontent.com/fystack/cosigner-cli/main/scripts/install.sh
bash install.sh v1.2.3 /opt/cosigner-cli/bin    # target dir must not exist yet
export PATH="/opt/cosigner-cli/bin:$PATH"
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
  - `callback-private.hex`
  - `callback-response.pub.pem`

**2. Pair and start**

```bash
export COSIGNER_HOME=/srv/cosigner     # or pass --home on every command

cosigner-cli up \
  --apex-endpoint https://YOUR-APEX-HOST \
  --config /secure/config.yaml
```

`up` prompts for the pairing token and a storage password (min 12 chars, with upper, lower, digit and symbol).
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
| `start`   | Start a paired instance (prompts for the storage password)      |
| `stop`    | Stop the container, keep all state                              |
| `restart` | Restart (prompts for the storage password)                      |
| `status`  | Show runtime status                                             |
| `logs`    | Show logs (`-f` to follow, `--tail N`)                          |
| `doctor`  | Check Docker, config, image signature and install state         |
| `info`    | Print the public cosigner identity                              |
| `backup`  | Encrypted backup of the instance (must be stopped)              |
| `restore` | Restore a backup into an empty directory                        |
| `export`  | Write `.mshare` files for Fystack Recovery (must be stopped)    |
| `update`  | Verify and install a newer release                              |
| `version` | Print CLI and runtime versions                                  |

Global flags: `--home DIR` (or `COSIGNER_HOME`), `--docker CMD`.

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
```

Releases: pushing a `vX.Y.Z` tag runs the release workflow, which publishes signed binaries.
