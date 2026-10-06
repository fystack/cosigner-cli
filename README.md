# Cosigner operator CLI

Standalone host-side CLI for the Fystack cosigner runtime. No runtime Go imports,
Windows support, or legacy installation migration. Linux is the production host;
macOS is supported for development with Docker Desktop. Architectures: amd64/arm64.
The managed deployment is one regular-mode cosigner, local identity, and SQLite per
instance. Nitro deployments remain in the runtime repository.

## Install and configure

Requires Docker Engine with Compose v2 and [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/),
which verifies the CLI download and every runtime image before it runs. Install
Cosign first:

```bash
brew install cosign                      # macOS
go install github.com/sigstore/cosign/v3/cmd/cosign@latest   # any OS with Go
# Linux packages and release binaries: https://docs.sigstore.dev/cosign/system_config/installation/
cosign version
```

`up`, `update` and `doctor` stop before any prompt or download if Cosign is
missing; `start`, `restart` and `status` don't need it.

Build with `make build`, or,
after a signed CLI release is published, run
`bash scripts/install.sh vX.Y.Z /absolute/new/bin-directory`.
CLI and runtime versions are independent. Installer verifies the CLI publisher;
the CLI verifies runtime images against the runtime release workflow before
executing them. No unsigned-image bypass or floating `latest` tag is supported.

Without `--image`, first `up` picks the newest stable `X.Y.Z` tag in
`ghcr.io/fystack/cosigner`, verifies its signature and runtime contract, and pins
its digest. Signatures are checked when a digest is installed (`up`, `update`)
and by `doctor`; `start`/`restart` reuse the pinned digest without network
access to Sigstore. `start`, `restart`, `status` and `doctor` print a notice when
a newer release exists (set `COSIGNER_NO_UPDATE_CHECK=1` to disable).

Copy `config.manual.example.yaml` to a file outside your new instance directory.
Replace callback endpoints and provide its credentials under
`INSTANCE/secrets/` with private permissions. Select your real Apex endpoint.
Example versions below are placeholders, not claims of available releases.

```bash
cosigner-cli --home /srv/cosigner up \
  --apex-endpoint https://YOUR-APEX-HOST \
  --config /secure/config.manual.yaml --profile manual
cosigner-cli --home /srv/cosigner status
cosigner-cli --home /srv/cosigner doctor
```

Pairing token and storage password are prompted without echo. The token is sent
to the pairing container over stdin, not persisted. Repeating `up` preserves
identity and database; running instances are left alone. Conflicting containers,
missing pairing metadata with existing data, and concurrent mutating commands
fail closed. Registration conflicts never trigger automatic key rotation.
Use `update` for image changes, not `up --image`; `--image` (tag or digest) only
selects the release for a first setup.

## Passwords and restarts

Manual mode requires a person to unlock each start/restart; automatic container
restart is disabled. Password input can use `COSIGNER_PASSWORD_FD` (an inherited
descriptor >=3); environment fallback `COSIGNER_PASSWORD` is less safe and should
be avoided. Never put passwords in command arguments or shell history.
Child processes do not inherit password variables. Unlock uses a bounded,
one-use authenticated encrypted channel. Mutable secret buffers are cleared;
Go, OS, terminal, and environment copies cannot be guaranteed to be erased.
Root/Docker administrators are inside the trust boundary.

Unattended mode uses `config.unattended.example.yaml` and `--profile unattended`.
Provision the wrapped storage key and least-privilege AWS workload-role access
before setup. The CLI does not provision IAM or inject AWS credentials.
Container failure retries are bounded. For boot startup on Linux, adapt
`deploy/cosigner.service` to your installed CLI, service account and instance path.
This unit is for KMS mode only. Protect host access and monitor container readiness,
relay outages, denied approvals, disk space and audit-log growth. Ship file audits
off-host; container log rotation does not rotate the audit file.

## Operations and recovery

```bash
cosigner-cli --home /srv/cosigner logs --follow
cosigner-cli --home /srv/cosigner stop
cosigner-cli --home /srv/cosigner backup --out /secure/backups/cosigner.enc
cosigner-cli --home /srv/cosigner start

cosigner-cli --home /srv/cosigner update --dry-run
cosigner-cli --home /srv/cosigner update \
  --backup-out /secure/backups/pre-update.enc
# or pin an exact release: update --version vX.Y.Z --backup-out ...

cosigner-cli --home /srv/recovered-cosigner restore \
  --in /secure/backups/cosigner.enc
```

Backup requires a stopped instance and a separate recovery password
(`COSIGNER_RECOVERY_PASSWORD_FD`, or hidden prompt; environment fallback also
exists). Archives contain configuration, identity, encrypted storage key and all
local state, with authenticated encryption and file integrity checks. Treat the
archive and password as custody secrets, store separately and test recovery.
Limits: 128 MiB source data / 256 MiB encrypted archive. Larger deployments need a
reviewed native backup procedure, not a partial backup.

Restore accepts only an empty destination and never starts signing. Re-establish
external KMS permissions and callback connectivity. Fence/revoke the old instance
before starting the recovered one: a process lock does not prevent two hosts from
using copied MPC shares. Restoring old MPC state may be unsafe without coordinator
reconciliation; get an approved recovery procedure for your MPC protocol.

Updates pull from the installed image's own repository, so an instance set up
from a mirror such as `ghcr.io/fystack/cosigner` stays on it. Moving between
registries is explicit: `update --repository ghcr.io/fystack/cosigner`. Signature
verification is unchanged either way; only the runtime release workflow's
identity is accepted, whatever the registry.

Updates use the newest stable release unless `--version` is given, and require a newer release, a verified digest, a compatible runtime
contract and an offline recovery checkpoint. Health is checked after startup.
Failures leave state available for investigation; there is no automatic database
rollback or downgrade. Do not restore a checkpoint after new signing activity
without protocol-specific recovery guidance.

## Approval and deployment boundary

Keep `approval.require_callback: true` and a durable file audit for custody.
Explicitly setting it false disables this protection and is only suitable for
isolated tests. Callback requests include the actual signing bytes, key ID,
derivation and hash. Your callback must independently decode/validate those
bytes, enforce chain/account/destination/value/fee policy, and bind the approval
to them. The runtime repository's reference callback server denies signing until
an application supplies its transaction verifier; it is not a ready-made chain
policy engine.

This is regular-mode host custody, not enclave isolation. Local tests and hardening
do not establish parity with a custody vendor or certify production readiness.
Before customer funds: exercise clean-host restore and signing, failure/restart
scenarios, IAM revocation, release signature verification and an independent MPC
and policy security review.

## Development and releases

`make test` runs vet and race tests; `make dist` builds Linux/macOS binaries.
The independent release workflow publishes signed CLI binaries for stable
`vX.Y.Z` tags in `fystack/cosigner-cli`. Configure its protected release
environment and publish the repository before using the release installer.
No remote repository or release is created by the local extraction.
