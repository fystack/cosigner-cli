# Node.js callback server

A starting point for the approval callback that a Cosigner asks before every
`SIGN`/`RESHARE`. The Cosigner sends a signed request; you answer `approve` or
`reject` with a signed response.

| File        | What it is                                                                 |
| ----------- | -------------------------------------------------------------------------- |
| `server.js` | Receives the request, logs it, answers. **Your approval logic goes here.** |
| `utils.js`  | Key files, request verification and response signing. Rarely changed.     |

Two dependencies: [`express`](https://expressjs.com) for HTTP and
[`jose`](https://github.com/panva/jose) for JWTs (Node 20.12+).
The server generates its own RSA-4096 keypair on first start.

The cosigner also sends a signed `PING` at startup and every 30 seconds. The
server answers it with a signed `pong` before any approval logic runs; if pings
fail, the cosigner will not start, or it marks itself not ready.

## Quick start: cosigner and callback on one machine

```bash
cp -r examples/node-callback-server ~/my-callback && cd ~/my-callback
npm install
npm start                                  # generates keys/, listens on :8089

# in the cosigner instance directory
cosigner-cli callback add ~/my-callback/keys
```

`callback add` reads `keys/server-public.pem` and writes the cosigner's key to
`keys/cosigner-public.pem`; the server reads it on every request, so no restart is
needed. The
cosigner reaches the server at `http://host.docker.internal:8089/cosigner/approve`.

## Callback on another machine

1. Start the server there (`npm start`). Copy `keys/server-public.pem` to the
   cosigner host.
2. On the cosigner host:

   ```bash
   cosigner-cli callback add https://callback.example.com --server-public-key server-public.pem
   ```

   It prints the path of the cosigner's public key (`cosigner-public.pem`).
3. Copy that file to the server as `keys/cosigner-public.pem` (or set
   `COSIGNER_PUBLIC_KEY`, below). No restart needed.

Only public keys travel between the two machines.

## Keys

| File                       | Whose                       | Leaves this machine?      |
| -------------------------- | --------------------------- | ------------------------- |
| `keys/server-private.pem`  | this server, signs answers  | Never                     |
| `keys/server-public.pem`   | this server                 | Yes, to the cosigner      |
| `keys/cosigner-public.pem` | the cosigner                | Arrives from the cosigner |

All keys are RSA-4096. `keys/` is git-ignored.

## Configuration

Copy `.env.example` to `.env` and adjust; the server loads it on start. Real
environment variables take precedence. `.env` is git-ignored.

| Variable              | Default  | Meaning                                                      |
| --------------------- | -------- | ------------------------------------------------------------ |
| `PORT`                | `8089`   | Listen port                                                  |
| `KEY_DIR`             | `./keys` | Where key files live                                         |
| `SERVER_PRIVATE_KEY`  | unset    | Server private key as PEM text; skips `server-private.pem`   |
| `COSIGNER_PUBLIC_KEY` | unset    | Cosigner public key as PEM text; skips `cosigner-public.pem` |

## Bring your own server key

The generated key is fine for development. In production you may want the
private key created and held elsewhere. Every option ends the same way: the
cosigner gets `server-public.pem`, and this server signs with the matching
private key.

### OpenSSL

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out keys/server-private.pem
openssl pkey -in keys/server-private.pem -pubout -out keys/server-public.pem
chmod 600 keys/server-private.pem
```

Start the server; it uses the existing key instead of generating one.

### Secret manager (Vault, AWS Secrets Manager, Kubernetes secret)

Store the PEM text of the private key as a secret and inject it at start, so
nothing is written to disk:

```bash
SERVER_PRIVATE_KEY="$(aws secretsmanager get-secret-value --secret-id callback/server-key \
  --query SecretString --output text)" npm start
```

The server still writes `keys/server-public.pem` for you to hand over.

### AWS KMS: encrypted at rest

The key is generated once, encrypted with a KMS key, and only the ciphertext is
stored. It is decrypted into memory at start.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out server-private.pem
openssl pkey -in server-private.pem -pubout -out keys/server-public.pem
aws kms encrypt --key-id alias/cosigner-callback --plaintext fileb://server-private.pem \
  --query CiphertextBlob --output text > server-private.pem.kms
shred -u server-private.pem

# at every start
SERVER_PRIVATE_KEY="$(aws kms decrypt --ciphertext-blob fileb://<(base64 -d server-private.pem.kms) \
  --query Plaintext --output text | base64 -d)" npm start
```

### AWS KMS: non-exportable signing key

The strongest option: the private key never leaves KMS, and each answer is
signed by a KMS API call.

```bash
aws kms create-key --key-spec RSA_4096 --key-usage SIGN_VERIFY --description "cosigner callback"
aws kms get-public-key --key-id <key-id> --query PublicKey --output text \
  | base64 -d | openssl pkey -pubin -inform DER -out keys/server-public.pem
```

Then add a KMS signer with the same `sign(request, decision)` method to
`utils.js` (this adds the `@aws-sdk/client-kms` dependency), and use
`new KmsSigner(process.env.KMS_KEY_ID)` instead of `Signer.load()` in
`server.js`. `jose` cannot sign with a remote key, so the token is assembled by
hand; `RSASSA_PKCS1_V1_5_SHA_256` is exactly RS256:

```js
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";

const b64url = (value) => Buffer.from(value).toString("base64url");

export class KmsSigner {
  constructor(keyId) {
    this.keyId = keyId;
    this.kms = new KMSClient({});
  }

  async sign(request, { action, reason }) {
    const now = Math.floor(Date.now() / 1000);
    const answer = { request_id: request.request_id, action, iat: now, exp: now + 60, jti: crypto.randomUUID() };
    if (action === "reject") answer.reason = String(reason ?? "").slice(0, 300) || "rejected";
    const input = `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${b64url(JSON.stringify(answer))}`;
    const { Signature } = await this.kms.send(
      new SignCommand({ KeyId: this.keyId, Message: Buffer.from(input), MessageType: "RAW", SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256" }),
    );
    return `${input}.${b64url(Signature)}`;
  }
}
```

Responses are a few hundred bytes, well under KMS's 4 KiB `RAW` message limit.

## The cosigner's key without `cosigner-cli` generating it

`cosigner-cli callback add` creates the cosigner's key the first time and
reuses an existing one. To use a key made elsewhere, put it in place first, in
the hex-encoded PKCS#8 DER format the cosigner runtime reads:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out cosigner.pem
openssl pkcs8 -topk8 -nocrypt -in cosigner.pem -outform DER | xxd -p | tr -d '\n' \
  > <instance>/secrets/callback-private.hex
chmod 600 <instance>/secrets/callback-private.hex
shred -u cosigner.pem
cosigner-cli callback add https://callback.example.com --server-public-key server-public.pem
```

## Before production

- Replace `let action = "approve"` in `server.js` with real rules. As shipped,
  the server approves every request.
- Serve over HTTPS: put it behind a load balancer or proxy that terminates TLS.
  The cosigner only allows plain HTTP to `host.docker.internal`.
- The cosigner retries a request once on network errors and 5xx. If your logic
  has side effects (spend limits, counters), make it idempotent by `request_id`.
- The cosigner rejects signing whenever this server is down or answers wrongly.
