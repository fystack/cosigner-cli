// Plumbing for server.js: verifying cosigner requests and signing answers.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { SignJWT, jwtVerify } from "jose";

if (fs.existsSync(".env")) process.loadEnvFile(".env");

const KEY_DIR = process.env.KEY_DIR ?? "./keys";

// File names match `cosigner-cli callback add <folder>`.
const SERVER_PRIVATE_KEY_FILE = path.join(KEY_DIR, "server-private.pem"); // signs our answers, never shared
const SERVER_PUBLIC_KEY_FILE = path.join(KEY_DIR, "server-public.pem"); // given to the cosigner
const COSIGNER_PUBLIC_KEY_FILE = path.join(KEY_DIR, "cosigner-public.pem"); // written by the cosigner

// Signer signs approve/reject answers with this server's private key.
export class Signer {
  constructor(privateKey) {
    this.privateKey = privateKey;
  }

  // load reads the key from SERVER_PRIVATE_KEY or keys/, generating one on first
  // start, and writes the public half to keys/ for the cosigner.
  static load() {
    fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
    if (!process.env.SERVER_PRIVATE_KEY && !fs.existsSync(SERVER_PRIVATE_KEY_FILE)) {
      const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });
      fs.writeFileSync(SERVER_PRIVATE_KEY_FILE, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    }
    const privateKey = crypto.createPrivateKey(process.env.SERVER_PRIVATE_KEY ?? fs.readFileSync(SERVER_PRIVATE_KEY_FILE));
    fs.writeFileSync(SERVER_PUBLIC_KEY_FILE, crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }));
    console.log(`Give the cosigner ${SERVER_PUBLIC_KEY_FILE}`);
    return new Signer(privateKey);
  }

  // sign answers a request with "approve", "reject" or (for PING) "pong". Anything
  // else becomes a reject. A reject always carries a reason; the cosigner caps it
  // at 1024 bytes, which 300 UTF-16 units never exceed.
  sign(request, { action, reason }) {
    const answer = { request_id: request.request_id, action: ["approve", "pong"].includes(action) ? action : "reject" };
    if (answer.action === "reject") answer.reason = String(reason ?? "").trim().slice(0, 300) || "rejected";
    return new SignJWT(answer)
      .setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .setIssuedAt()
      .setExpirationTime("60s")
      .setJti(crypto.randomUUID())
      .sign(this.privateKey);
  }
}

// Verifier checks that a request was signed by the trusted cosigner.
export class Verifier {
  // cosignerKey defaults to COSIGNER_PUBLIC_KEY or keys/cosigner-public.pem, read
  // per request so `cosigner-cli callback add` needs no restart.
  constructor(cosignerKey) {
    this.cosignerKey = cosignerKey;
  }

  // verify returns the request payload, or throws. Only RS256 is accepted, so a
  // token cannot pick a weaker algorithm.
  async verify(token) {
    const key = this.cosignerKey ?? crypto.createPublicKey(process.env.COSIGNER_PUBLIC_KEY ?? fs.readFileSync(COSIGNER_PUBLIC_KEY_FILE));
    const { payload } = await jwtVerify(token, key, {
      algorithms: ["RS256"],
      requiredClaims: ["exp", "request_id"],
      clockTolerance: 30,
    });
    return payload;
  }
}
