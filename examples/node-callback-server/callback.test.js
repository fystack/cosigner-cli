import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import { SignJWT, jwtVerify } from "jose";
import { Signer, Verifier } from "./utils.js";

const cosigner = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });
const server = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });
const attacker = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });

const now = () => Math.floor(Date.now() / 1000);
const request = (claims = {}, key = cosigner.privateKey) =>
  new SignJWT({ request_id: "req-1", operation: "SIGN", exp: now() + 30, ...claims }).setProtectedHeader({ alg: "RS256" }).sign(key);
const verifier = new Verifier(cosigner.publicKey);
const signer = new Signer(server.privateKey);
const verify = (token) => verifier.verify(token);
const readAnswer = async (token) => (await jwtVerify(token, server.publicKey, { algorithms: ["RS256"] })).payload;

test("accepts a request from the trusted cosigner", async () => {
  assert.equal((await verify(await request())).request_id, "req-1");
});

test("refuses requests not signed by the trusted cosigner", async () => {
  await assert.rejects(verify(await request({}, attacker.privateKey)));
});

test("refuses tokens that pick another algorithm", async () => {
  const [, claims, signature] = (await request()).split(".");
  for (const alg of ["none", "HS256", "RS512"]) {
    const header = Buffer.from(JSON.stringify({ alg })).toString("base64url");
    await assert.rejects(verify(`${header}.${claims}.${signature}`));
  }
});

test("refuses tampered, expired and incomplete requests", async () => {
  const [header, , signature] = (await request()).split(".");
  const tampered = Buffer.from(JSON.stringify({ request_id: "req-1", operation: "RESHARE" })).toString("base64url");
  await assert.rejects(verify(`${header}.${tampered}.${signature}`));
  await assert.rejects(verify(await request({ exp: now() - 60 })));
  await assert.rejects(verify(await request({ request_id: undefined })));
  await assert.rejects(verify("not-a-jwt"));
});

test("signs approve and reject answers", async () => {
  const approve = await readAnswer(await signer.sign({ request_id: "req-1" }, { action: "approve", reason: "ignored" }));
  assert.deepEqual([approve.request_id, approve.action, approve.reason], ["req-1", "approve", undefined]);
  assert.ok(approve.exp > approve.iat);

  const reject = await readAnswer(await signer.sign({ request_id: "req-1" }, { action: "reject", reason: "not allowlisted" }));
  assert.deepEqual([reject.action, reject.reason], ["reject", "not allowlisted"]);
  assert.equal((await readAnswer(await signer.sign({ request_id: "req-1" }, { action: "reject", reason: "" }))).reason, "rejected");
  const pong = await readAnswer(await signer.sign({ request_id: "req-1" }, { action: "pong" }));
  assert.deepEqual([pong.action, pong.reason], ["pong", undefined]);
  assert.equal((await readAnswer(await signer.sign({ request_id: "req-1" }, { action: "maybe" }))).action, "reject");
  const long = await readAnswer(await signer.sign({ request_id: "req-1" }, { action: "reject", reason: "é".repeat(2000) }));
  assert.ok(Buffer.byteLength(long.reason) <= 1024);
});
