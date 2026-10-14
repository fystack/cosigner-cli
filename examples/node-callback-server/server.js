import express from "express";
import { Signer, Verifier } from "./utils.js";

const PORT = Number(process.env.PORT ?? 8089);
const signer = Signer.load();
const verifier = new Verifier();
const app = express();

app.post("/cosigner/approve", express.text({ type: "application/jwt", limit: "512kb" }), async (req, res) => {
  try {
    const request = await verifier.verify(req.body.trim());

    // Liveness check the cosigner sends every 30s: always answer "pong", never run approval logic.
    if (request.operation === "PING") {
      return res.type("application/jwt").send(await signer.sign(request, { action: "pong" }));
    }

    console.log("Cosigner request:", JSON.stringify(request, null, 2));

    let decision = { action: "approve" };
    // A re-share with local_veto_lost moves the wallet to a committee that can sign
    // without this cosigner, for good. Reject it unless you expect exactly that change.
    if (request.local_veto_lost) {
      decision = { action: "reject", reason: "re-share would let the new committee sign without this cosigner" };
    }
    // Your approval logic goes here. For example:
    //   if (request.signing_context?.tx?.decoded?.to_address !== ALLOWED_ADDRESS) {
    //     decision = { action: "reject", reason: "destination not allowed" };
    //   }

    res.type("application/jwt").send(await signer.sign(request, decision));
  } catch (err) {
    console.error("Rejected callback request:", err.message);
    res.sendStatus(401);
  }
});

app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}/cosigner/approve`));
