// Minimal Proof Gatekeeper agent — zkVerify Agent Games Season 01.
// Docs: https://agentgames.zkverify.io/build (protocol source of truth)
//       https://agentgames.zkverify.io/events/proof-gatekeeper (traps + scoring)
//
// Flow per task (60s hard deadline):
//   1. Verify HMAC (x-agent-games-signature) over the RAW request body.
//   2. Decide APPROVE/REJECT deterministically from the 7 documented trap checks.
//   3. If the decision agrees with the circuit's expiry rule, generate a local
//      Groth16 proof with snarkjs (downloaded wasm/zkey) and attach
//      { proof, public_signals }. Otherwise respond without a proof (-2, but the
//      decision itself still scores).
//   4. Sign the raw response body with x-agent-games-signature.
//
// Reverse-engineered circuit facts (verified locally against the real artifacts):
//   - 13 inputs: registeredVkHash, proofVkHash, minimum, publicBalance,
//     expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//     maxTransfer, taskId, decision, salt.
//   - 13 public signals, in order: [H, registeredVkHash, proofVkHash, minimum,
//     publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
//     amount, maxTransfer, decision, taskId]. H = binding hash of (taskId, salt).
//   - salt is the sole PRIVATE input (blinding factor; any value works).
//   - Circuit decision encoding: 1 = APPROVE, 0 = REJECT.
//   - The circuit enforces ONLY the expiry rule: decision must be 1 iff
//     expiryBlock > currentBlock, else 0. The other 6 trap checks live in the
//     plain-code decision logic below (and in the platform's own scoring).
//   - Warm proving takes ~0.4s on this VM — far inside the 60s window.
//   - Value encodings for registeredVkHash / proofVkHash / taskId are NOT in the
//     public docs; defaults below are best guesses, VALIDATE VIA PRACTICE MODE
//     (see README.md) and flip VK_ENCODING / TASKID_ENCODING if the platform
//     rejects the proof.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import * as snarkjs from "snarkjs";
import { keccak256 } from "js-sha3";

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const VK_ENCODING = process.env.VK_ENCODING || "keccak-bytes";
const TASKID_ENCODING = process.env.TASKID_ENCODING || "keccak-str";
const SALT = BigInt(process.env.SALT || "1");
const SEEN_FILE = process.env.SEEN_FILE || "./data/seen-proof-txs.json";

// bn128 prime — all circuit inputs are field elements mod this prime.
const PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

if (!HMAC_SECRET) {
  console.warn("[warn] AGENT_GAMES_HMAC_SECRET is empty — HMAC verification will fail closed.");
}

// ---- circuit artifacts (loaded once at boot; proving is ~0.4s warm) ----
const ART = path.join(import.meta.dirname, "artifacts");
const WASM = fs.readFileSync(path.join(ART, "gatekeeper.wasm"));
const ZKEY = fs.readFileSync(path.join(ART, "gatekeeper_final.zkey"));
const VK = JSON.parse(fs.readFileSync(path.join(ART, "vk.json"), "utf8"));

// ---- seen proof references (PROOF_REUSED detection), persisted to disk ----
const seen = new Set();
try {
  fs.mkdirSync(path.dirname(SEEN_FILE), { recursive: true });
  if (fs.existsSync(SEEN_FILE)) {
    for (const tx of JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"))) seen.add(tx);
  }
} catch (e) {
  console.warn("[warn] seen-set load failed:", e.message);
}
function persistSeen() {
  try {
    fs.writeFileSync(SEEN_FILE, JSON.stringify([...seen]));
  } catch (e) {
    console.warn("[warn] seen-set persist failed:", e.message);
  }
}

// ---- HMAC (SHA-256, hex) over raw bodies ----
function hmacHex(secret, raw) {
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}
function verifySignature(raw, header) {
  if (!HMAC_SECRET || !header) return false;
  const got = header.trim().toLowerCase().replace(/^sha256=/, "");
  const want = hmacHex(HMAC_SECRET, raw);
  const a = Buffer.from(got, "utf8");
  const b = Buffer.from(want, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---- value encodings (field elements) ----
function keccakMod(bytes) {
  return BigInt("0x" + keccak256(bytes)) % PRIME;
}
function encodeVk(hex) {
  const clean = String(hex).replace(/^0x/, "");
  if (process.env[`VK_HASH_OVERRIDE_${clean.slice(0, 8)}`]) {
    return BigInt(process.env[`VK_HASH_OVERRIDE_${clean.slice(0, 8)}`]);
  }
  if (VK_ENCODING === "raw-int") return BigInt("0x" + clean) % PRIME;
  if (VK_ENCODING === "keccak-hexstr") return keccakMod(Buffer.from("0x" + clean, "utf8"));
  return keccakMod(Buffer.from(clean, "hex")); // keccak-bytes (default)
}
function encodeTaskId(taskId) {
  const s = String(taskId ?? "");
  if (TASKID_ENCODING === "raw-hex") {
    const m = s.match(/[0-9a-fA-F]+/g);
    return m ? BigInt("0x" + m.join("")) % PRIME : 0n;
  }
  return keccakMod(Buffer.from(s, "utf8")); // keccak-str (default)
}
const toFieldInt = (v) => BigInt(v); // decimal strings / small ints (blocks, amounts)
const toFieldAddr = (hex) => BigInt(hex); // 20-byte address fits in the field

// ---- decision logic: the 7 documented trap checks, deterministic order ----
// Returns { decision: "APPROVE"|"REJECT", reason_code }.
// Boundary: current_block >= expiry_block counts as EXPIRED (matches the circuit).
export function decide(input) {
  const { registered_vk, proof_vk, minimum, public_balance, expiry_block,
    current_block, recipient, condition_recipient, amount, max_transfer, proof_tx } = input;
  if (proof_tx && seen.has(proof_tx)) return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  if (String(proof_vk).toLowerCase() !== String(registered_vk).toLowerCase()) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  }
  if (BigInt(public_balance) < BigInt(minimum)) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  }
  if (BigInt(current_block) >= BigInt(expiry_block)) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  }
  if (String(recipient).toLowerCase() !== String(condition_recipient).toLowerCase()) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  }
  if (BigInt(amount) > BigInt(max_transfer)) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

// ---- circuit input construction ----
function buildCircuitInput(input, decisionStr) {
  // Prefer precomputed hashes if the platform sends them (not in the sample payload).
  const regHash = input.registered_vk_hash ?? input.registeredVkHash;
  const proofHash = input.proof_vk_hash ?? input.proofVkHash;
  return {
    registeredVkHash: regHash !== undefined ? BigInt(regHash) : encodeVk(input.registered_vk),
    proofVkHash: proofHash !== undefined ? BigInt(proofHash) : encodeVk(input.proof_vk),
    minimum: toFieldInt(input.minimum),
    publicBalance: toFieldInt(input.public_balance),
    expiryBlock: toFieldInt(input.expiry_block),
    currentBlock: toFieldInt(input.current_block),
    recipient: toFieldAddr(input.recipient),
    conditionRecipient: toFieldAddr(input.condition_recipient),
    amount: toFieldInt(input.amount),
    maxTransfer: toFieldInt(input.max_transfer),
    taskId: input.task_id_hash ?? input.taskIdHash ? BigInt(input.task_id_hash ?? input.taskIdHash) : encodeTaskId(input.task_id),
    decision: decisionStr === "APPROVE" ? 1n : 0n,
    salt: SALT,
  };
}

// The circuit only proves decisions that agree with its expiry rule:
//   APPROVE(1) iff expiryBlock > currentBlock, else REJECT(0).
function proofIsPossible(input, decisionStr) {
  const expired = BigInt(input.current_block) >= BigInt(input.expiry_block);
  return decisionStr === "APPROVE" ? !expired : expired;
}

async function generateProof(input, decisionStr) {
  const circuitInput = buildCircuitInput(input, decisionStr);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  return { proof, publicSignals };
}

// ---- HTTP server ----
function sendJson(res, status, obj, sign) {
  const body = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (sign && HMAC_SECRET) headers["x-agent-games-signature"] = hmacHex(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    const started = Date.now();
    try {
      if (req.method === "GET") {
        return sendJson(res, 200, { ok: true, service: "agent-games-gatekeeper" }, false);
      }
      if (req.method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" }, false);

      // 1. HMAC verification BEFORE parsing (fail closed).
      const sig = req.headers["x-agent-games-signature"];
      if (!verifySignature(raw, sig)) {
        console.warn("[auth] bad/missing signature");
        return sendJson(res, 401, { error: "bad_signature" }, false);
      }
      let envelope;
      try {
        envelope = JSON.parse(raw.toString("utf8"));
      } catch {
        return sendJson(res, 400, { error: "bad_json" }, true);
      }

      // 2. Preflight handshake.
      if (envelope.type === "agent-games.preflight.v1") {
        console.log("[preflight] ok");
        return sendJson(res, 200, { ok: true, protocolVersion: "v1" }, true);
      }
      if (envelope.type !== "agent-games.proof-gatekeeper.v1") {
        return sendJson(res, 400, { error: "unknown_type" }, true);
      }

      // 3. Decide (deterministic trap checks).
      const input = envelope.input || {};
      const { decision, reason_code } = decide(input);
      console.log(`[task ${envelope.task_id}] ${decision} ${reason_code}`);

      // 4. Proof: only when the decision agrees with the circuit's expiry rule
      //    (and never for PROOF_REUSED — the docs exclude those from proofs).
      //    Budget: leave 10s of the 60s deadline for the response.
      const response = { decision, reason_code, proof_tx: input.proof_tx ?? null };
      if (reason_code !== "PROOF_REUSED" && proofIsPossible(input, decision)) {
        try {
          const timed = await Promise.race([
            generateProof(input, decision),
            new Promise((_, rej) => setTimeout(() => rej(new Error("proof_timeout")), 45000)),
          ]);
          // Local sanity check before sending.
          const ok = await snarkjs.groth16.verify(VK, timed.publicSignals, timed.proof);
          if (ok) {
            response.proof = timed.proof;
            response.public_signals = timed.publicSignals;
          } else {
            console.warn(`[task ${envelope.task_id}] local proof verification failed — omitting proof`);
          }
        } catch (e) {
          console.warn(`[task ${envelope.task_id}] proof skipped (${e.message}) — decision still returned`);
        }
      } else if (reason_code !== "PROOF_REUSED") {
        console.log(`[task ${envelope.task_id}] proof not generatable for this decision (circuit expiry rule) — omitting proof`);
      }

      // 5. Record an APPROVEd proof reference so a replay is caught as PROOF_REUSED.
      if (decision === "APPROVE" && input.proof_tx) {
        seen.add(input.proof_tx);
        persistSeen();
      }

      console.log(`[task ${envelope.task_id}] responded in ${Date.now() - started}ms, proof=${!!response.proof}`);
      return sendJson(res, 200, response, true);
    } catch (e) {
      // Fail closed: never approve by default; return a signed REJECT-shaped error.
      console.error("[error]", e);
      return sendJson(res, 500, { decision: "REJECT", reason_code: "AGENT_ERROR", proof_tx: null }, true);
    }
  });
});

server.listen(PORT, () => {
  console.log(`gatekeeper listening on :${PORT} (vk=${VK.nPublic} public signals, salt=${SALT})`);
});
