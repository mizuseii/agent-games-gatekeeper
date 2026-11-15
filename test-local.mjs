// Local test harness for the Gatekeeper agent.
// Spins up server.mjs on a test port with a throwaway HMAC secret and replays:
//   - preflight (good + bad signature)
//   - a valid task (realistic values) -> APPROVE + locally-verifiable proof
//   - each of the 6 trap types (+ PROOF_REUSED via replay) -> correct REJECT
//   - response-signature verification + timing
// No network, no registration, no real platform involved.
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import * as snarkjs from "snarkjs";
import fs from "node:fs";

const PORT = 3456;
const SECRET = "test-secret-do-not-use-in-production";
const BASE = `http://127.0.0.1:${PORT}`;
const VK = JSON.parse(fs.readFileSync("./artifacts/vk.json", "utf8"));

const server = spawn("node", ["server.mjs"], {
  env: {
    ...process.env,
    PORT: String(PORT),
    AGENT_GAMES_HMAC_SECRET: SECRET,
    SEEN_FILE: "./data-test/seen.json",
    SALT: "1",
  },
  stdio: ["ignore", "pipe", "pipe"],
});
server.stdout.on("data", (d) => process.stdout.write("[srv] " + d));
server.stderr.on("data", (d) => process.stdout.write("[srv:err] " + d));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
await sleep(1500); // let the server boot + load artifacts

function sign(raw) {
  return crypto.createHmac("sha256", SECRET).update(raw).digest("hex");
}
async function post(obj, { sig = true, rawOverride = null } = {}) {
  const raw = rawOverride ?? JSON.stringify(obj);
  const t0 = Date.now();
  const res = await fetch(BASE + "/", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(sig ? { "x-agent-games-signature": sign(raw) } : {}),
    },
    body: raw,
  });
  const text = await res.text();
  const ms = Date.now() - t0;
  let body = null;
  try { body = JSON.parse(text); } catch { /* non-JSON */ }
  const respSig = res.headers.get("x-agent-games-signature");
  const sigOk = respSig
    ? crypto.timingSafeEqual(Buffer.from(respSig), Buffer.from(sign(text)))
    : false;
  return { status: res.status, body, ms, sigOk, raw: text };
}

let pass = 0, fail = 0;
function check(name, cond, extra = "") {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${extra}`); }
}

const REG_VK = "0x7d3a9c1e5f2846a0b8c7d3e5f1a2b4c6d8e0f1a2b3c4d5e6f7a8b9c0d1e2f291";
const OTHER_VK = "0xa4c1b8ff9e2d4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f1a2b3";
const ADDR_A = "0xDe42a1B2c3D4e5F6a7B8c9D0e1F2a3B4c5D6e7F01";
const ADDR_B = "0xBeef00000000000000000000000000000000000001";

function task(overrides = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_test_001",
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: REG_VK,
      proof_vk: REG_VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: ADDR_A,
      condition_recipient: ADDR_A,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa8c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c2",
      ...overrides,
    },
  };
}

console.log("== preflight ==");
{
  const r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  check("preflight 200 + ok + v1 + signed", r.status === 200 && r.body?.ok === true && r.body?.protocolVersion === "v1" && r.sigOk, JSON.stringify(r.body));
  const bad = await post({ type: "agent-games.preflight.v1" }, { sig: false });
  check("preflight without signature -> 401", bad.status === 401);
  const wrong = await fetch(BASE + "/", { method: "POST", headers: { "content-type": "application/json", "x-agent-games-signature": "deadbeef" }, body: JSON.stringify({ type: "agent-games.preflight.v1" }) });
  check("preflight with wrong signature -> 401", wrong.status === 401);
}

console.log("== valid task ==");
{
  const r = await post(task());
  check("valid -> 200 + APPROVE + VALID_CONDITION", r.status === 200 && r.body?.decision === "APPROVE" && r.body?.reason_code === "VALID_CONDITION", JSON.stringify(r.body)?.slice(0, 200));
  check("valid -> proof attached", !!r.body?.proof && Array.isArray(r.body?.public_signals) && r.body.public_signals.length === 13, `signals=${r.body?.public_signals?.length}`);
  if (r.body?.proof) {
    const ok = await snarkjs.groth16.verify(VK, r.body.public_signals, r.body.proof);
    check("valid -> proof verifies against platform VK", ok);
    // public-signal order check: [H, regVk, proofVk, min, bal, exp, cur, recip, condRecip, amt, max, decision, taskId]
    const ps = r.body.public_signals;
    check("signals: decision==1 (APPROVE)", ps[11] === "1", `ps[11]=${ps[11]}`);
    check("signals: minimum==1000", ps[3] === "1000");
    check("signals: publicBalance==1460", ps[4] === "1460");
    check("signals: expiryBlock==8430000", ps[5] === "8430000");
    check("signals: currentBlock==8420000", ps[6] === "8420000");
    check("signals: amount==500", ps[9] === "500");
    check("signals: maxTransfer==1000", ps[10] === "1000");
  }
  check("valid -> response signed", r.sigOk);
  check("valid -> fast (<10s)", r.ms < 10000, `${r.ms}ms`);
  check("valid -> proof_tx echoed", r.body?.proof_tx === task().input.proof_tx);
}

console.log("== traps ==");
async function trap(name, overrides, reason, expectProof) {
  const t = task({ ...overrides, proof_tx: "0x" + Buffer.from("trap-" + name).toString("hex").padEnd(64, "0").slice(0, 64) });
  const r = await post(t);
  check(`${name} -> REJECT ${reason}`, r.status === 200 && r.body?.decision === "REJECT" && r.body?.reason_code === reason, JSON.stringify(r.body)?.slice(0, 160));
  check(`${name} -> proof ${expectProof ? "present" : "absent"}`, expectProof ? !!r.body?.proof : !r.body?.proof, `proof=${!!r.body?.proof}`);
  if (r.body?.proof) {
    const ok = await snarkjs.groth16.verify(VK, r.body.public_signals, r.body.proof);
    check(`${name} -> attached proof verifies`, ok);
  }
  check(`${name} -> signed`, r.sigOk);
}
await trap("VK_SUBSTITUTION", { proof_vk: OTHER_VK }, "VK_SUBSTITUTION", false);
await trap("THRESHOLD_MISMATCH", { public_balance: "999" }, "THRESHOLD_MISMATCH", false);
await trap("EXPIRED_CONDITION", { current_block: 8430000 }, "EXPIRED_CONDITION", true); // circuit agrees: expired -> REJECT(0) proves
await trap("RECIPIENT_MISMATCH", { recipient: ADDR_B }, "RECIPIENT_MISMATCH", false);
await trap("AMOUNT_OVERFLOW", { amount: "1001" }, "AMOUNT_OVERFLOW", false);

console.log("== PROOF_REUSED (replay the valid task) ==");
{
  const r = await post(task()); // same proof_tx as the approved valid task
  check("replay -> REJECT PROOF_REUSED, no proof", r.body?.decision === "REJECT" && r.body?.reason_code === "PROOF_REUSED" && !r.body?.proof, JSON.stringify(r.body)?.slice(0, 160));
}

console.log(`\n${pass} passed, ${fail} failed`);
server.kill();
process.exit(fail ? 1 : 0);
