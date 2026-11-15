# Proof Gatekeeper — minimal agent (zkVerify Agent Games Season 01)

Status: **built + locally verified (33/33 tests pass)**. NOT yet deployed,
NOT registered, NOT preflighted — those need user actions (see below).

## What it does

`server.mjs` — a dependency-light Node.js HTTP service:

1. Verifies `x-agent-games-signature` (HMAC-SHA256, hex) over the RAW request
   body **before** parsing JSON; rejects (401) on mismatch.
2. Answers the preflight handshake: `{ ok: true, protocolVersion: "v1" }`, signed.
3. Decides each task deterministically from the 7 documented trap checks
   (see `decide()` in `server.mjs`): PROOF_REUSED → VK_SUBSTITUTION →
   THRESHOLD_MISMATCH → EXPIRED_CONDITION → RECIPIENT_MISMATCH →
   AMOUNT_OVERFLOW → else APPROVE. Boundary: `current_block >= expiry_block`
   counts as expired (matches the circuit).
4. Generates a local Groth16 proof with snarkjs (downloaded `gatekeeper.wasm` +
   `gatekeeper_final.zkey`) and returns `{ decision, reason_code, proof,
   public_signals, proof_tx }`, signed. Warm proving ≈ 0.4 s — far inside the
   60 s deadline. If a proof can't be generated, the decision is still
   returned without one (costs −2 for that task, decision still scores).
5. Tracks approved `proof_tx` values in `data/seen-proof-txs.json` so replays
   are rejected as PROOF_REUSED.

Run locally: `cp .env.example .env` (set a throwaway secret) → `node server.mjs`.
Test: `node test-local.mjs` (33 checks, no network, no registration).

## What was reverse-engineered (verified against the real artifacts)

The public docs do **not** publish the circuit input schema. It was recovered
empirically by probing the downloaded wasm/zkey with snarkjs (scripts in
`probes/`):

- 13 circuit inputs: `registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, taskId, decision, salt`.
- 13 public signals, in order: `[H, registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId]` where `H` is a binding hash of
  `(taskId, salt)`.
- `salt` is the sole **private** input (blinding factor; any value works).
- Decision encoding: **1 = APPROVE, 0 = REJECT**.
- The circuit enforces **only the expiry rule**: decision must be 1 iff
  `expiryBlock > currentBlock`, else 0. The other 6 trap checks are enforced
  by the plain-code decision logic (and the platform's own scoring) — the
  proof does not cover them.
- Consequence: proofs are generatable for APPROVE decisions (valid tasks) and
  for REJECTs caused by expiry, but **not** for REJECTs caused by the other 5
  trap types when the task is not expired. Expected proof coverage ≈ 56% of
  tasks (+11% PROOF_REUSED excluded from the proof requirement). The
  decision itself still scores +12 when correct; a missing proof costs −2
  and forfeits part of the +0–5 reliability bonus. Decision correctness
  dominates the score either way.

## Known unknowns — validate via Practice Mode before trusting the proof

1. **VK / taskId hash encodings.** The task payload gives `registered_vk` /
   `proof_vk` as 32-byte hex and `task_id` as a string (`gk_...`), but the
   circuit takes `registeredVkHash` / `proofVkHash` / `taskId` field elements.
   Defaults: `VK_ENCODING=keccak-bytes` (keccak256 of the raw 32 bytes, mod
   the bn128 prime), `TASKID_ENCODING=keccak-str` (keccak256 of the UTF-8
   task id, mod prime). Alternatives: `VK_ENCODING=raw-int|keccak-hexstr`,
   `TASKID_ENCODING=raw-hex`. If the platform rejects the proof in practice
   mode, flip these (or check whether the real payload carries precomputed
   `*_hash` fields — the server prefers those when present).
2. **HMAC construction.** Assumed HMAC-SHA256, lowercase hex, no prefix.
   Preflight is the oracle: if it fails, try `sha256=` prefix / base64.
3. **Response `proof_tx`.** Included as an echo of the input's `proof_tx`
   (matches the event-page sample; the starter prompt omits it). Drop it if
   practice mode complains about the schema.

## User actions still needed (nothing here can be done without them)

1. **Register** at agentgames.zkverify.io (X or wallet, from the user's
   phone — X login from this VM is blocked; wallet connect needs their
   MetaMask). Prize eligibility also needs a connected GitHub + wallet.
2. **HMAC secret**: dashboard → agent settings → "Rotate Secret" (shown
   once). Put it in the deployment environment as `AGENT_GAMES_HMAC_SECRET`.
   Never paste it in chat. The agent cannot pass preflight without it.
3. **Hosting**: a public HTTPS endpoint, no custom ports, must stay up during
   rounds (17:30–03:30 WIB daily; a sleeping free tier forfeits tasks) and
   answer in <60 s. The proving step needs ~0.4 s CPU per task plus the
   1.75 MB wasm + 310 KB zkey in memory — a plain Node host (Fly.io /
   Railway / Render / small VPS) fits; a Cloudflare Worker is a poor fit
   (no filesystem for the artifacts, tight CPU limits on free plans). The
   user's existing Worker runs their vAPI agent, not this.
4. **Validate**: after deploy + preflight, run Practice Mode tasks (capped
   10/hour) and confirm (a) preflight passes, (b) practice decisions score
   as expected, (c) proofs are accepted (flip the encoding switches if not).

## Timing

- Round 3 starts **Sun 2026-11-15 17:30 WIB**; rounds run daily thru 20 Nov.
- The build itself is done. Live + preflighted before Round 3 is possible
  **only if** the user registers + supplies the HMAC secret + picks hosting
  in the next few hours, and the proof encodings validate quickly. If any of
  that slips, Rounds 4–8 remain, and the agent can still run decision-only
  (no proof) with a small score penalty.
- Rounds 1–2 are already gone (cumulative scoring); maximum realistic
  outcome from Round 3 on is a mid-table finish, not a win — set
  expectations accordingly.

## Files

- `server.mjs` — the agent (HTTP + HMAC + decision + proof).
- `test-local.mjs` — 33 local checks (run with `node test-local.mjs`).
- `artifacts/` — `gatekeeper.wasm` (1.75 MB), `gatekeeper_final.zkey`
  (310 KB), `vk.json` (exported verification key; vkHash
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
- `probes/` — scratch scripts used to reverse-engineer the circuit.
- `.env.example`, `package.json`, `.gitignore`.
