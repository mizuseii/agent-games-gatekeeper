import * as snarkjs from "snarkjs";
const fs = await import("fs");
const vk = JSON.parse(fs.readFileSync("artifacts/vk.json","utf8"));
const base = {registeredVkHash:1,proofVkHash:1,minimum:1,publicBalance:1,expiryBlock:1,currentBlock:1,recipient:1,conditionRecipient:1,amount:1,maxTransfer:1,taskId:1};
async function trial(input, label) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, "artifacts/gatekeeper.wasm", "artifacts/gatekeeper_final.zkey");
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(label, `=> PROVED+verified=${ok} in ${Date.now()-t0}ms H=${publicSignals[0]}`);
    return publicSignals[0];
  } catch (e) {
    console.log(label, `=> FAIL in ${Date.now()-t0}ms:`, String(e && e.message || e).replace(/\n/g," ").slice(0,150));
    return null;
  }
}
// A: warm prove timing — same valid input twice
await trial({ ...base, decision: 0, salt: 1 }, "A1 valid d0 s1");
await trial({ ...base, decision: 0, salt: 1 }, "A2 valid d0 s1 (warm)");
// C: salt effect on H
await trial({ ...base, decision: 0, salt: 2 }, "C salt=2");
// B: trap — VK mismatch should make REJECT(1) correct, APPROVE(0) wrong
await trial({ ...base, proofVkHash: 2, decision: 1, salt: 1 }, "B1 vkMismatch d1(REJECT?)");
await trial({ ...base, proofVkHash: 2, decision: 0, salt: 1 }, "B2 vkMismatch d0(APPROVE?)");
// B3: threshold trap — balance < minimum
await trial({ ...base, publicBalance: 0, decision: 1, salt: 1 }, "B3 balance0 d1");
