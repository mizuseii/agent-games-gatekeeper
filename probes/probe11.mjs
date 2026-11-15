import * as snarkjs from "snarkjs";
const base = {registeredVkHash:1,proofVkHash:1,minimum:1,publicBalance:1,expiryBlock:1,currentBlock:1,recipient:1,conditionRecipient:1,amount:1,maxTransfer:1,taskId:1,salt:1};
async function trial(input, label) {
  try {
    await snarkjs.groth16.fullProve(input, "artifacts/gatekeeper.wasm", "artifacts/gatekeeper_final.zkey");
    console.log(label, "=> PROVES");
  } catch (e) {
    console.log(label, "=> fail:", String(e && e.message || e).replace(/\n/g," ").slice(0,80));
  }
}
// expiry/current matrix x decision
for (const [e,c] of [[5,1],[1,5],[5,5],[2,1],[1,2],[10,1]]) {
  await trial({ ...base, expiryBlock:e, currentBlock:c, decision:0 }, `exp=${e} cur=${c} d=0`);
  await trial({ ...base, expiryBlock:e, currentBlock:c, decision:1 }, `exp=${e} cur=${c} d=1`);
}
// does VK mismatch flip expected decision when expiry<=current?
await trial({ ...base, proofVkHash:2, expiryBlock:1, currentBlock:5, decision:1 }, "vkMismatch exp<=cur d=1");
await trial({ ...base, proofVkHash:2, expiryBlock:1, currentBlock:5, decision:0 }, "vkMismatch exp<=cur d=0");
