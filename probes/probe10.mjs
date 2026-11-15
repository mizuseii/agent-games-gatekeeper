import * as snarkjs from "snarkjs";
const fs = await import("fs");
const vk = JSON.parse(fs.readFileSync("artifacts/vk.json","utf8"));
const base = {registeredVkHash:1,proofVkHash:1,minimum:1,publicBalance:1,expiryBlock:1,currentBlock:1,recipient:1,conditionRecipient:1,amount:1,maxTransfer:1,taskId:1,decision:0,salt:1};
async function trial(input, label) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, "artifacts/gatekeeper.wasm", "artifacts/gatekeeper_final.zkey");
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(label, "=> OK verify="+ok, "pub:", JSON.stringify(publicSignals.map(s=>String(s).slice(0,12))));
    return publicSignals;
  } catch (e) {
    console.log(label, "=> FAIL:", String(e && e.message || e).replace(/\n/g," ").slice(0,100));
    return null;
  }
}
// Map each input to its public-signal position (distinctive values)
const vars = [["minimum",11],["publicBalance",12],["expiryBlock",13],["currentBlock",14],["recipient",15],["conditionRecipient",16],["amount",17],["maxTransfer",18],["taskId",19],["registeredVkHash",20],["proofVkHash",21],["salt",22]];
for (const [k,v] of vars) await trial({ ...base, [k]: v }, `vary ${k}=${v}`);
// d=1 across trap matrix
await trial({ ...base, proofVkHash: 2, decision: 1 }, "d1 vkMismatch");
await trial({ ...base, publicBalance: 0, decision: 1 }, "d1 balance0");
await trial({ ...base, recipient: 5, decision: 1 }, "d1 recipientMismatch");
await trial({ ...base, currentBlock: 99, decision: 1 }, "d1 expired");
await trial({ ...base, amount: 99, decision: 1 }, "d1 amountOverflow");
await trial({ ...base, decision: 2 }, "d2 allpass");
