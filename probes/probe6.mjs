import * as snarkjs from "snarkjs";
const base = {registeredVkHash:1,proofVkHash:1,minimum:1,publicBalance:1,expiryBlock:1,currentBlock:1,recipient:1,conditionRecipient:1,amount:1,maxTransfer:1,taskId:1};
async function trial(input, label) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, "artifacts/gatekeeper.wasm", "artifacts/gatekeeper_final.zkey");
    const vk = JSON.parse((await import("fs")).readFileSync("artifacts/vk.json","utf8"));
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(label, "=> WITNESS OK, proof verifies:", ok, "publicSignals:", JSON.stringify(publicSignals));
    return true;
  } catch (e) {
    const m = String(e && e.message || e).replace(/\n/g," ").slice(0, 200);
    console.log(label, "=> FAIL:", m);
    return false;
  }
}
for (const d of [0, 1]) {
  for (const s of [0, 1, 2, 12345]) {
    await trial({ ...base, decision: d, salt: s }, `decision=${d} salt=${s}`);
  }
}
