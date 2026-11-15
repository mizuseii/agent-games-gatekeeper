import * as snarkjs from "snarkjs";
const base = {registeredVkHash:1,proofVkHash:1,minimum:1,publicBalance:1,expiryBlock:1,currentBlock:1,recipient:1,conditionRecipient:1,amount:1,maxTransfer:1,taskId:1};
console.log("starting trial decision=1 salt=1 at", new Date().toISOString());
try {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve({ ...base, decision: 1, salt: 1 }, "artifacts/gatekeeper.wasm", "artifacts/gatekeeper_final.zkey");
  console.log("PROVED. publicSignals:", JSON.stringify(publicSignals));
} catch (e) {
  console.log("FAIL:", String(e && e.message || e).replace(/\n/g," ").slice(0, 300));
}
console.log("done at", new Date().toISOString());
