import * as snarkjs from "snarkjs";
const candidates = [
  "decision","reason_code","reasonCode","reason","result","outcome","approved","approve","reject",
  "registered_vk","registeredVk","registered_vk_hash","registeredVkHash",
  "proof_vk","proofVk","proof_vk_hash","proofVkHash","vk","vkHash","vk_hash",
  "minimum","min","public_balance","publicBalance","balance","threshold",
  "expiry_block","expiryBlock","current_block","currentBlock","expiry","block",
  "recipient","condition_recipient","conditionRecipient",
  "amount","max_transfer","maxTransfer","proof_tx","proofTx","proofRef","proof_ref",
  "task_id","taskId","taskHash","task_hash","inputHash","input_hash","decisionHash",
  "mode","type","issued_at","deadline_at","nonce","hash","digest",
  "isValid","valid","is_valid","check","checks",
  "a","b","c","x","in","in0","out","publicSignals",
  "sender","from","to","token","chainId","address","addr",
  "isExpired","isReused","vkMatches","balanceOk","thresholdOk","recipientOk","amountOk","expiryOk",
  "expected","actual","value","limit","cap","condition","conditionHash",
];
const valid = {};
let count = 0;
const results = [];
for (const name of candidates) {
  const trial = { ...valid, [name]: 1 };
  try {
    await snarkjs.groth16.fullProve(trial, "artifacts/gatekeeper.wasm", "artifacts/gatekeeper_final.zkey");
    results.push([name, "PROVED?!"]); valid[name] = 1; count++;
  } catch (e) {
    const m = String(e && e.message || e);
    if (/Not all inputs have been set\. Only (\d+) out of 13/.test(m)) {
      const n = +m.match(/Only (\d+) out of/)[1];
      if (n > count) { results.push([name, `VALID scalar (count ${n})`]); valid[name] = 1; count = n; }
      else results.push([name, `no-increment (n=${n})`]);
    } else if (/Not enough values for input signal/.test(m)) {
      results.push([name, "VALID ARRAY — needs size probe"]); valid[name] = 1; // tentative
    } else if (/Too many values/.test(m)) {
      results.push([name, "invalid"]);
    } else {
      results.push([name, "OTHER: " + m.slice(0, 120)]);
    }
  }
}
console.log("=== VALID SO FAR ===");
console.log(JSON.stringify(valid), "count:", count);
console.log("=== DETAIL ===");
for (const [n, r] of results) if (!r.startsWith("invalid")) console.log(n, "->", r);
