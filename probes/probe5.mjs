import * as snarkjs from "snarkjs";
const candidates = [
  "proofTxHash","proofHash","txHash","proofReference","reference","refHash",
  "taskIdHash","taskHash","recipientHash","decisionHash","payloadHash","envelopeHash",
  "inputHash","inputsHash","stateHash","publicInputHash",
  "salt","domain","domainId","chainId","version","circuitVersion","eventId","agentId","agent_id",
  "expectedDecision","correctDecision","isCorrect","correct","verified","finalized","onChain",
  "proofValid","isValidProof","proofOk","timestamp","issuedAt","deadlineAt","deadline",
  "score","points","nonce","round","roundId","mode2","type2",
  "nullifier","commitment","secret","trap","trapType","errorCode","code","reasonEnum",
  "decisionReason","rejectionReason","decisionValue","decisionCode",
  "minBalance","maxAmount","transferAmount","requestedAmount","requested",
  "blockNumber","currentHeight","expiryHeight","expiryTime","issued","deadlineBlock",
  "from","sender","to","token","amount2","value","limit2","cap2",
  "publicKey","pubkey","signer","authority","owner","creator",
  "proofSystem","circuit","circuitId","circuitHash","vkRegistered",
  "registeredVk","proofVk","proofTx2","tx","hash2","h","input1",
  "expected","expectedOutcome","groundTruth","label","answer",
  "validCondition","isValidCondition","conditionValid","conditionOk",
  "thresholdMet","recipientMatch","amountWithinCap","notExpired","notReused","vkMatch",
];
const valid = {decision:1,registeredVkHash:1,proofVkHash:1,minimum:1,publicBalance:1,expiryBlock:1,currentBlock:1,recipient:1,conditionRecipient:1,amount:1,maxTransfer:1,taskId:1};
let count = 12;
const hits = [];
for (const name of candidates) {
  const trial = { ...valid, [name]: 1 };
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(trial, "artifacts/gatekeeper.wasm", "artifacts/gatekeeper_final.zkey");
    hits.push([name, "PROVED! publicSignals=" + JSON.stringify(publicSignals)]);
  } catch (e) {
    const m = String(e && e.message || e);
    if (/Not all inputs have been set\. Only (\d+) out of 13/.test(m)) {
      const n = +m.match(/Only (\d+) out of/)[1];
      if (n > count) { hits.push([name, `VALID (count ${n})`]); valid[name] = 1; count = n; }
    } else if (/Not enough values for input signal/.test(m)) {
      hits.push([name, "VALID ARRAY"]);
    } else if (/Assert Failed/.test(m)) {
      hits.push([name, "VALID but circuit assert failed (wrong values?)"]);
    } else if (!/Too many values/.test(m)) {
      hits.push([name, "OTHER: " + m.slice(0, 150)]);
    }
  }
}
console.log("count now:", count, "valid:", JSON.stringify(Object.keys(valid)));
for (const [n, r] of hits) console.log(n, "->", r);
