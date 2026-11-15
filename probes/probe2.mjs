import { readFileSync } from "fs";
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const wcBuilder = require("circom_runtime").WitnessCalculatorBuilder;
const { fnvHash } = require("./node_modules/circom_runtime/js/utils.js");

const candidates = [
  "task_id","taskId","taskHash","type","mode","issued_at","deadline_at","nonce",
  "registered_vk","registeredVk","proof_vk","proofVk","vk",
  "minimum","public_balance","publicBalance","balance","threshold",
  "expiry_block","expiryBlock","current_block","currentBlock",
  "recipient","condition_recipient","conditionRecipient",
  "amount","max_transfer","maxTransfer","proof_tx","proofTx",
  "decision","reason_code","reasonCode","approved","isValid","valid",
  "approve","reject","result","outcome",
  "input","inputs","hash","digest","a","b","c","x","y","z",
  "in0","in1","in2","signal","value","expected","actual",
  "taskHashHex","decisionHash","commitment","nullifier",
  "min","max","limit","cap","expiry","block","height",
  "sender","from","to","token","chainId","chain_id",
  "proofRef","proof_ref","reference","ref",
  "registered_vk_hash","proof_vk_hash","vkHash","vk_hash",
  "recipientHash","conditionHash","addr","address",
  "isExpired","expired","isReused","reused","isValidVk","vkMatches",
  "balanceOk","thresholdOk","recipientOk","amountOk","expiryOk",
  "check1","check2","check3","check4","check5","check6","check7",
];
const wasm = readFileSync("artifacts/gatekeeper.wasm");
const wc = await wcBuilder(wasm);
const inst = wc.instance;
console.log("getInputSize():", inst.exports.getInputSize());
console.log("witnessSize:", inst.exports.getWitnessSize());
console.log("version:", inst.exports.getVersion());
let found = 0;
for (const name of candidates) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  const size = inst.exports.getInputSignalSize(hMSB, hLSB);
  if (size >= 0) { found++; console.log("FOUND:", name, "size:", size); }
}
console.log("total found:", found);
