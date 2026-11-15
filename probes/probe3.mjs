import * as snarkjs from "snarkjs";
for (const input of [{decision: 1}, {task_id: 1}, {nonsense_xyz: 1}]) {
  try {
    await snarkjs.groth16.fullProve(input, "artifacts/gatekeeper.wasm", "artifacts/gatekeeper_final.zkey");
    console.log(JSON.stringify(input), "-> PROVED?!");
  } catch (e) {
    console.log(JSON.stringify(input), "->", String(e && e.message || e).slice(0, 200));
  }
}
