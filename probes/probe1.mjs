import * as snarkjs from "snarkjs";
try {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve({}, "artifacts/gatekeeper.wasm", "artifacts/gatekeeper_final.zkey");
  console.log("PROVED with empty input?! publicSignals:", publicSignals);
} catch (e) {
  console.log("ERROR:", String(e && e.message || e).slice(0, 800));
}
