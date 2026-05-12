// Verifies that scanner invocations honor a timeout — a hung/wedged tool must
// be killed, not block SecGate forever. See lib/utils.mjs DEFAULT_TOOL_TIMEOUT_MS.
import assert from "node:assert/strict";
import { runTool, runToolAsync, DEFAULT_TOOL_TIMEOUT_MS } from "../lib/utils.mjs";

assert.equal(DEFAULT_TOOL_TIMEOUT_MS, 180_000, "default tool timeout should be 180s");

// A child that would otherwise run for 30s, with an explicit short timeout.
const node = process.execPath;
const hangArgs = ["-e", "setTimeout(() => {}, 30_000)"];

{
  const t0 = Date.now();
  const out = await runToolAsync(node, hangArgs, { timeout: 400 });
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 5_000, `runToolAsync should be killed near 400ms, took ${elapsed}ms`);
  assert.equal(out, "", "timed-out tool yields empty stdout");
}

{
  const t0 = Date.now();
  const out = runTool(node, hangArgs, { timeout: 400 });
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 5_000, `runTool should be killed near 400ms, took ${elapsed}ms`);
  assert.equal(out, "", "timed-out tool yields empty stdout");
}

console.log("✓ runTool / runToolAsync honor timeout (default 180s, overridable)");
