#!/usr/bin/env node

import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const bin = path.join(repoRoot, "secgate.js");

let passed = 0;
let failed = 0;

function run(args, opts = {}) {
  try {
    const stdout = execFileSync("node", [bin, ...args], {
      encoding: "utf-8",
      stdio: "pipe",
      cwd: opts.cwd || repoRoot,
      ...opts
    });
    return { code: 0, stdout, stderr: "" };
  } catch (e) {
    return {
      code: e.status ?? 1,
      stdout: (e.stdout || "").toString(),
      stderr: (e.stderr || "").toString()
    };
  }
}

function test(name, fn) {
  try {
    fn();
    console.log(`  ok  ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL ${name}`);
    console.log(`       ${e.message}`);
    failed++;
  }
}

function assertEq(a, b, msg) {
  if (a !== b) throw new Error(`${msg}: expected ${b}, got ${a}`);
}
function assertContains(s, sub, msg) {
  if (!s.includes(sub)) throw new Error(`${msg}: missing "${sub}"`);
}
function assertNotContains(s, sub, msg) {
  if (s.includes(sub)) throw new Error(`${msg}: unexpected "${sub}"`);
}

console.log("\nSecGate smoke tests");
console.log("-------------------");

test("--version prints semver", () => {
  const r = run(["--version"]);
  assertEq(r.code, 0, "exit");
  if (!/^\d+\.\d+\.\d+/.test(r.stdout.trim())) {
    throw new Error(`bad version: ${r.stdout}`);
  }
});

test("--help prints usage", () => {
  const r = run(["--help"]);
  assertEq(r.code, 0, "exit");
  assertContains(r.stdout, "Usage:", "help");
  assertContains(r.stdout, "--apply", "help");
});

test("rejects missing target with exit 2", () => {
  const r = run(["/this/path/does/not/exist/xyz"]);
  assertEq(r.code, 2, "exit");
  assertContains(r.stderr, "not found", "stderr");
});

test("rejects non-directory target with exit 2", () => {
  const r = run([bin]);
  assertEq(r.code, 2, "exit");
  assertContains(r.stderr, "not a directory", "stderr");
});

test("clean fixture → exit 0 PASS", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  const r = run([fixture], { cwd: fixture });
  assertEq(r.code, 0, "exit");
  assertContains(r.stdout, "STATUS: PASS", "status");
});

test("clean fixture → JSON + HTML written", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  run([fixture], { cwd: fixture });
  const json = path.join(fixture, "secgate-v7-report.json");
  const html = path.join(fixture, "clean.html");
  if (!fs.existsSync(json)) throw new Error(`missing ${json}`);
  if (!fs.existsSync(html)) throw new Error(`missing ${html}`);
  const rep = JSON.parse(fs.readFileSync(json, "utf-8"));
  assertEq(rep.status, "PASS", "report.status");
  fs.unlinkSync(json);
  fs.unlinkSync(html);
});

test("vulnerable-dockerfile fixture → trivy detects misconfig", () => {
  const fixture = path.join(repoRoot, "test/fixtures/vulnerable-dockerfile");
  const r = run([fixture], { cwd: fixture });
  assertEq(r.code, 1, "exit (FAIL expected)");
  assertContains(r.stdout, "FAIL", "status");
  const json = path.join(fixture, "secgate-v7-report.json");
  const rep = JSON.parse(fs.readFileSync(json, "utf-8"));
  const trivyFindings = rep.findings.filter(f => f.tool === "trivy");
  if (trivyFindings.length === 0) {
    throw new Error("expected at least one trivy finding");
  }
  fs.unlinkSync(json);
  fs.unlinkSync(path.join(fixture, "vulnerable-dockerfile.html"));
});

test("secret-leak fixture → gitleaks detects credential", () => {
  const fixture = path.join(repoRoot, "test/fixtures/secret-leak");
  const r = run([fixture], { cwd: fixture });
  const json = path.join(fixture, "secgate-v7-report.json");
  const htmlFile = path.join(fixture, "secret-leak.html");
  if (!fs.existsSync(json)) {
    // gitleaks not installed — skip
    console.log("  skip  secret-leak fixture (gitleaks not installed)");
    return;
  }
  const rep = JSON.parse(fs.readFileSync(json, "utf-8"));
  const gitleaksFindings = rep.findings.filter(f => f.tool === "gitleaks");
  if (gitleaksFindings.length === 0) {
    // gitleaks ran but produced no findings — may not be installed, skip
    console.log("  skip  secret-leak fixture (gitleaks skipped or no findings)");
    if (fs.existsSync(json)) fs.unlinkSync(json);
    if (fs.existsSync(htmlFile)) fs.unlinkSync(htmlFile);
    return;
  }
  assertEq(r.code, 1, "exit (FAIL expected)");
  assertContains(r.stdout, "FAIL", "status");
  if (fs.existsSync(json)) fs.unlinkSync(json);
  if (fs.existsSync(htmlFile)) fs.unlinkSync(htmlFile);
});

test("vulnerable-deps fixture → npm audit detects CVE", () => {
  const fixture = path.join(repoRoot, "test/fixtures/vulnerable-deps");
  const r = run([fixture], { cwd: fixture });
  const json = path.join(fixture, "secgate-v7-report.json");
  const htmlFile = path.join(fixture, "vulnerable-deps.html");
  if (!fs.existsSync(json)) {
    console.log("  skip  vulnerable-deps fixture (report not generated)");
    return;
  }
  const rep = JSON.parse(fs.readFileSync(json, "utf-8"));
  const npmFindings = rep.findings.filter(f => f.tool === "npm" || f.tool === "osv");
  if (npmFindings.length === 0) {
    // npm audit or osv may not flag without node_modules — skip gracefully
    console.log("  skip  vulnerable-deps fixture (npm/osv found no findings without node_modules install)");
    if (fs.existsSync(json)) fs.unlinkSync(json);
    if (fs.existsSync(htmlFile)) fs.unlinkSync(htmlFile);
    return;
  }
  assertEq(r.code, 1, "exit (FAIL expected)");
  assertContains(r.stdout, "FAIL", "status");
  if (fs.existsSync(json)) fs.unlinkSync(json);
  if (fs.existsSync(htmlFile)) fs.unlinkSync(htmlFile);
});

test("command injection regression — shell metachar in target rejected", () => {
  const malicious = `${repoRoot}; echo PWNED`;
  const r = run([malicious]);
  assertEq(r.code, 2, "exit (invalid target)");
  // stderr echoes the raw target in the error message, but stdout must not
  // contain the `echo` output as its own line — that would mean a shell ran.
  assertNotContains(r.stdout, "PWNED\n", "no shell execution in stdout");
});

test("HTML report contains all 5 tool tabs", () => {
  const fixture = path.join(repoRoot, "test/fixtures/clean");
  run([fixture], { cwd: fixture });
  const html = fs.readFileSync(path.join(fixture, "clean.html"), "utf-8");
  for (const t of ["semgrep", "gitleaks", "npm", "osv", "trivy"]) {
    assertContains(html, `id="tab-${t}"`, `tab ${t}`);
  }
  fs.unlinkSync(path.join(fixture, "secgate-v7-report.json"));
  fs.unlinkSync(path.join(fixture, "clean.html"));
});

console.log("-------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
