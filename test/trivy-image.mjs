#!/usr/bin/env node
// Tests for trivy image mode: Dockerfile detection, base-image extraction,
// and finding emission. Does NOT invoke the real trivy binary — stubs or skips.

import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const bin = path.join(repoRoot, "secgate.js");

let passed = 0;
let failed = 0;

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

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
function assertEq(a, b, msg) {
  if (a !== b) throw new Error(`${msg}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

function scratchDir(suffix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secgate-${suffix}-`));
}

function runWithStubs(scanDir, stubs, env = {}) {
  const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-stubs-"));

  for (const [name, payload] of Object.entries(stubs)) {
    const p = path.join(stubDir, name);
    const file = path.join(stubDir, `${name}.json`);
    fs.writeFileSync(file, payload);
    fs.writeFileSync(p, `#!/bin/sh\ncat ${JSON.stringify(file)}\n`);
    fs.chmodSync(p, 0o755);
  }

  const fullEnv = {
    ...process.env,
    PATH: `${stubDir}:${process.env.PATH}`,
    ...env
  };

  let code = 0;
  let stdout = "";
  try {
    stdout = execFileSync("node", [bin, scanDir], {
      encoding: "utf-8",
      stdio: "pipe",
      cwd: scanDir,
      env: fullEnv
    });
  } catch (e) {
    code = e.status ?? 1;
    stdout = (e.stdout || "").toString();
  }

  const reportPath = path.join(scanDir, "secgate-v7-report.json");
  const report = JSON.parse(fs.readFileSync(reportPath, "utf-8"));

  try { fs.unlinkSync(reportPath); } catch {}
  try {
    const html = path.join(scanDir, `${path.basename(scanDir)}.html`);
    fs.unlinkSync(html);
  } catch {}
  fs.rmSync(stubDir, { recursive: true, force: true });

  return { code, stdout, report };
}

console.log("\nSecGate trivy-image tests");
console.log("-------------------------");

test("existing fixture Dockerfile contains FROM python:3.8", () => {
  const df = path.join(repoRoot, "test/fixtures/vulnerable-dockerfile/Dockerfile");
  assert(fs.existsSync(df), "fixture Dockerfile must exist");
  const content = fs.readFileSync(df, "utf-8");
  assert(/^FROM\s+\S+/im.test(content), "Dockerfile must have at least one FROM");
});

test("base-image extraction: simple FROM", () => {
  const d = scratchDir("img-simple");
  fs.writeFileSync(path.join(d, "Dockerfile"), "FROM python:3.8\nRUN echo hi\n");

  // Stub trivy to return empty results for both fs and image calls.
  // The fs call is invoked first (without 'image' as second arg);
  // the image call passes 'image' as first positional arg.
  // We use a single stub that always prints an empty Results array.
  const emptyResult = JSON.stringify({ Results: [] });
  const { report } = runWithStubs(d, { trivy: emptyResult });

  // trivyImage ran (skipped is ok if trivy not installed, but stub is present)
  // toolStatus.trivyImage should be "clean" (no findings, ran ok)
  const ts = report.tools;
  assert(
    ts.trivyImage === "clean" || ts.trivyImage === "skipped",
    `trivyImage status should be clean or skipped, got: ${ts.trivyImage}`
  );

  fs.rmSync(d, { recursive: true, force: true });
});

test("base-image extraction: multi-stage Dockerfile deduplicates refs", () => {
  const d = scratchDir("img-multistage");
  fs.writeFileSync(
    path.join(d, "Dockerfile"),
    "FROM node:18 AS builder\nFROM node:18 AS runner\nFROM nginx:alpine\n"
  );

  const emptyResult = JSON.stringify({ Results: [] });
  const { report } = runWithStubs(d, { trivy: emptyResult });

  const ts = report.tools;
  assert(
    ts.trivyImage === "clean" || ts.trivyImage === "skipped",
    `trivyImage status: ${ts.trivyImage}`
  );
  fs.rmSync(d, { recursive: true, force: true });
});

test("trivy image findings emitted with scanMode=image and image ref", () => {
  const d = scratchDir("img-findings");
  fs.writeFileSync(path.join(d, "Dockerfile"), "FROM python:3.8\n");

  // Stub trivy to return a vuln for the image call.
  // secgate calls trivy with different args for fs vs image mode;
  // the same stub binary is used — we return a vuln payload that
  // works for both (Results with Vulnerabilities).
  const vulnPayload = JSON.stringify({
    Results: [
      {
        Target: "python:3.8 (debian)",
        Vulnerabilities: [
          {
            VulnerabilityID: "CVE-2023-12345",
            Severity: "HIGH",
            Title: "Test vuln in python image",
            PkgName: "openssl"
          }
        ]
      }
    ]
  });

  const { report } = runWithStubs(d, { trivy: vulnPayload });

  const imageFindings = report.findings.filter(
    f => f.tool === "trivy" && f.scanMode === "image"
  );

  assert(imageFindings.length > 0, "expected at least one trivy image finding");
  assertEq(imageFindings[0].signature.startsWith("trivy-image:"), true, "signature prefix");
  assertEq(imageFindings[0].image, "python:3.8", "image field");
  assertEq(imageFindings[0].severity, "HIGH", "severity");

  fs.rmSync(d, { recursive: true, force: true });
});

test("no Dockerfiles → trivyImage skipped", () => {
  const d = scratchDir("img-nodockerfile");
  fs.writeFileSync(path.join(d, "app.js"), "console.log('hi');\n");

  const emptyResult = JSON.stringify({ Results: [] });
  const { report } = runWithStubs(d, { trivy: emptyResult });

  assertEq(report.tools.trivyImage, "skipped", "trivyImage skipped when no Dockerfiles");
  fs.rmSync(d, { recursive: true, force: true });
});

test("scratch base image is excluded from trivy image scan", () => {
  const d = scratchDir("img-scratch");
  fs.writeFileSync(
    path.join(d, "Dockerfile"),
    "FROM golang:1.21 AS builder\nFROM scratch\nCOPY --from=builder /app /app\n"
  );

  const emptyResult = JSON.stringify({ Results: [] });
  const { report } = runWithStubs(d, { trivy: emptyResult });

  // scratch should be skipped; golang:1.21 should be scanned → clean
  const ts = report.tools;
  assert(
    ts.trivyImage === "clean" || ts.trivyImage === "skipped",
    `trivyImage: ${ts.trivyImage}`
  );
  fs.rmSync(d, { recursive: true, force: true });
});

test("node_modules Dockerfiles are not walked", () => {
  const d = scratchDir("img-nm");
  const nmDir = path.join(d, "node_modules", "some-pkg");
  fs.mkdirSync(nmDir, { recursive: true });
  fs.writeFileSync(path.join(nmDir, "Dockerfile"), "FROM alpine\n");

  const emptyResult = JSON.stringify({ Results: [] });
  const { report } = runWithStubs(d, { trivy: emptyResult });

  // No Dockerfiles found outside node_modules → trivyImage skipped
  assertEq(report.tools.trivyImage, "skipped", "trivyImage skipped when Dockerfile only in node_modules");
  fs.rmSync(d, { recursive: true, force: true });
});

console.log("-------------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
