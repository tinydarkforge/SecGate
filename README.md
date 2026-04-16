# 🛡️ SEC GATE v7 — AI SOC Engine

SEC GATE v7 is an autonomous **security scanning and remediation engine** designed for modern CI/CD pipelines.

It combines:
- Static Application Security Testing (SAST)
- Secret detection
- Dependency vulnerability analysis
- AI-driven risk reasoning
- Automated remediation planning

---

## 🚀 Features

### 🔍 Multi-layer Security Scanning
- **Semgrep** → static code analysis (SAST)
- **Gitleaks** → secret detection (API keys, credentials, tokens)
- **npm audit** → dependency vulnerability scanning

### 🧠 AI-Driven Intelligence Layer
- Risk scoring engine
- Attack surface classification
- Exploitability reasoning
- Security recommendations engine

### 🛠️ Remediation Engine
- Auto-generated fix plans
- Safe staged remediation workflow
- Optional auto-execution mode (`--apply`)
- Confidence scoring for decision-making

### ⚙️ CI/CD Ready
- Exit codes for pipeline blocking
- JSON report output
- Deterministic execution
- Works in GitHub Actions / GitLab CI / Jenkins

---

## 📦 Installation

### 1. Clone repository
```bash
git clone https://github.com/your-org/secgate.git
cd secgate
