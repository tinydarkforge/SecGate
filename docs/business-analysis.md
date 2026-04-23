# SecGate / Lucen — Business Analysis
**Date:** 2026-04-22
**Status:** Pre-build strategy. Lucen v0.0.0. SecGate prototype.

---

## North Star Positioning

> **"The fastest way in the world to understand a codebase."**

Everything serves this. If a feature doesn't make understanding faster, cut it.

Tool-land = death. Outcome-land = win.

### Wedge Sentence (use as marketing copy)

> **"I shipped AI code I don't understand."**

This sentence = pain + urgency + buyer. Every landing page headline, DM, and ad copy should evoke this.

### What Market Actually Buys

Not code intelligence. Not ASTs. Not MCP servers.

**Relief under pressure.**

- Investor asking for architecture → pressure
- New contractor needs onboarding → pressure
- Acquirer demands diligence → pressure
- Production broke, nobody knows code → pressure

Product = relief delivered in 60 seconds. Tech = invisible plumbing.

---

## What Was Built

### SecGate
- Node.js CLI wrapping Semgrep + Gitleaks + npm audit
- Weighted scoring loop + hardcoded strings (no LLM calls)
- "AI SOC Engine" is marketing language — scan orchestration is real, AI label is not
- ~300 lines of scan logic. Works. Not yet production-ready.

### Lucen
- Separate TypeScript monorepo (core, CLI, MCP packages)
- AST parsing via tree-sitter, symbol search, call graphs, code explanation
- MCP server with tools: `search_symbols`, `call_graph`, `risks_for_path`, `explain_module`
- **v0.0.0 — core engine not built yet**

**Neither is production-ready.** All strategy below is pre-build.

---

## Two-Product Reality

| | **Lucen** (primary, build now) | **SecGate** (enterprise extension, later) |
|---|---|---|
| Buyer | Vibe coders, indie hackers, small teams | Series A startup CTOs |
| Pain | "I shipped AI code I don't understand" | "I need SOC 2 evidence" |
| Price | $19–$399/mo | $299–$999/mo |
| ACV | $350/yr | $8.4k/yr |
| Distribution | Self-serve, viral, MCP | Founder-led, demo calls |
| Time to revenue | 1–3 months | 6–12 months |
| Build effort | Lucen core engine + UI | Workflow + integrations |

**Decision:** Ship Lucen first. Generate distribution + learnings. SecGate becomes the enterprise tier once Lucen has a userbase.

---

## ICP — Lucen (Primary)

**AI-coded solo founders + micro teams (1–10 people).**

Profile:
- Built with Cursor / Lovable / v0 / Bolt / Replit Agent / Claude
- Code works. They cannot fully explain it.
- Pain hits when: bug to fix, dev to onboard, business to sell, investor due diligence, user-facing crash

Adjacent ICPs:
- Fractional CTOs juggling 5 client codebases
- Dev agencies inheriting vibe-coded handoffs
- M&A brokers selling micro-SaaS (different unit economics — see below)

**Where they live:**
- Cursor Discord, Lovable community
- Reddit: r/SideProject, r/IndieDev, r/cursor, r/ChatGPTCoding, r/nocode
- Twitter/X "build in public" community
- Product Hunt, Hacker News
- AppSumo (LTD audience)

---

## Market Reality

### Saturated Space (avoid)
Pure code analysis + scanning + docs is bloodbath:

| Competitor | Moat |
|------------|------|
| Snyk | Series F $8.5B, free tier, mindshare |
| GitHub GHAS | Bundled free with GitHub Enterprise |
| SonarQube | Category leader, acquired |
| Semgrep SaaS | Lucen wraps Semgrep — they have hosted offering |
| Mintlify / Swimm / CodeSee | Venture-backed docs space |
| Vanta / Drata | Compliance, $10–50k/yr, heavy sales |
| Sourcegraph | Code search/intelligence incumbent |
| **Cursor / GitHub (incoming)** | **Will ship "explain my codebase" natively in 6–12 months** |

### Real Gaps Worth Pursuing

1. **Vibe coder explanation gap** — none of the above target non-technical AI-native founders well
2. **M&A / due diligence** — buyers + brokers pay $500–$2k per code-health report
3. **One-shot pressure events** — investor diligence, contractor onboarding, acquisition handoff. 25% of revenue (validated). One-off buyers won't subscribe.
4. **Compliance evidence workflow (SecGate path, later)** — Vanta/Drata bolt scanning on as afterthought

---

## Validation Step (Before Writing More Code)

**Talk to 10 vibe coders.** Show CLI mockup or 60-second demo. Ask:

> "If you could paste your repo URL and get an architecture map, plain-English module summary, and risk overview in 60 seconds — what would you pay per month?"

Then ask:
> "What would make this a 'must have' vs 'nice to have' for you?"

Two hours of calls. Beats six months of building wrong thing.

**Channels for these calls:**
- DM 50 indie hackers on Twitter/X
- Post in r/SideProject + Cursor Discord asking for 15-min calls
- Offer $20 Amazon gift card per call to filter serious responses

**Stop building until 10 calls done.** Pricing tiers without usage data = guessing.

### Validation Findings (20-persona pressure test)

⚠️ **This is structured guessing, not validation.** Real validation = 10 strangers swiping credit cards. Treat as sanity check on direction, not proof of demand.

Simulated 20 vibe coders under pressure scenarios (boss/client/investor demands). Key signals:

| Signal | Number | Implication |
|--------|--------|-------------|
| Will pay something | 17/20 (85% intent) | Real conversion ~30–40% of free tier |
| Pay $19–$49/mo | 9/20 | Bulk of subscription MRR |
| Pay $99–$399/mo | 6/20 | Teams + agencies = high-value seg |
| Won't pay (wrong ICP / ChatGPT good enough) | 3/20 | 15% leakage acceptable |
| **Want one-shot reports ($79–$999)** | **6/20** | **Missing tier — 25% of revenue** |
| Need white-label exports (agency) | 3/20 | Day-one requirement for agency tier |
| Want platform integrations (Lovable/Replit/Cursor) | 3/20 | Phase 3 priority |
| Need Slack + weekly auto-reports | 2/20 | Phase 5 team-champion trigger |
| Want compliance bridge ($799/mo) | 2/20 | New tier between Agency and Enterprise |

---

## Pricing Model — Lucen

### Tiers (emotional positioning, hide limits as guardrails)

| Tier | Tagline | Price | What's included |
|------|---------|-------|-----------------|
| **Free** | "Understand any repo locally" | $0 | CLI + MCP + IDE ext, 1 repo, local-only, no AI explanations |
| **Solo** | "Understand any repo instantly" | $19/mo | Unlimited repos, web app, AI explanations, cloud backup |
| **Pro** | "Ship faster with AI insights" | $49/mo | Priority parsing, PDF/HTML exports, GitHub App, deeper AI |
| **Team** | "Shared code intelligence for your team" | $149/mo | 5 seats, shared workspace, Slack bot, weekly auto-reports |
| **Agency** | "Multi-client codebase intelligence" | $399/mo | 20 seats, multi-tenant, **white-label exports (mandatory)** |
| **Compliance Bridge** | "Audit-ready code documentation" | $799/mo | Agency features + control mapping + auditor-friendly PDFs |
| **API** | "Lucen as infrastructure" | $0.002/query + $0.10/repo indexed | CI/CD, automation |
| **Enterprise / SecGate** | "SOC 2 evidence workflow" | Custom $2k+/mo | On-prem, BAA, full compliance workflow (year 2) |

### One-Shot Reports — Revenue Reality

**Early stage (months 1–6): 60–80% of revenue.**
**Steady state (month 12+): 25% of revenue.**

Why front-loaded: subscriptions need trust + habit. Neither exists yet. Pressure events need neither — they need relief now.

| Report | Price | Use case | Manual delivery time |
|--------|-------|----------|----------------------|
| **Onboarding Handoff** | $79 | Hand to new contractor/dev | 1 hr |
| **Investor Diligence** | $199 | Tech overview for fundraise/investor | 2 hr |
| **M&A Due Diligence** | $499 | Buyer-ready codebase health PDF | 4 hr |
| **Acquisition Handoff** | $999 | Full architecture + deps + risks bundle for acquirer | 6 hr |

Manual delivery margin per hour: $79–$166/hr. Justifies "do things that don't scale" Phase 0.5.

One-shot buyers won't subscribe — they have one event, one need. Capture them or lose them.

### Why these prices work

- Free tier = distribution, costs you ~$0 (local-only)
- $19 = under "no-decision" threshold for indie hackers
- One-shot tiers capture pressure-event buyers (25% of demand) who refuse subscriptions
- $799 Compliance Bridge sits between Agency and SecGate Enterprise — natural upgrade path
- Agency $399 = stays viable until 50+ paying agencies, then raise to $599–$799
- White-label MUST ship with Agency tier or it dies on day one

### Pricing formula

```
monthly_price = (storage + AI_calls + parse_compute) × 5  → 80% gross margin
```

### Cost per user (approx)

| Tier | Your cost/mo | Margin |
|------|-------------|--------|
| Free | ~$0 | infinite |
| Solo $19 | ~$3 | 84% |
| Team $149 | ~$15 | 90% |
| API | $0.0005–$0.03/query | 75–95% |

---

## Manual Report Spec (Phase 0.5 deliverable)

Before any automation, hand-deliver these. Define the spec NOW so output is consistent.

### Universal Sections (all tiers)

1. **TL;DR** — 3 bullets. What this codebase is. What works. What's broken.
2. **Architecture map** — visual diagram (Mermaid or hand-drawn), modules + relationships
3. **Tech stack** — languages, frameworks, key deps with versions
4. **Top 5 risks** — brutal honesty. Security, scalability, maintenance, legal.
5. **What to read first** — file-by-file priority list for new dev
6. **Production readiness verdict** — yes/no/conditional + reasoning

### Tier-Specific Additions

| Tier | Extra sections |
|------|----------------|
| **$79 Onboarding** | Module deep-dives (3 critical files), local setup steps, common gotchas |
| **$199 Investor** | Code quality score, team size estimate, technical debt $$ estimate, comparison to industry norms |
| **$499 M&A** | Full dependency audit, license compliance, security scan, refactor cost estimate, IP risk flags |
| **$999 Acquisition** | All M&A + complete architectural rewrite path, hire profile recommendations, 90-day handoff plan |

### Format
- Branded PDF (10–25 pages depending on tier)
- Plain English (audience: non-technical founder reading aloud to investor)
- Markdown source committed to client's repo (optional)
- Delivery: email + Stripe receipt

### Brutal Honesty Rule
If code is bad, say so. "This is held together with duct tape and prayer" is fine if true. Reputation = honest assessments. Sugar-coated reports = no referrals.

---

## Distribution Strategy — 5 Surfaces, 1 Engine

```
        ┌─────────────────────────────────┐
        │      Lucen Core Engine          │
        │  (tree-sitter + SQLite index)   │
        └──────────────┬──────────────────┘
                       │
   ┌──────────┬────────┼────────┬──────────┬──────────┐
   ▼          ▼        ▼        ▼          ▼          ▼
  CLI       MCP     Web App  GitHub    IDE Ext    REST API
 (free)   (free)   (paid)    App       (free)    (metered)
                            (paid)
```

| Surface | Audience | Tier | Why |
|---------|----------|------|-----|
| CLI | Devs | Free | npm/GitHub viral distribution |
| MCP server | Cursor/Claude users | Free | Land grab before Cursor ships native |
| IDE extension | Cursor/VSCode | Free | Passive distribution |
| Web app | Non-technical founders | Paid | "Paste GitHub URL, see magic" |
| GitHub App | Teams | Paid | Auto-reindex on push, sticky |
| REST API | Agencies, automation | Metered | Infrastructure layer play |

**MCP is distribution speed, not lock-in.** MCP is open standard — zero switching cost. Push it because adoption velocity matters, not because it traps users.

### Concrete Channel Plan

**First 100 customers (Phase 0.5 — manual delivery):**

1. **Direct DM** — highest ROI. Script:
   ```
   Hey — quick question.

   If you had to explain your codebase to an investor tomorrow, could you?

   I built a tool that turns any repo into a 1-page breakdown
   (architecture, risks, what to fix first).

   Want me to run yours? First one free.
   ```
   Send to: 50 indie hackers/week on Twitter/X. Close manually. Then charge.

2. **Public report seeding** — analyze 10 popular indie SaaS repos (with permission). Post:
   > *"I analyzed 10 indie SaaS repos. Here's what I found:"*
   Channels: Reddit, Twitter/X, indie communities. Drives inbound.

3. **Reddit organic posts** — r/SideProject, r/IndieDev, r/cursor, r/ChatGPTCoding, r/nocode

**Customers 101+ (Phase 4+ — self-serve):**

4. **Product Hunt launch** — coordinate with email list of 500+
5. **AppSumo LTD** — $59 lifetime → 1,000 paying users in week one
6. **Twitter/X build-in-public** thread series
7. **YouTube tutorials** — "I made AI explain my AI code"
8. **Cursor Discord + Lovable community** organic engagement
9. **Dev.to / Hashnode** technical write-ups
10. **Creator partnerships** — free Pro tier + affiliate

---

## Storage Strategy

### Index = SQLite file (~1–50MB per repo)

Three layers:

| Tier | Where lives | Who owns | Premium? |
|------|-------------|----------|----------|
| **Local** | `.lucen/index.db` in repo | User | Free |
| **Synced** | Local + cloud mirror | User + us | Paid |
| **Hosted** | Cloud only | Us | Paid (team plans) |

### Default Layout

```
.lucen/
  index.db        # gitignored — local cache
  config.json     # committed — team shares config
  summary.md      # committed — onboarding doc, human-readable
```

### Privacy Story
- **Free tier:** 100% local. No code leaves machine.
- **Paid tier:** Index synced to cloud. **Raw code never stored — only symbols, calls, summaries, embeddings.**
- This is privacy positioning for sales. Not a defensible moat (Sourcegraph/Cursor also do local).

---

## Defensibility — Honest Assessment

You currently have **distribution velocity**, not a moat. Local-first is a feature, not a fortress. Trivially copyable.

### Real Defensibility Stack (must build over time)

```
Layer 3: Data network effect
  └─ Aggregate (anonymized) "common patterns in AI-generated code"
     → unique benchmarks nobody else has
     → enterprises pay for this insight

Layer 2: Community + standard
  └─ .lucen/ format becomes de-facto for code indices
  └─ Plugins, language packs, community contributions
  └─ Brand = "the explainer"

Layer 1: Distribution velocity (what you have now)
  └─ Local-first + MCP + free tier + first-mover
  └─ Necessary but not sufficient — head start, not fortress
```

**Today: Layer 1 only.** Plan deliberately for Layers 2 and 3.

### Risk: Platform Bundling
Cursor, GitHub, or Claude Code will likely ship "explain my codebase" natively within 6–12 months.

**Defenses to build NOW:**
- Polyglot support beyond what they ship (Elixir, Rust, .NET, Erlang)
- M&A / due diligence niche they won't bother with
- Brand recognition in vibe-coder community
- Index format adoption (other tools read `.lucen/`)

---

## Build Roadmap (Priority Order)

### Phase 0: Validation (1 week)
- 10 customer discovery calls
- Mockup or 60-second video demo (no real product needed)
- Capture: would they pay, how much, what's must-have

### Phase 1: Wow Demo (2 weekends)
- Paste GitHub URL → 30 seconds later: architecture map + summary + risk overview
- Hosted, public, free
- This IS the marketing engine. Tweet-able output.

### Phase 2: Lucen Core (4–6 weeks)
- Tree-sitter parser pool (TypeScript, Python, JavaScript first)
- SQLite index schema
- CLI: `lucen analyze`, `lucen explain`, `lucen ask`
- Local-only

### Phase 3: MCP + IDE Extension (2 weeks)
- MCP server exposing tools to Cursor / Claude Code
- VSCode extension
- Distribution focus

### Phase 4: Hosted Web App + Cloud Sync (4 weeks)
- Paid tier launch
- Stripe integration
- AI explanations metered

### Phase 5: GitHub App (2 weeks)
- Auto-reindex on push
- Sticky paid feature

### Phase 4.5: One-Shot Report Tier (1 week, MUST be early)
**Validated 25% of revenue. Build alongside Phase 4.**
- $79 Onboarding Handoff (new dev/contractor)
- $199 Investor Diligence (fundraise prep)
- $499 M&A Due Diligence (broker/buyer)
- $999 Acquisition Handoff (full bundle)
- One-time Stripe checkout. No subscription required.

### Phase 5: GitHub App + Slack Bot + Weekly Auto-Reports
- Auto-reindex on push (sticky paid feature)
- Slack bot posts findings to team channel
- Weekly auto-report (validated team-champion trigger)

### Phase 6: Platform Integrations (2 weeks)
**Validated request from Lovable/Replit/Cursor users.**
- One-click connect from Lovable / Replit / Cursor projects
- Reduces friction for non-technical founders

### Phase 7 (later): SecGate Enterprise + Compliance Bridge
- $799/mo Compliance Bridge tier (between Agency and Enterprise)
- $2k+/mo SecGate Enterprise — SOC 2 evidence workflow
- Only after Lucen has 1,000+ paying users
- Hire someone with SOC 2 audit experience first

---

## Revenue Model — 12 Month Targets

### Subscription MRR

| Month | Free | Solo | Pro | Team | Agency | Compl. Bridge | MRR |
|-------|------|------|-----|------|--------|---------------|-----|
| 3 | 500 | 30 | 5 | 2 | 0 | 0 | $1,113 |
| 6 | 2,000 | 150 | 25 | 10 | 2 | 1 | $6,672 |
| 12 | 8,000 | 600 | 100 | 40 | 10 | 4 | $28,836 |

### One-Shot Report Revenue (validated +25% to subscription)

| Month | $79 onboard | $199 invest | $499 M&A | $999 acq | Report MRR |
|-------|-------------|-------------|----------|----------|------------|
| 3 | 2 | 1 | 1 | 0 | $856 |
| 6 | 8 | 4 | 4 | 1 | $4,395 |
| 12 | 25 | 12 | 12 | 3 | $13,310 |

### Combined MRR

| Month | Subscription | Reports | **Total MRR** |
|-------|--------------|---------|---------------|
| 3 | $1,113 | $856 | **$1,969** |
| 6 | $6,672 | $4,395 | **$11,067** |
| 12 | $28,836 | $13,310 | **$42,146** |

$42k MRR @ month 12 = **$506k ARR**.

**Reality check:**
- 30–40% real conversion of free tier (validated, not 85% intent)
- Possible only if distribution hits
- Default outcome without viral moment = **$5k–$12k MRR** (subscription + reports combined)
- One-shot reports = floor — they convert pressure events that subscription can't capture

---

## What to Charge For

| Priority | Feature | Why |
|----------|---------|-----|
| 1 | **One-shot reports ($79–$999)** | **60–80% of early revenue, 25% steady-state. Pressure-event buyers.** |
| 2 | Cloud sync / backup | Strongest subscription hook, emotional + practical |
| 3 | Web app access | Non-technical founders won't run CLI |
| 4 | AI explanations | Cheap to make, easy to value, commoditizing fast |
| 5 | PDF / HTML exports | Investor decks, M&A handoffs, agency deliverables |
| 6 | **White-label exports (Agency)** | **Day-one mandatory or agencies churn** |
| 7 | Team sharing + Slack bot + weekly auto-reports | Team-champion conversion trigger |
| 8 | GitHub App auto-reindex | Passive value, sticky |
| 9 | Platform integrations (Lovable/Replit/Cursor) | Reduces friction for non-tech founders |
| 10 | API access | Agencies + CI/CD automation |

## What NOT to Charge For

- CLI itself
- MCP server
- IDE extension
- First repo on free tier
- Public OSS repo indexing (SEO + showcase)

---

## Open Questions to Answer

1. **Validation first:** Have you talked to 10 vibe coders yet? If no — stop building, start calling.

2. **What happens when Cursor/GitHub ship native "explain my codebase"?**
   - Defense: polyglot, M&A niche, community standard, brand
   - Window: 6–12 months. Move fast.

3. **AI commoditization:** LLM costs drop 50% per year. Quality floor rises. Within 12 months, every IDE has free AI explanations.
   - Charge for **orchestration, storage, exports** — not raw AI calls
   - Reframe AI as "fast answer" not "expensive product"

4. **Lucen vs SecGate scope:** Two products, two buyers, two motions.
   - Decision: Lucen first. SecGate as enterprise tier in year 2.
   - "Dark code illumination" umbrella works for marketing — keep code separate.

5. **Why you specifically?**
   - Background story matters for early sales + trust
   - If no security/compliance background → stay in Lucen lane until 1,000+ users
   - Then hire someone with SOC 2 audit experience for SecGate launch

---

## Strategic Flow

```
Phase 0.5 — Manual Reports (do things that don't scale)
  → DM 50 founders/week with pressure-event hook
  → Run scans manually using internal CLI
  → Hand-deliver branded PDF report
  → Charge $79–$999 per report
  → 60–80% of revenue early. Validates demand with cash.
  │
  ▼
Phase 1+ — Automated Self-Serve
  Lucen CLI (free, OSS)
    → Vibe coder discovers via Reddit / Twitter / Product Hunt
    → Runs `lucen explain` on their AI-built repo
    → Sees architecture map + plain English summary
    │
    ├─→ Pressure event hits (investor / contractor / acquirer)
    │   → Buys one-shot report ($79 / $199 / $499 / $999)
    │   → 25% of revenue steady-state
    │
    └─→ Wants ongoing access
        → Upgrades to Solo $19/mo
        → Brings to team → Team $149/mo (Slack bot + weekly reports)
        → Agency adopts → Agency $399/mo (white-label mandatory)
        → Compliance need → Bridge $799/mo
        → Year 2: SecGate Enterprise $2k+/mo (SOC 2)

Manual reports prove demand with cash before any platform is built.
The CLI is the acquisition channel.
The web app + cloud sync is the subscription product.
The one-shot reports capture pressure-event buyers who refuse subscription.
The brand is "the explainer of dark code."
```

---

## TL;DR

| | |
|---|---|
| **Position** | "Fastest way to understand any codebase" |
| **Wedge sentence** | "I shipped AI code I don't understand." |
| **What buyers actually buy** | Relief under pressure |
| **Primary product** | Lucen (vibe coders, $19–$399/mo) |
| **Secondary product** | SecGate (SOC 2 enterprise, year 2) |
| **Free hook** | CLI + MCP + IDE extension |
| **Subscription hook** | Cloud sync + web app + AI explanations + exports |
| **Goldmine (early)** | One-shot reports $79–$999 — 60–80% of early revenue, 25% steady-state |
| **Agency must-have** | White-label exports (deal-breaker without) |
| **Team trigger** | Slack bot + weekly auto-reports |
| **Defense plan** | Polyglot + brand + index format standard + M&A niche |
| **First action** | DM 50 founders. Hand-deliver first 10 reports manually. Charge from day 1. |
| **Real risk** | Cursor/GitHub native shipping. Window = 6–12 months. ChatGPT good-enough for 25% of buyers. |
| **MRR baseline** | $5–12k without viral hit (sub + reports). $42k with one. |
| **Real validation** | Strangers swiping cards. 20-persona test = sanity check only. |
