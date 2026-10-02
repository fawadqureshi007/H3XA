
<div align="center">
  <img src="h3xa_logo.png" alt="H3XA Logo" width="200" />
</div>

# ⚡ H3XA — All-in-One OSINT Framework

**Automated Multi-Tool Intelligence Aggregation & Target Pivoting Engine**

*Run 8 leading OSINT tools concurrently with a single command — zero dependency conflicts, zero setup headache.*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL/AGPL Compatibility](https://img.shields.io/badge/License-GPL%2FAGPL%20Compatible-brightgreen.svg)](#-system-architecture--conflict-avoidance)
[![Architecture: Isolated Venvs](https://img.shields.io/badge/Architecture-Isolated%20Venvs-orange.svg)](#-system-architecture--conflict-avoidance)
[![Build Status: 48 Tests Passed](https://img.shields.io/badge/Tests-48%20Passed-success.svg)](#-testing--diagnostics)

---

## 📌 Overview

**H3XA** is an automated orchestration framework designed to eliminate the tedious manual effort of running multiple reconnaissance tools. Instead of opening multiple terminals, manually copying emails/usernames, and trying to stitch conflicting output files together, H3XA handles the entire lifecycle automatically:

1. **Target Detection:** Paste *anything* (email, username, phone, IP, domain, or name)—H3XA automatically detects what it is.
2. **Execution Planning:** Determines which tools fit the target type, flags missing credentials/keys early, and presents a clear execution plan.
3. **Parallel Execution:** Runs relevant tools inside their own private virtual environments concurrently without dependency collisions.
4. **Smart Pivoting:** Extracts newly discovered leads (e.g., finding a hidden email during a username search) and automatically queries them.
5. **Verified Reporting:** Generates clean, self-contained, and verified reports in HTML, JSON, CSV, and Markdown formats.

---

## ✨ Why H3XA? (Designed for Maximum Ease of Use)

Traditional OSINT setups require juggling dozens of Python environments, resolving library conflicts, and spending hours trying to get tools to play nicely together. H3XA solves all of this out-of-the-box:

* 🚀 **One-Click Startup:** Launch directly via `H3XA.bat` on Windows or `./h3xa.sh` on Linux/macOS.
* 📦 **Self-Managing Environments:** Each tool gets its own isolated virtual environment automatically—no manual `pip install` dependency conflicts ever.
* 🧠 **Zero Configuration Needed to Start:** H3XA intelligently auto-detects target types and picks the optimal workflow automatically.
* 📊 **Live Visual Dashboard:** Track scan progress in real-time with per-module progress bars, active timers, and live finding counters.
* 🛡 **Fault-Tolerant Engine:** If one tool encounters a network glitch or timeout, H3XA retries gracefully without stopping or failing the rest of your scan session.
* 📑 **Instant Verified Reports:** Generates clean, ready-to-share HTML executive reports with zero external dependencies.

---

## 🛠️ Integrated Tools

| Tool | Core Capability | Standard Coverage |
| :--- | :--- | :--- |
| **`user-scanner`** | Username enumeration & Email registration checks | 880+ sites / 200+ email services |
| **`holehe`** | Email account presence verification | 120+ platforms |
| **`h8mail`** | Email breach analysis & password leak correlation | Breach databases |
| **`GHunt`** | Deep Google Account intelligence (Gmail, GAIA ID, Photos, Maps) | Google Ecosystem |
| **`tookie-osint`** | Secondary username verification engine | 262 sites |
| **`userrecon`** | Deep-profile username validation subset | ~75 sites |
| **`SpiderFoot`** | Infrastructure footprinting, domain/IP intelligence & Name OSINT | Global infrastructure |
| **`Osintgram`** | Target Instagram account analysis & metadata scraping | Instagram |

---

## ⚡ Quick Start & Interactive Menu

### 🚀 Launching
* **Windows:** Double-click **`H3XA.bat`** *(Requires Python 3.10+ with "Add to PATH" checked)*.
* **Linux / macOS:** Make executable and launch:
  ```bash
  chmod +x h3xa.sh && ./h3xa.sh

```

> 💡 **First-Time Setup:** On your first launch, H3XA extracts bundled tool archives from `zips/`, builds private virtual environments for each tool, and installs dependencies. *This runs automatically once and takes only a few minutes.*

### 🎯 Main Interactive Menu

When launched without arguments, H3XA presents a clear, numbered interactive menu:

```text
┌──────────────────────────────────────────────────────────┐
│                    ⚡ H3XA OSINT FRAMEWORK                │
└──────────────────────────────────────────────────────────┘

  [1] ALL-IN-ONE SCAN  -> Enter target (email/user/phone/domain/IP/name)
  [2] QUICK SCAN       -> Fast surface recon profile
  [3] DEEP SCAN        -> Extended pivoting & comprehensive module run
  [4] SELF-TEST        -> Run framework diagnostic doctor
  [5] EXIT

```

---

## ⚙️ Automatic Target Routing Workflow

Simply select option `[1]` and type your target. H3XA auto-detects the input type and routes the target through the appropriate tools:

| Input Entered | How H3XA Processes It |
| --- | --- |
| **Email** (`user@domain.com`) | `user-scanner` $\rightarrow$ `holehe` $\rightarrow$ `h8mail` $\rightarrow$ `GHunt` *(if Google/Gmail detected)* $\rightarrow$ Lead Pivoting |
| **Username** (`target_handle`) | `user-scanner` $\rightarrow$ `tookie-osint` $\rightarrow$ `userrecon` *(in deep profile)* $\rightarrow$ `Osintgram` *(if IG hit)* |
| **Phone** (`+1234567890`) | `phoneinfo` *(offline carrier, region, time zone)* $\rightarrow$ `SpiderFoot` |
| **Domain / IP** (`example.com`) | `SpiderFoot` *(infrastructure footprinting, reverse DNS, GeoIP)* |
| **Name** (`Jane Doe`) | `SpiderFoot` $\rightarrow$ Weak username heuristic generation *(low-confidence leads)* |

---

## 🧩 System Architecture & Conflict Avoidance

```text
                      +-------------------+
                      |   H3XA CLI Core   |
                      +---------+---------+
                                |
         +----------------------+----------------------+
         |                                             |
 Adapter Interface                             Adapter Interface
         |                                             |
+--------v--------+                           +--------v--------+
|  vendor/holehe  |                           |   vendor/GHunt  |
|  (Private Venv) |                           |  (Private Venv) |
+-----------------+                           +-----------------+

```

### Why not a literal "code merge"?

* **Dependency Isolation:** Vendored tools rely on conflicting, strictly pinned versions of core libraries (e.g., `httpx`, `requests`, `trio`). Keeping tools in dedicated virtual environments (`.venvs/`) prevents breakage.
* **License Compliance:** Integrated tools carry different open-source licenses (GPL/AGPL for GHunt, holehe, Osintgram). Operating via adapters keeps code cleanly separated and compliant.
* **Seamless Maintenance:** Each tool stays untouched in `vendor/`. You can update any individual tool folder without touching the rest of the framework.

---

## 🎯 Correlation & Deduplication Engine

H3XA normalizes and correlates cross-platform findings so you never have to parse duplicate entries:

* **Username Deduplication:** `user-scanner` acts as primary (880+ sites). `tookie` acts as secondary verification. `userrecon` runs strictly in `--profile deep` (weight: 0.35).
* **Email Registration Correlation:** `user-scanner` and `holehe` run simultaneously; matched results are merged per platform, raising overall confidence.
* **Platform Handle Normalization:** Handles like `Instagram`, `instagram.com`, and `https://instagram.com/user` map to a single unified key in final reports.
* **Smart Pivoting:** Extracted leads from structured profile fields (e.g., `h8mail` related emails, social links, `Osintgram` public email) automatically trigger secondary scan hops (default depth: 1, capped at 8).
* **Confidence Scoring Model:**

$$\text{Confidence} = 1 - \prod (1 - w_i)$$

Scored across distinct tools and decayed by **0.85 per verified pivot hop** (0.6 for regex-scraped text, 0.5 for guesses).

---

## 📊 Multi-Format Verified Reporting Engine

Every scan run produces clean, structurally verified reports inside `reports/`:

* **HTML Report:**
* Self-contained (zero external network dependencies or fonts).
* Professional header layout with Case ID, Operator, Purpose, Timestamps, and **Coverage Banner** (Full / Partial / None).
* Sortable account finding tables, confidence score distributions, and grouped identity clues.
* Built-in Dark Mode & Print/PDF styling (`Ctrl + P`).


* **JSON / CSV / Markdown:**
* Structured JSON schema for integration into threat intelligence pipelines.
* Formula-injection sanitized CSV exports.
* Clean, formatted Markdown tables ready for documentation paste.


* **Automated Post-Write Verification:** H3XA automatically verifies report integrity after writing (validates HTML tag balancing, JSON schema conformance, and row counts).

---

## ⚙ Setup & CLI Command Reference

### Environment Commands

```bash
# Unpack dependencies and build per-tool virtual environments
python3 -m h3xa setup --zips /path/to/zips

# Inspect tool readiness and credential status
python3 -m h3xa status

```

### Optional Authentication Setup

Optional credentials can be configured to unlock deep authentication features:

* **GHunt:** Run `.venvs/ghunt/bin/ghunt login` to bind your Google session.
* **Osintgram:** Set `HIKERAPI_TOKEN` or supply credentials in `vendor/osintgram/config/credentials.ini`.
* **h8mail / SpiderFoot:** Pass API config files via `h3xa.toml`.

### Direct Command Line Usage Examples

```bash
# Basic Email Recon
python3 -m h3xa scan jane@example.com

# Fast Surface Scan Profile
python3 -m h3xa scan target_username -p quick

# Deep Audit with Instagram Extraction
python3 -m h3xa scan janedoe -p deep --instagram

# Domain Reconnaissance via SpiderFoot
python3 -m h3xa scan example.com -p standard --tools spiderfoot --sf-mode footprint

# Custom Report Output & Metadata Tagging
python3 -m h3xa scan target@domain.com --format html,csv --operator "Fawad Qureshi" --purpose "Authorized Security Audit"

```

---

## 🧪 Testing & Diagnostics

H3XA includes an automated self-diagnostic tool (`doctor`) to verify system integrity:

```bash
# Perform framework self-test
python3 -m h3xa doctor

# Live network pipeline verification against your own target
python3 -m h3xa doctor --live your_email@example.com

```

* **48 Unit Tests Passing:** Evaluated via `python3 -m unittest discover -s tests -p "test_*.py"`.
* Verifies output parser integrity, pivot logic, phase-2 triggers, crash isolation, subprocess handling, and report sanitization.

---

## 🛡️ Powered by CodenSec

### Operator-Led Cyber Security & Offensive Research

> **CodenSec** is an operator-led cybersecurity firm focused on realistic adversary simulation, red teaming, security research, custom tooling, and practical offensive security education.

#### 🎯 Core Operating Principles

* **Realism Over Theater:** Security testing models real-world attack paths and objective-driven adversary behavior rather than generating compliance noise.
* **Evidence Over Assumptions:** Every vulnerability finding is validated, reproducible, and accompanied by practical remediation guidance.
* **Continuous Research & Tooling:** Research findings, custom automation, and red team engagements directly feed into developing offensive intelligence frameworks.

---

### 🔬 Core Operational Capabilities

| Pillar | Focus & Execution |
| --- | --- |
| **Offensive Red Teaming** | Simulating real-world adversary tactics across web apps, Active Directory environments, and cloud infrastructure. |
| **Advanced OSINT & Recon** | Architecting automated intelligence gathering tools and deep multi-source target pivoting pipelines. |
| **Critical Infrastructure Defense** | Grounded in certified critical infrastructure protection (ICIP) and rigorous network security standards. |
| **Custom Security Development** | Engineering bespoke automation tools, reconnaissance scripts, and specialized CLI security frameworks. |

📲 **Follow Research & Updates on Instagram:** [@h4cker_fawad](https://instagram.com/h4cker_fawad)

🌐 **Official Platform:** [codensec.com](https://www.google.com/search?q=https://codensec.com)

---

## ⚖ Legal & Ethical Usage Notice

H3XA queries third-party services directly using target identifiers. **Always obtain explicit authorization before scanning target assets.**

* `--allow-loud` mode may generate platform interaction notifications to target accounts.
* `--hudson` mode transmits target inputs to Hudson Rock API services.
* All generated outputs are intelligence leads—verify findings independently before acting.

```
