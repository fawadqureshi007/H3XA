# H3XA - All-in-One OSINT Framework

![logo](assets/h3xa_logo.png)

## Quick start
**Windows:** double-click **`H3XA.bat`** (Python 3.10+ must be installed, "Add to PATH" ticked).
**Linux/macOS:** `./h3xa.sh`

First launch: unpacks the 8 tools from `zips/`, gives each its own private venv, installs `phonenumbers`
(needs internet, a few minutes; happens once). Then the menu:

```
[1] ALL-IN-ONE   -> type a target (email / +number / username / name / domain / IP)
```
H3XA detects the type, shows an **execution plan** (which tools fit, which are not ready), runs them live,
follows verified leads automatically, and prints: accounts (with confidence), identity/phone/location clues,
breaches, infrastructure, tool status. HTML + JSON + Markdown reports are saved in `reports/`.

| You enter | Tools that run |
|---|---|
| email | user-scanner, holehe, h8mail, GHunt (if Google), then any username/email leads found |
| username | user-scanner, tookie, (userrecon), Osintgram (if Instagram hit) |
| phone | phoneinfo (offline: validity, region, carrier, time zone) + SpiderFoot |
| domain / IP | SpiderFoot (infrastructure, geo) |
| name | SpiderFoot + weak username guesses (low confidence) |

Limits, stated plainly: a phone number gives region/carrier metadata only - not the owner or live location.
"Geo-location" comes from what the tools expose (Google/Instagram/SpiderFoot/number region); there is no
tracking of a person's device. Osintgram/GHunt need your own credentials (see Setup below).

Logo files: `assets/h3xa_logo.png`, `.svg`, `h3xa.ico` (right-click H3XA.bat -> Create shortcut -> Properties -> Change Icon).

Tools: user-scanner, holehe, h8mail, GHunt, tookie-osint, userrecon, SpiderFoot, Osintgram.

## Why not a literal "code merge"?
* Their dependencies conflict (different pinned httpx/requests/trio versions), and 3 are GPL/AGPL
  (GHunt, holehe, Osintgram) - copying code into one file would force the whole result under those licences.
* Instead each tool stays **untouched** in `vendor/` with its **own venv**; `h3xa` drives them through
  small adapters, so you can update any tool by replacing its folder.

## What "no duplicates" means here
| Overlap | Decision |
|---|---|
| Username checking: user-scanner (880+ sites), tookie (262), userrecon (~75) | user-scanner = primary; tookie runs as second opinion; **userrecon** is a strict subset with grep-based detection -> only in `deep` profile, weight 0.35 |
| E-mail registration: user-scanner (200+), holehe (120+) | both run; results merged per platform, agreement raises confidence |
| Same site named differently ("Instagram" / instagram.com / https://www.instagram.com/x) | normalised to one platform key, one row in the report |
| user-scanner's own `--cross-scan` | disabled; h3xa pivots for *all* tools instead |

## How the tools cooperate
1. **Phase 1** (parallel): e-mail -> user-scanner, holehe, h8mail. Username -> user-scanner, tookie.
   Domain/IP/phone/name -> SpiderFoot.
2. **Phase 2** (conditional): GHunt runs only if the address is Gmail or another tool saw a Google account;
   Osintgram runs only if some tool found that handle on Instagram (or `--instagram`).
3. **Pivoting**: e-mails/usernames that a tool read from a *structured* field (user-scanner profile extras,
   h8mail related-emails, Osintgram public_email...) become new targets (depth 1 by default, capped at 8).
   Text-scraped leads are ignored unless `pivot.emails = "all"`.
4. **Confidence** = `1 - Π(1 - w)` over *distinct* tools (2 tools at 0.8 -> 0.96), multiplied by 0.85 per verified
   pivot hop (0.6 scraped, 0.5 guessed). It says "this account exists *and* belongs to the same subject".

## What's new in 1.2

**Scanning flow (menu `[1] NEW SCAN`)**
1. Paste a target - H3XA detects the type and lets you correct it (`jane.doe` is a username, not a domain).
2. *Other known identifiers for the same person* (e-mail / username / phone). A bare name matches thousands
   of people; adding one known identifier is what makes a name search useful.
3. Pick a mode: **Quick**, **Standard**, **Deep** or **Custom** (tick exactly the modules you want).
4. Execution plan (what runs, what is not ready and why) -> confirm -> **live dashboard**: overall progress bar,
   every running module with its own timer, retry markers, findings/leads counters. `Ctrl+C` stops cleanly and still saves a report.
5. Results screen + report files, each one **re-read and verified** (see below).

**Resilience:** a module that fails for a network reason is retried once (`retries` setting); timeouts, missing
setup and missing credentials are not retried. One crashing module never stops the others. Per-module time limits
via `[timeouts]` in `h3xa.toml`.

**Self-test (`[4] Self-test` or `python3 -m h3xa doctor`)** checks, per module and independently:
install (source + private env + packages) -> contract (the CLI flags / functions our adapter relies on still exist in the
vendored source) -> parser (adapter turns a built-in sample of the tool's real output into findings; asserts secrets never
leak) -> access (credentials present). `--live YOUR_OWN_EMAIL` additionally *runs* every fitting module for real.
It also builds a full case, writes every report format and validates them, including hostile input.
Exit code 1 if anything failed; `--json` for machines.

**Reports (HTML, Markdown, JSON, CSV)**
* HTML: cover with case ID / operator / purpose / period, sticky navigation, KPI tiles, a **coverage banner**
  (full / partial / none - a thin result is never mistaken for a clean one), confidence distribution, sortable + filterable
  account table, identity clues grouped by type, module status with plain-language states, a "Method & limits" section,
  dark mode and a print stylesheet (Ctrl+P -> PDF). Self-contained: no external scripts, fonts or images are loaded.
* Safe by construction: all tool data escaped; CSV formula-injection neutralised; Markdown cells escaped; atomic writes.
* Verified after writing: HTML tag balance + required sections + targets present, JSON schema + counts, CSV header + row count.
  The result is shown in the UI/CLI (`verified: ...` or `VERIFICATION FAILED: ...`).
* `scan` exit codes: 0 ok, 3 no module completed, 4 a report failed verification.

## Report (HTML + Markdown + JSON + CSV)
Key findings, accounts table (confidence, which tools confirmed), identity clues (names, photos, recovery hints,
locations), breach records, rich profiles (Google, Instagram), infrastructure (SpiderFoot), pivot chain, and a
**module-status table** so missing keys / rate limits / failures are visible instead of silently lowering coverage.
Breach passwords/hashes are counted, never stored or printed.

## Setup
```
python3 -m h3xa setup --zips /path/to/zips     # extract into vendor/, one venv per tool, pip install
python3 -m h3xa status                          # which tools are ready
```
Needs Python 3.11+ (3.10+ inside tool venvs). Optional credentials (h3xa never bypasses auth):
* GHunt: `.venvs/ghunt/bin/ghunt login` (your own Google session)
* Osintgram: `HIKERAPI_TOKEN` or an instagrapi login (see vendor/osintgram/config/credentials.ini.example)
* h8mail: API keys in a config file -> `[h8mail] config`; SpiderFoot keys via its own config
Tools without setup/credentials are reported as `unavailable` / `needs_auth`; the rest still run.

## Use
```
python3 -m h3xa scan jane@example.com
python3 -m h3xa scan janedoe -p deep --instagram
python3 -m h3xa scan example.com -p standard --tools spiderfoot --sf-mode footprint
python3 -m h3xa scan a@x.com --no-pivot --exclude h8mail -o ./out
python3 -m h3xa scan a@x.com --format html,csv --operator "Ali" --purpose "own account audit"
python3 -m h3xa doctor                          # self-test everything (no network needed)
python3 -m h3xa doctor --live you@example.com   # also run each module for real against YOUR target
```
Reports go to `reports/`. Config: `h3xa.example.toml`.

## Status / honesty
* 48 automated tests pass (`python3 -m unittest discover -s tests -p "test_*.py"`): parsers built from each tool's
  source, correlation, pivoting, phase-2 gating, retries, cancel, crash isolation, timeout kill, report writing +
  verification + injection safety, doctor (incl. detecting a broken parser and contract drift), subprocess plumbing with a stub tool.
* **Not run against the live tools** (no network in the build sandbox). Output parsers follow the sources
  of the versions you supplied; if a tool changes its JSON, that adapter's `parse()` is the only place to touch.
  First run: `h3xa status`, then `scan <your own e-mail> -p quick`.

## Use responsibly
These tools query many third-party services with the identifier you give them (some log it). Use on yourself,
with consent, or within a lawful engagement. `--allow-loud` can trigger notification e-mails to the target;
`--hudson` sends the identifier to Hudson Rock. Findings are leads - verify before acting.
