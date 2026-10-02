from __future__ import annotations
import math
from collections import defaultdict
from dataclasses import dataclass, field

from .models import Finding, Target, ToolRun


def combine(weights) -> float:
    """Independent-evidence combination: 1 - prod(1 - w). Two 0.8 tools -> 0.96."""
    p = 1.0
    for w in weights:
        p *= (1.0 - max(0.0, min(w, 0.99)))
    return min(0.99, 1.0 - p)


def label(c: float) -> str:
    return "High" if c >= 0.85 else "Medium" if c >= 0.6 else "Low"


@dataclass
class Account:
    subject: str
    via: str
    platform: str
    title: str
    urls: list = field(default_factory=list)
    tools: list = field(default_factory=list)
    confidence: float = 0.0
    profile: dict = field(default_factory=dict)
    origin: str = ""

    @property
    def label(self):
        return label(self.confidence)


@dataclass
class Case:
    seeds: list
    targets: list                 # list[Target]
    runs: list                    # list[ToolRun]
    findings: list                # list[Finding]
    started: str = ""
    finished: str = ""
    accounts: list = field(default_factory=list)
    breaches: list = field(default_factory=list)
    identity: list = field(default_factory=list)
    profiles: list = field(default_factory=list)
    infra: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)     # case_id, operator, purpose, profile, modules ...


def build_case(seeds, targets, runs, findings, started="", finished="", meta=None) -> Case:
    case = Case(seeds, targets, runs, findings, started, finished, meta=dict(meta or {}))
    origin = {t.value: (t.reason if t.depth else "seed") for t in targets}
    trust = {t.value: t.trust for t in targets}

    # ---- accounts: one row per (subject, via, platform), merged across tools ----
    groups: dict = defaultdict(list)
    for f in findings:
        if f.category == "account" and f.platform:
            groups[(f.subject, f.via, f.platform)].append(f)
    # merge groups whose alternative key equals another group's primary key
    primaries = {(s, v, p) for (s, v, p) in groups}
    remap = {}
    for (s, v, p), fs in list(groups.items()):
        for f in fs:
            for alt in f.data.get("alt_keys", []):
                if alt and alt != p and (s, v, alt) in primaries:
                    remap[(s, v, p)] = (s, v, alt)
    for src, dst in remap.items():
        if src in groups and dst in groups and src != dst:
            groups[dst].extend(groups.pop(src))
    for (s, v, p), fs in groups.items():
        by_tool: dict = {}
        for f in fs:
            by_tool[f.tool] = max(by_tool.get(f.tool, 0), f.weight)
        conf = combine(by_tool.values()) * trust.get(s, 1.0)
        prof: dict = {}
        for f in fs:
            prof.update(f.data.get("profile", {}))
        urls = sorted({f.url for f in fs if f.url})
        title = max((f.title for f in fs if f.title), key=len, default=p)
        case.accounts.append(Account(s, v, p, title, urls, sorted(by_tool), round(conf, 3), prof, origin.get(s, "seed")))
    case.accounts.sort(key=lambda a: (-len(a.tools), -a.confidence, a.platform))

    # ---- identity clues -------------------------------------------------------
    idg: dict = defaultdict(list)
    for f in findings:
        if f.category == "identity" and f.value:
            idg[(f.kind, f.value.strip().lower())].append(f)
    for (kind, _), fs in idg.items():
        tools = sorted({f.tool for f in fs})
        conf = combine({f.tool: f.weight for f in fs}.values()) * max(f.trust for f in fs)
        case.identity.append({"kind": kind, "value": fs[0].value.strip(), "tools": tools,
                              "sources": sorted({f.title for f in fs if f.title}),
                              "subjects": sorted({f.subject for f in fs}),
                              "confidence": round(conf, 3), "url": next((f.url for f in fs if f.url), "")})
    case.identity.sort(key=lambda d: (d["kind"], -d["confidence"]))

    # ---- breaches ---------------------------------------------------------------
    bg: dict = defaultdict(list)
    for f in findings:
        if f.category == "breach":
            bg[(f.subject, f.kind, f.title.lower(), f.value.lower())].append(f)
    for (subj, kind, _, _), fs in bg.items():
        case.breaches.append({"subject": subj, "kind": kind, "title": fs[0].title, "value": fs[0].value,
                              "tools": sorted({f.tool for f in fs}), "url": next((f.url for f in fs if f.url), ""),
                              "data": {k: v for f in fs for k, v in f.data.items()},
                              "confidence": round(combine({f.tool: f.weight for f in fs}.values()), 3)})
    case.breaches.sort(key=lambda b: (b["subject"], b["title"]))

    case.profiles = [f for f in findings if f.category == "profile"]
    ig: dict = defaultdict(list)
    for f in findings:
        if f.category == "infra":
            ig[(f.kind, f.value.lower())].append(f)
    case.infra = [{"kind": k, "value": fs[0].value, "subject": fs[0].subject,
                   "tools": sorted({f.tool for f in fs})} for (k, _), fs in sorted(ig.items())]
    case.notes = [f for f in findings if f.category == "note"]
    return case


def summarize(case: Case) -> dict:
    multi = [a for a in case.accounts if len(a.tools) >= 2]
    high = [a for a in case.accounts if a.confidence >= 0.85]
    ok = [r for r in case.runs if r.status == "ok"]
    bad = [r for r in case.runs if r.status in ("error", "timeout")]
    need = [r for r in case.runs if r.status in ("needs_auth", "unavailable")]
    medium = [a for a in case.accounts if 0.6 <= a.confidence < 0.85]
    low = [a for a in case.accounts if a.confidence < 0.6]
    return {"targets": len(case.targets), "accounts": len(case.accounts),
            "accounts_multi_tool": len(multi), "accounts_high": len(high),
            "accounts_medium": len(medium), "accounts_low": len(low),
            "breaches": len(case.breaches), "identity_clues": len(case.identity),
            "infra": len(case.infra), "tool_runs": len(case.runs), "runs_ok": len(ok),
            "runs_failed": len(bad), "runs_need_setup": len(need)}
