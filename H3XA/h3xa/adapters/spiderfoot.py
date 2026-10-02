from __future__ import annotations
import re
from ..models import AdapterError, AdapterResult, Pivot, Target
from ..util import URL_RE, clean_dict, load_json_lenient, platform_key, strip_ansi
from .base import Adapter

# SpiderFoot event type -> (h3xa category, kind, weight)
_MAP = {
    "EMAILADDR": ("identity", "email", 0.6), "EMAILADDR_GENERIC": ("identity", "email", 0.4),
    "USERNAME": ("identity", "username", 0.55), "HUMAN_NAME": ("identity", "name", 0.55),
    "PHONE_NUMBER": ("identity", "phone", 0.55), "GEOINFO": ("identity", "location", 0.5),
    "COUNTRY_NAME": ("identity", "location", 0.5), "PHYSICAL_ADDRESS": ("identity", "location", 0.5),
    "SOCIAL_MEDIA": ("account", "", 0.6), "ACCOUNT_EXTERNAL_OWNED": ("account", "", 0.6),
    "LEAKSITE_URL": ("breach", "leaksite", 0.6), "EMAILADDR_COMPROMISED": ("breach", "breach", 0.75),
    "PASSWORD_COMPROMISED": ("breach", "breach", 0.75), "BREACH": ("breach", "breach", 0.7),
    "DARKNET_MENTION_URL": ("breach", "darknet", 0.5),
}
_INFRA = {"IP_ADDRESS", "IPV6_ADDRESS", "INTERNET_NAME", "DOMAIN_NAME", "AFFILIATE_INTERNET_NAME",
          "TCP_PORT_OPEN", "UDP_PORT_OPEN", "WEBSERVER_TECHNOLOGY", "WEBSERVER_BANNER", "SSL_CERTIFICATE_ISSUED",
          "DNS_TEXT", "DNS_SPF", "BGP_AS_MEMBER", "NETBLOCK_OWNER", "CO_HOSTED_SITE", "LINKED_URL_INTERNAL",
          "PROVIDER_MAIL", "PROVIDER_DNS", "PROVIDER_HOSTING", "DOMAIN_WHOIS", "DOMAIN_REGISTRAR"}
_NOISE = {"ROOT", "INITIAL_TARGET", "RAW_RIR_DATA", "RAW_DNS_RECORDS", "TARGET_WEB_CONTENT",
          "HTTP_CODE", "WEBSERVER_HTTPHEADERS", "SEARCH_ENGINE_WEB_CONTENT", "LINKED_URL_EXTERNAL",
          "URL_FORM", "URL_STATIC", "URL_JAVASCRIPT", "URL_WEB_FRAMEWORK", "CLOUD_STORAGE_BUCKET_OPEN_"}


class SpiderFoot(Adapter):
    name = "spiderfoot"
    dir = "spiderfoot"
    kinds = ("domain", "ip", "phone", "name", "email", "username")
    weight = 0.60
    # No critical_imports list needed here any more - base.Adapter.check() finds
    # vendor/spiderfoot/requirements.txt automatically and verifies every package
    # pinned in it (cherrypy, cryptography, lxml, pygexf, ...), not a hand-picked
    # subset, so a different missing package each time can't keep slipping through.

    def applies(self, target, prior) -> bool:
        return target.kind in self.opts.get("kinds", ["domain", "ip", "phone", "name"])

    def run(self, target: Target) -> AdapterResult:
        wd = self.workdir()
        val = f'"{target.value}"' if target.kind == "name" else target.value
        cmd = [self.py(), self.src / "sf.py", "-s", val, "-u", self.opts.get("mode", "passive"),
               "-o", "json", "-q", "-max-threads", str(self.opts.get("max_threads", 3))]
        r = self.exec(cmd, cwd=self.src)
        events = load_json_lenient(r.out)
        if events is None:
            raise AdapterError(f"unparseable output (rc={r.rc}): {strip_ansi(r.err or r.out)[-300:]}")
        return self.parse(events, target)

    def parse(self, events, target: Target) -> AdapterResult:
        res = AdapterResult(checked=len(events))
        seen = set()
        for ev in events:
            t, data = ev.get("type", ""), str(ev.get("data", ""))
            if t in _NOISE or not data:
                continue
            key = (t, data)
            if key in seen:
                continue
            seen.add(key)
            mod = ev.get("module", "")
            if t in _MAP:
                cat, kind, w = _MAP[t]
                url = (URL_RE.findall(data) or [""])[0]
                if cat == "account":
                    title = data.split("\n")[0].split(" (Category")[0].strip("<>/ ") or "account"
                    plat = platform_key(url) or platform_key(title)
                    f = self.mk(target, "account", title=title, url=url, platform=plat, via="username",
                                weight=w, data={"module": mod})
                else:
                    f = self.mk(target, cat, kind=kind or t, title=t, value=data[:300], url=url,
                                weight=w, data={"module": mod})
                    if t == "EMAILADDR":
                        f.pivots.append(Pivot("email", data.lower(), "scraped"))
                    elif t == "USERNAME":
                        f.pivots.append(Pivot("username", data, "scraped"))
                res.findings.append(f)
            elif t in _INFRA or t.startswith(("VULNERABILITY", "MALICIOUS", "BLACKLISTED")):
                cat = "infra"
                res.findings.append(self.mk(target, cat, kind=t, title=t, value=data[:300], weight=0.6,
                                            data={"module": mod}))
        return res
