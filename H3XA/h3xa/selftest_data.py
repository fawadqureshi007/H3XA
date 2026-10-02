"""Built-in sample data for the self-test.

Each entry is shaped exactly like what the real tool writes, so running an adapter's
`parse()` on it proves the parser still understands the format - with no network and no
accounts needed. If a tool changes its output, its entry here (and the adapter's `parse`)
is the only place to touch.
"""
from __future__ import annotations

from .models import Target

T_MAIL = Target("email", "selftest@example.com")
T_USER = Target("username", "selftest_user")
T_DOMAIN = Target("domain", "example.com")

# module key -> (target, sample payload, categories the parser must produce)
FIXTURES = {
    "user-scanner": (T_MAIL, [
        {"status": "Registered", "site_name": "Instagram", "url": "https://instagram.com/selftest", "category": "social",
         "extra": {"full_name": "Self Test", "contact_email": "contact@example.org"}, "media": {}},
        {"status": "Not Registered", "site_name": "Other"}, {"status": "Error", "site_name": "Broken"},
    ], {"account", "identity"}),
    "holehe": (T_MAIL, [
        {"name": "github", "domain": "github.com", "exists": True, "rateLimit": False, "method": "register",
         "emailrecovery": "s***@e***.com", "phoneNumber": None, "others": {"FullName": "Self Test"}},
        {"name": "x", "domain": "x.com", "exists": False, "rateLimit": True},
    ], {"account", "identity"}),
    "h8mail": (T_MAIL, {"targets": [{"target": "selftest@example.com", "pwn_num": 2, "data": [
        ["HIBP3:Adobe"],
        ["SCYLLA_USERNAME:stuser", "SCYLLA_PASSWORD:SECRET-VALUE-123", "SCYLLA_EMAIL:other@example.org", "SCYLLA_SOURCE:col1"]]}]},
        {"breach"}),
    "ghunt": (T_MAIL, {"PROFILE_CONTAINER": {"profile": {
        "personId": "1234567890", "names": {"PROFILE": {"fullname": "Self Test"}},
        "profilePhotos": {"PROFILE": {"url": "https://lh3.example/photo", "isDefault": False}},
        "inAppReachability": {"PROFILE": {"apps": ["Maps", "Photos"]}}},
        "play_games": None, "maps": {"stats": {"reviews": 3}}, "calendar": None}}, {"account", "identity", "profile"}),
    "tookie": (T_USER, [{"url": "https://github.com/selftest_user", "found": True, "status": 200},
                        {"url": "https://example.net/selftest_user", "found": False, "status": 404}], {"account"}),
    "userrecon": (T_USER, ["https://www.facebook.com/selftest_user", ""], {"account"}),
    "spiderfoot": (T_DOMAIN, [
        {"type": "EMAILADDR", "data": "info@example.com", "module": "sfp_email"},
        {"type": "IP_ADDRESS", "data": "93.184.216.34", "module": "sfp_dns"},
        {"type": "ROOT", "data": "noise"},
        {"type": "ACCOUNT_EXTERNAL_OWNED", "data": "Twitter (Category: social)\n<SFURL>https://twitter.com/selftest</SFURL>",
         "module": "sfp_account"},
    ], {"account", "identity", "infra"}),
    "osintgram": (T_USER, {"info": {"full_name": "Self Test", "biography": "mail st@example.org", "public_email": "st@biz.example",
                                     "bio_links": [{"url": "https://selftest.example"}]},
                           "about": {"country": "PK"}, "_api_calls": 3}, {"account", "profile", "identity"}),
}

PHONE_SAMPLE = "+923001234567"      # exercised through the real `phonenumbers` library when installed

# Static contract: strings that must still exist in each vendored tool's source for our adapter to
# drive it correctly (CLI flags, functions the bridge imports). (relative path inside vendor/<tool>, needle).
CONTRACTS = {
    "user-scanner": [("user_scanner/__main__.py", n) for n in ('"--all"', '"-C"', '"--output"', '"--allow-loud"', '"--no-nsfw"')],
    "holehe": [("holehe/core.py", n) for n in ("def get_functions", "def import_submodules", "async def launch_module", "nopasswordrecovery")],
    "h8mail": [("h8mail/utils/run.py", n) for n in ('"--targets"', '"--json"', '"--config"')],
    "ghunt": [("ghunt/cli.py", n) for n in ("--json", "parser_email")],
    "tookie": [("brib.py", n) for n in ('"--user"', 'choices=["txt", "csv", "json"]')] + [("modules/modules.py", "def write_json")],
    "userrecon": [("userrecon.sh", "read -p"), ("userrecon.sh", ".txt")],
    "spiderfoot": [("sf.py", n) for n in ('"-max-threads"', 'choices=["all", "footprint", "investigate", "passive"]',
                                          'choices=["tab", "csv", "json"]')],
    "osintgram": [("src/osint_service.py", n) for n in ("def build_service", "def get_user_info", "def get_account_about",
                                                         "def get_hashtags", "def get_addrs", "def get_posting_times",
                                                         "def api_call_count", "is_private")],
}

# Hostile strings: the report must neutralise every one of these.
HOSTILE_TITLE = "<img src=x onerror=alert(1)>"
HOSTILE_VALUE = "=HYPERLINK(\"http://evil.example\",\"x\")"
HOSTILE_PIPE = "a|b\nc"
