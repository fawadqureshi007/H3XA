"""User-facing names for each module.

Internally every module keeps its original key (holehe, spiderfoot, ...) because that's
what config files, adapters and vendor/ folders are keyed on - changing that would be a
large, risky rename for no real benefit. What THIS file controls is what the person
running H3XA actually sees: the banner, the execution plan, the live scan log, module
status, and every report (HTML/Markdown/JSON). None of those should print an internal
key or reveal that a module is a wrapper around a specific known project.
"""
from __future__ import annotations

DISPLAY = {
    "user-scanner": "SocialSweep",
    "holehe":       "MailTrace",
    "h8mail":       "BreachRadar",
    "ghunt":        "GAccountID",
    "tookie":       "HandleScan",
    "userrecon":    "LegacySweep",
    "spiderfoot":   "NetScope",
    "osintgram":    "InstaLens",
    "phoneinfo":    "PhoneID",
}


def display(key: str) -> str:
    """User-facing module name. Falls back to the raw key for anything unmapped so a
    newly added module never renders blank."""
    return DISPLAY.get(key, key)


def display_list(keys) -> str:
    return ", ".join(display(k) for k in keys)


# Human labels for identity-clue kinds (shared by the terminal UI and the reports).
KIND_LABEL = {"name": "Name", "location": "Location", "phone": "Phone", "carrier": "Carrier",
              "timezone": "Time zone", "line_type": "Line type", "recovery_email": "Recovery e-mail (masked)",
              "recovery_phone": "Recovery phone (masked)", "google_id": "Google ID", "username": "Username",
              "link": "Link", "photo": "Photo", "created": "Account created", "email": "E-mail", "bio": "Bio"}
KIND_ORDER = list(KIND_LABEL)
