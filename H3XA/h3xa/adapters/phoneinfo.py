from __future__ import annotations
from ..models import AdapterResult, Target, Unavailable
from .base import Adapter


class PhoneInfo(Adapter):
    """Built-in, offline number analysis (no network, nothing sent anywhere).
    Uses the `phonenumbers` library: validity, country/region, carrier of first allocation, time zones."""
    name = "phoneinfo"
    dir = ""
    kinds = ("phone",)
    weight = 0.90
    needs_python = False

    def check(self):
        import sys
        # a stub (empty folder) or stub module without `parse` is not the real library
        m = sys.modules.get("phonenumbers")
        if m is not None and not callable(getattr(m, "parse", None)):
            sys.modules.pop("phonenumbers", None)
        try:
            import phonenumbers
        except ImportError:
            raise Unavailable("pip install phonenumbers (the launcher does this on first run)")
        if not callable(getattr(phonenumbers, "parse", None)):
            raise Unavailable("phonenumbers is present but empty/broken (stale libs/ folder?) - "
                              "delete libs/phonenumbers and restart so it is reinstalled")

    def run(self, target: Target) -> AdapterResult:
        import phonenumbers
        from phonenumbers import PhoneNumberType as T, carrier, geocoder, timezone
        raw = target.value.strip()
        region = (target.hints.get("region") or "").upper() or None
        try:
            n = phonenumbers.parse(raw, None if raw.startswith("+") else region)
        except phonenumbers.NumberParseException as e:
            return AdapterResult(message=f"cannot parse number ({e}); include country code, e.g. +92...")
        return self.parse_number(n, target)

    def parse_number(self, n, target):
        import phonenumbers
        from phonenumbers import PhoneNumberType as T, carrier, geocoder, timezone
        res = AdapterResult()
        valid = phonenumbers.is_valid_number(n)
        e164 = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        res.findings.append(self.mk(target, "identity", kind="phone", title="Number (normalised)",
                                    value=intl, data={"e164": e164, "valid": valid}))
        if not valid:
            res.message = "number is not valid for its country (format/length)"
            return res
        loc = geocoder.description_for_number(n, "en")
        country = geocoder.country_name_for_number(n, "en") if hasattr(geocoder, "country_name_for_number") else ""
        if loc:
            res.findings.append(self.mk(target, "identity", kind="location", title="Number region (allocation area)",
                                        value=loc if not country or country in loc else f"{loc}, {country}"))
        car = carrier.name_for_number(n, "en")
        if car:
            res.findings.append(self.mk(target, "identity", kind="carrier", title="Original carrier", value=car,
                                        weight=0.6, data={"note": "carrier at allocation time; number portability can change it"}))
        tzs = [z for z in timezone.time_zones_for_number(n) if z != "Etc/Unknown"]
        if tzs:
            res.findings.append(self.mk(target, "identity", kind="timezone", title="Time zone", value=", ".join(tzs)))
        kind = {T.MOBILE: "mobile", T.FIXED_LINE: "fixed line", T.FIXED_LINE_OR_MOBILE: "fixed/mobile", T.VOIP: "VoIP",
                T.TOLL_FREE: "toll free", T.PREMIUM_RATE: "premium rate"}.get(phonenumbers.number_type(n))
        if kind:
            res.findings.append(self.mk(target, "identity", kind="line_type", title="Line type", value=kind))
        res.message = "offline analysis; does not reveal the owner or live location"
        return res
