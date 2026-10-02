"""Runs inside Osintgram's venv with cwd = Osintgram source dir. Calls its service
layer directly (the current Osintgram is a service/web app, not an interactive shell)
and prints a single JSON document. Followers/followings are opt-in: they cost API
credits and involve many third parties."""
import json, sys, traceback

src, target, out_path, limit, followers, followings = sys.argv[1:7]
sys.path.insert(0, src)
limit, doc = int(limit), {}


def put(key, fn, *a, **kw):
    try:
        doc[key] = fn(*a, **kw)
    except Exception as e:  # keep partial results
        doc.setdefault("_errors", {})[key] = f"{type(e).__name__}: {e}"


try:
    from src.osint_service import build_service
    svc = build_service(target)
    put("info", svc.get_user_info)
    put("about", svc.get_account_about)
    if not svc.is_private:
        put("hashtags", svc.get_hashtags, limit_posts=limit)
        put("places", svc.get_addrs, limit_posts=limit)
        put("posting_times", svc.get_posting_times, limit_posts=limit)
        if followers == "1":
            put("followers", svc.get_followers, limit=200)
        if followings == "1":
            put("followings", svc.get_followings, limit=200)
    else:
        doc["_errors"] = {"posts": "private profile - post-level data not collected"}
    doc["_api_calls"] = svc.api_call_count
except Exception as e:
    doc["_fatal"] = f"{type(e).__name__}: {e}"
    doc["_trace"] = traceback.format_exc()[-800:]

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(doc, f, default=str)
