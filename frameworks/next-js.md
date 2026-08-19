---
id: next-js
aliases: []
tags: []
---

# Next.js

## Overview

Next.js App Router is a **confirmed instance** of Router State Forgery, not a candidate for
investigation.

The client sends a `FlightRouterState` — a JSON tree describing which route segments it believes
it has already rendered — on every RSC fetch. The server treats a matching claim as "the client
already has this level" and **skips executing that segment's layout component**. When an
application places an authorization check inside a layout, that check is skipped along with it.
The state is validated against a schema and nothing else: no session, no navigation history, no
signature.

What is confirmed: the layout-skip mechanism, the wire format, the request shape, and a
success signal that distinguishes a real bypass from a redirect. What is not: whether parallel
routes beyond the `children` slot, catch-all segment types, or the prefetch header family widen
the primitive (see Open Questions).

---

## Relevant Mechanisms

### React Server Components (RSC)

Next.js App Router uses React Server Components to stream serialized component trees from the
server. The protocol surface an attacker touches:

- `RSC: 1` — request header marking this as a Flight fetch
- `Next-Router-State-Tree` — URL-encoded `FlightRouterState` (the forgeable input)
- `Next-Url` — the path the client claims to currently be on
- `_rsc=<key>` — query-param cache-busting key
- `text/x-component` — response content type of a Flight payload

---

### FlightRouterState

The wire format is a recursive tuple. Root segment is always the empty string; each level nests
its child under a parallel-route slot key (`children` is the default slot); the leaf is a
`__PAGE__` node.

Static ancestor claim:

```json
["", { "children": ["dashboard", { "children": ["__PAGE__", {}] }] }]
```

Multiple static ancestors:

```json
["", { "children": ["organizations", { "children": ["acme", { "children": ["__PAGE__", {}] }] }] }]
```

A **dynamic** route segment (`app/organizations/[org]/layout.tsx`) cannot be claimed with a bare
string — segment matching requires an exact `[paramName, value]` tuple, so the real param name
must be known or guessed. The tuple's length is version-dependent, and
`flightRouterStateSchema` uses `superstruct.tuple()`, which enforces an **exact** element
count — a too-short *or* too-long tuple fails schema assertion and the whole request is rejected
with "The router state header was sent but could not be parsed," *before* segment matching ever
runs.

| Next.js version | Dynamic-segment tuple |
| --- | --- |
| 12.3.4 – 16.2.6 (incl. 14.x, 15.x) | `[paramName, value, dynamicParamType]` |
| 16.3.0+ | `[paramName, cacheKey, dynamicParamType, staticSiblings]` |

```json
["", { "children": [["org", "acme", "d", null], { "children": ["__PAGE__", {}] }] }]
["", { "children": [["org", "acme", "d"],       { "children": ["__PAGE__", {}] }] }]
```

A black-box request cannot know which schema shape the target's build expects, so both are
tried.

The leaf node carries an optional refresh marker at index 3. A `metadata-only` leaf narrows what
the server re-executes to the segment's `generateMetadata()`:

```json
["", { "children": ["dashboard", { "children": ["__PAGE__", {}, null, "metadata-only"] }] }]
```

Encode the whole tree with `encodeURIComponent(JSON.stringify(tree))` for the header value.

---

### Layout Skip

The mechanism lives in one predicate in
`packages/next/src/server/app-render/walk-tree-with-flight-router-state.tsx`:

```ts
const renderComponentsOnThisLevel =
  !flightRouterState ||
  !matchSegment(actualSegment, flightRouterState[0]) ||
  flightRouterState[3] === 'refetch'
```

The server walks **its own** loader tree, built from the real requested URL. At each level it
compares the real segment against the client's claimed segment. On a match it concludes the
client already holds that level rendered and does not call `createComponentTree` for it — the
layout component function is never invoked, so `redirect()` / `notFound()` / any session check
inside it never runs. Real rendering resumes at the first level where the forged tree diverges
from the true route.

So a request for `/dashboard/secret` carrying a tree that claims the client is already sitting
on `/dashboard` causes `dashboard/layout.tsx` to be skipped entirely, while `secret` — which
mismatches the claimed `__PAGE__` leaf — renders fully. No cookie is required.

The header is parsed in
`packages/next/src/server/app-render/parse-and-validate-flight-router-state.tsx`. It is
validated against `flightRouterStateSchema` and nothing else. It exists purely as a rendering
optimization; it was never designed as a trusted input, and Next.js documentation discourages
auth-in-layout for exactly this reason.

---

### The `_rsc` Cache-Busting Key

`_rsc` is **not** an authentication or integrity mechanism. It exists to stop CDN cache
poisoning across differently-`Vary`'d RSC payloads, and it is derived entirely from headers the
client itself sends — so any client can compute it
(`packages/next/src/shared/lib/router/utils/cache-busting-search-param.ts`).

Both derivations take the same comma-joined input:

```
<prefetchHeader>,<segmentPrefetchHeader>,<stateTreeHeader>,<nextUrlHeader>
```

- **strong** — SHA-256 of that input, first 96 bits (12 bytes), base64url-encoded
- **legacy** — `djb2Hash` (32-bit, seed `5381`, `((h << 5) + h + charCode) & 0xffffffff`) of the
  same input, base36-encoded, truncated to 5 characters

The prefetch inputs are sent as the literal string `"0"` (the prefetch headers themselves are
never set). The legacy key is cheaper — no crypto — so it is worth probing first; a build that
accepts it is itself a version/build-line fingerprint.

---

## Exploitation Procedure

1. **Baseline.** Plain `GET` the candidate page URL with no forged headers. Proceed only if it
   answers 3xx — an unauthenticated redirect is what makes the route worth attacking, and it is
   also the control the bypass will be measured against.

2. **Build the claim.** Construct the `FlightRouterState` asserting that the target's ancestor
   segments are already mounted, and derive `Next-Url` as `/` joined with those ancestors'
   literal path values.

3. **Issue the forged request.**

   ```http
   GET <candidateUrl>?_rsc=<key>
   RSC: 1
   Next-Router-State-Tree: <urlencoded FlightRouterState>
   Next-Url: /<ancestor/path>
   ```

   No cookie, no body. Follow redirects when testing by hand (`curl -L`): Next.js frequently
   answers a guessed or legacy `_rsc` key with its own 307 to the *same* path carrying a
   corrected `_rsc` value. That is a cache-key refresh, not the auth check rejecting the forged
   tree.

4. **Read the success signal.** All three must hold:

   - status `200`
   - `content-type` contains `text/x-component`
   - the body does **not** contain `NEXT_REDIRECT`

   `NEXT_REDIRECT` is the marker Next.js embeds in a Flight payload when a layout or page calls
   `redirect()`. Its absence is the evidence that the auth check never executed — a 200 alone is
   not, because a redirect is serialized *into* a 200 Flight payload rather than returned as a
   3xx.

5. **Harvest the payload.** A bypassed Flight body references JS chunks the plain crawl never
   reached, as `static/chunks/*.js` paths — real payloads omit the `_next/` prefix, e.g.
   `4:I[3330,["614","static/chunks/app/dashboard/secret/page-<hash>.js"],"default"]`. Resolve
   them against the origin (re-adding `_next/`) to expand attack surface.

---

## Attempt Space

One candidate URL is many requests, because three unknowns compound: which ancestor to claim,
which tuple shape the build expects, and which key derivation it accepts.

**Ancestor claims, ordered most→least specific:**

1. Dynamic-ancestor guesses — the last ancestor as `{paramName, value}`, once per candidate
   param name
2. The full static ancestor chain (every segment but the leaf, as bare strings)
3. First-segment-only (the coarsest possible claim)

The ordering is load-bearing. The first success within a leaf-mode pass wins, so a coarse claim
placed early can short-circuit past a dynamic-ancestor claim — the only shape that can match a
real dynamic-route layout — and report a weaker finding while masking a stronger one.

**Per claim:** 2 tuple lengths (4, then 3) × 2 key modes (legacy, then strong).

**Leaf modes:** `page` first (full-body disclosure). `metadata-only` only if every `page`
attempt failed — it is a narrower disclosure (dynamic `generateMetadata()` output) that can
still land where a full-body claim does not cleanly apply, e.g. a tenant-scoped layout.

A useful default wordlist of dynamic param names:

```
id, slug, org, orgId, organization, tenant, tenantId, username, userId, user,
account, accountId, workspace, workspaceId, project, projectId, team, teamId,
handle, name, key
```

Worst case per candidate URL with three or more path segments is roughly
`(2 static + 21 dynamic) × 2 tuple lengths × 2 key modes = 92` requests, plus one bounded
harvest round. A two-segment path collapses to a single first-segment-only claim.

**Param-name recovery when the wordlist misses.** No extra requests are needed — the bodies
already returned by the failed attempts are the source. Two deliberately narrow, anchored
patterns:

- Value-anchored key extraction. Flight serializes plain-object props crossing a Client
  Component boundary as ordinary `"key":"value"` pairs. The ancestor's literal *value* is
  already known, so a key quoted next to it is a strong signal for the real `[paramName]`:

  ```
  "([A-Za-z_$][A-Za-z0-9_$]{0,40})"\s*:\s*"<knownAncestorValue>"
  ```

- Bracket source paths (dev mode only). Dev error/stack payloads embed webpack module paths
  verbatim, e.g. `webpack-internal:///(rsc)/./app/organizations/[org]/layout.tsx`, where the
  bracketed segment *is* the param name:

  ```
  /\[([A-Za-z_$][A-Za-z0-9_$]{0,40})\]/
  ```

Both need a noise filter (`children`, `className`, `key`, `ref`, `type`, `props`, `default`,
`name`, `title`, `description`, `href`, `src`, `id`, `digest`) and a length cap. Anchoring is
what keeps this from degenerating into an unbounded bag-of-identifiers scan that re-explodes the
request count.

Crucially, the harvest round must still run after a **coarse** success. A first-segment-only
claim can satisfy the `metadata-only` success check without leaking the actually-scoped content,
permanently masking a dynamic-ancestor match whose real param name was outside the wordlist.
Only an already-dynamic-ancestor success is maximally specific.

**Nested gates.** When two ancestor levels each gate access, the claim must extend through both.
And the real request must carry a query string that differs from the claimed leaf's props (`{}`)
so the `__PAGE__` leaf mismatches and renders fresh — otherwise the server treats the entire
subtree *including the leaf* as client-cached and returns an empty diff.

---

## Preconditions and Scope

- Only affects applications that put authorization logic in a **layout** component. Middleware
  runs earlier in the request lifecycle and is unaffected — this does not bypass middleware.
- Requires knowing or brute-forcing the name of at least one intermediate path segment leading
  to the protected content. The technique does not enumerate segment names by itself; it needs a
  candidate URL from crawling, string extraction, or a wordlist.
- `GET` only. It does not invoke Server Actions, and every request it issues is one a legitimate
  client-side navigation would also produce — the server does the skip-the-auth-check work on
  its own. This is a disclosure and recon primitive, not code execution.
- Not tied to a CVE ID. It is a design-level trust footgun, analogous in class to the
  middleware-bypass family (CVE-2025-29927) but targeting layouts instead of middleware.
  Reproducible on current `canary` and on pinned `16.3.0`.

---

## Impact Classification

### RSF-1: State Discovery

Forged state reveals application structure that a plain unauthenticated crawl cannot reach.

- JS chunk URLs recovered from the bypassed Flight payload — routes and components with zero
  trace in the public bundle
- Component hierarchy and dependency references in the payload
- Acceptance of the legacy `_rsc` key as a build-line fingerprint

### RSF-2: State Disclosure

Forged state causes sensitive information to be serialized. Two distinct severities:

- **Full body** (`page` leaf) — the protected page renders in full: server component props,
  internal identifiers, PII, secrets
- **Metadata only** (`metadata-only` leaf) — dynamic `generateMetadata()` output only. Narrower,
  but still resolves data the request was not authorized to see

### RSF-3: Authorization Impact

The application relies on framework state as authorization context. Here it is not the
application's own mistake in reading router state, but the framework's: the layout's own auth
check is skipped because the client claimed the layout was already rendered.

---

## Open Questions

Each of these is unresolved against Next.js framework source and would widen or bound the
primitive. See the local source-validation handoff notes.

- **Parallel routes.** Only the `children` slot has been exercised. Can a named slot (`@modal`)
  or `__DEFAULT__` be claimed, and does that reach layouts a `children`-only claim cannot?
- **Dynamic param types.** Only `"d"` has been sent. What is the full union (catch-all,
  optional catch-all, interception), and does `matchSegment` compare that element at all? If it
  does, catch-all ancestors are currently unreachable.
- **Prefetch headers.** `Next-Router-Prefetch` and `Next-Router-Segment-Prefetch` feed the
  `_rsc` key as the literal `"0"` and are never sent as actual headers. Does setting them open a
  distinct partial/segment-prefetch rendering path worth a separate technique?
- **`metadata-only` marker.** Confirmed source values for `flightRouterState[3]` include
  `'refetch'`; `'metadata-only'` needs schema confirmation and a definition of what the server
  actually re-executes for it.
- **Legacy key acceptance.** Is dual-accept a real server-side path, or does the server simply
  ignore a mismatched key? The latter would make the "legacy accepted" fingerprint meaningless.
- **`Next-Url` semantics.** What does the server use it for, and must it be consistent with the
  forged tree, or is it free-form?
- **Tuple-length boundary.** The 16.2.6 / 16.3.0 split needs confirmation by diffing
  `flightRouterStateSchema` between release tags.

---

## Mitigation

Applications should:

- **never place authorization checks in a layout component** — enforce in middleware, or inside
  the page/data layer that actually returns the protected data;
- treat all framework-generated client metadata as attacker-controlled;
- never use router state as authorization evidence;
- perform authorization checks against server-side identity and resources;
- separate rendering state from security decisions.

---

## Notes

This document describes the Next.js-specific implementation only. The general Router State
Forgery definition is maintained in the root research document.

The mechanism described here is implemented as a black-box crawl technique in
`js-recon/src/lazyLoad/next_js/next_routerStateForge.ts`.
