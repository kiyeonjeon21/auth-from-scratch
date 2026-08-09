# auth-from-scratch

A study repo that builds authentication mechanisms by hand and **compares them side by side**.
Not one protocol in depth: sessions, passkeys, request signing, logout, SAML, OIDC.

**The deliverable is `notes/comparison.md`, not the code.** Each chapter fills one row.
Individual mechanisms can be learned anywhere; the table only exists if you build it.

The organising question for every chapter is *what did the previous approach fail at, and what
did this one give up in exchange*. Authentication is a chain of trade-offs, not a list of features.

**Optimize for understanding, not for working code.**
A chapter that runs but leaves its questions unanswered is not done.
Prefer the explicit, readable version over the clever one, and comment the *why* rather than the *what*.

Prose in chapter READMEs and generated study output is Korean, matching the root README.
Code comments and this file are English.

## Scope boundary with agent-identity-lab

`../agent-identity-lab` already covers the OIDC branch in depth: a hand-rolled IdP with RS256 and
JWKS, Authorization Code + PKCE, refresh and lifetime mismatch, Token Exchange with nested `act`,
step-up consent, confused deputy. It has working code, tests, and attack scripts for all of it.

**Do not rebuild any of that here.** Before starting a chapter, check whether that repo already
covers it; if it does, link to the phase instead. This repo takes the ground OIDC does not cover.

---

## Layout

```
00-first-login-trace/     D1. library-based login + wire capture
02-authcode-pkce/         D1. the same flow with no library
internal/wiretrace/       shared HTTP recorder; the engine that makes mechanisms comparable
docker/keycloak/          realm-as-code for the local IdP
notes/comparison.md       the deliverable
notes/diagrams.md         Excalidraw index
```

Directory numbers are creation order, not reading order. Reading order is the A-D axes in the
root README.

Single Go module at the repo root.
Each chapter is a `main` package run with `go run ./NN-name`.
Shared helpers go in `internal/`, never copied between chapters.

## Workflows

```bash
make kc-up        # start Keycloak, block until discovery answers
make kc-reset     # wipe the volume and re-import realm-demo.json  <- after ANY realm edit
make kc-logs      # tail the IdP
make discovery    # dump the discovery document
make run-00       # run chapter 00
make check        # go vet + go build
```

The IdP is Keycloak `26.2`, pinned.
Do not move to `latest`: feature flag names change between releases and break a chapter two steps later.
Preview flags currently on: `token-exchange-standard:v2` (ch. 06), `dpop:v1` (ch. 08).

App port is `5556`.
`3000` collides with other dev servers and the collision surfaces as a confusing `redirect_uri` mismatch.

## Diagrams

Excalidraw workspace `kiyeon lab`, collection **`auth-from-scratch`** (`84eGDSACiLI`).
Index and links live in `notes/diagrams.md`; each chapter README links its own scenes.

Draw only what prose loses - spatial facts like which route a value takes, or what is absent from
a region. Scene naming is `NN · 제목`. Colours are fixed across scenes so they can be compared.

**Never pre-create empty scenes.** Create one only when filling it in the same turn; the `Main`
collection already has three abandoned shells from a session that did otherwise.

Full conventions are in the `auth-diagrams` skill. Read it before touching a scene.

## Rules that are easy to get wrong

**Realm config is code.**
`docker/keycloak/realm-demo.json` is the only source.
Never configure the demo realm by clicking in the admin console, and never add comment keys to the JSON: the importer rejects unknown fields and the server refuses to start.
After editing it, `make kc-reset`, not `make kc-up`.

**Libraries are banned outside chapter 00.**
Chapter 00 exists to capture the finished shape of a login.
Every later chapter reimplements a piece of it with the standard library plus crypto primitives only.

**Never commit `trace.md`.**
It holds real tokens issued by the local IdP.
Already gitignored.

**Attack repros stay local and inert.**
Each chapter demonstrates one failure by removing a check from *our own* code and showing what breaks.
Nothing in this repo targets a system we do not run.

## Chapter completion contract

A chapter is done when all four exist:

1. Working minimal code.
2. `ANSWERS.md` filled in, in the reader's own words, citing which trace step supports each answer.
3. One attack reproduction: remove a single check, show the break, put it back.
4. **A row added to `notes/comparison.md`.** Filled from what the chapter actually demonstrated,
   never guessed. An empty cell is better than an assumed one.

Use the `new-chapter` skill to scaffold this.
Use the `keycloak-lab` skill for IdP setup and troubleshooting.
Use the `auth-diagrams` skill when a concept is spatial and prose is losing.
Use the `spec-auditor` agent to diff an implementation against the RFC it claims to follow.
