---
name: new-chapter
description: Scaffold or finish a chapter in this repo. A chapter is done when it has working code that demonstrates the mechanism and a filled row in notes/comparison.md; attack repro and reflection prose are recommended, not required. Use when starting chapter NN or checking whether one is done.
---

# New chapter

A chapter is a `main` package at `NN-name/` plus a `README.md`.
It is **done** when the two required parts below exist. The rest is recommended.

## Before starting: check the boundary

`../agent-identity-lab` already covers the OIDC branch in depth (hand-rolled IdP with RS256/JWKS,
Authorization Code + PKCE, refresh, Token Exchange with nested `act`, step-up consent, confused
deputy, six attack scripts). **If the chapter you are about to write is covered there, stop and
link to the phase instead.** This repo takes what OIDC does not cover: sessions, logout, passkeys,
request signing, SAML.

## Required

1. **Working minimal code.** Standard library plus crypto primitives. No auth library outside
   chapter 00. Shared helpers live in `internal/`, never copy-pasted between chapters.
2. **A row in `notes/comparison.md`.** This is the repo's deliverable. Fill only cells the chapter
   actually demonstrated; leave the rest blank rather than guessing.

## Recommended (deepen understanding, skip when they teach nothing)

- **One attack reproduction.** Remove exactly one check from our own code, show what breaks,
  put it back. Inert, local, against our own IdP only.
- **A README paragraph** on what the previous approach failed at and what this one gave up.
- A `생각해볼 질문` section in the README — reflection prompts, not homework. There is **no
  answers file**; the answers live in the code and the trace. Do not create an ANSWERS.md.

## Files to create

```
NN-name/
├── README.md      goal, run instructions, checklist, reflection questions, traps
└── main.go        or several files if it genuinely needs them
```

Prose in these files is Korean, matching the root README.
Code comments are English.

## README skeleton

Mirror `00-first-login-trace/README.md`. Sections, in order:

- Title and one-paragraph statement of what this chapter takes apart, ideally naming what the
  previous approach failed at.
- `## 실행` - exact commands, starting from `make kc-up` when the IdP is needed.
- `## 체크리스트` - the checkbox list, copied from the chapter's entry in the root README.
- `## 생각해볼 질문` - reflection prompts. Add a line noting the answers are in the code and
  trace, not a separate file.
- `## 공격 재현` - (recommended) which single check gets removed and what is expected to break.
- `## 함정` - what actually went wrong while building it. Written after, not before.

## Wiring

- Add the chapter to the root `README.md` directory tree and 학습 순서 if it is not already there.
- Add a `run-NN` target to the `Makefile`.
- If it needs a new client or user, edit `docker/keycloak/realm-demo.json` and
  `make kc-reset`. See the `keycloak-lab` skill.
- If it makes HTTP calls worth comparing against chapter 00, use `internal/wiretrace`
  rather than ad-hoc logging, so the traces are diffable.
- New protocol terms discovered along the way go into `internal/wiretrace/glossary.go`
  so later traces annotate them automatically.

## Finishing check

Before calling a chapter done:

- `make check` passes.
- The flow was run end to end, not just unit tested.
- The `notes/comparison.md` row is filled from observed behaviour, with unproven cells left blank.
- If an attack repro was written, it was actually executed and its output is recorded.
- `trace.md` is not staged for commit.
