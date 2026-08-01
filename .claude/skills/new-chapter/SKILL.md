---
name: new-chapter
description: Scaffold or finish a chapter in this repo so it satisfies the three-part completion contract - working code, ANSWERS.md, and one attack reproduction. Use when starting chapter NN, or when checking whether a chapter is actually done.
---

# New chapter

A chapter is a `main` package at `NN-name/` plus two Markdown files.
It is **done** only when all three parts exist. Code alone is not done.

## The contract

1. **Working minimal code.** Standard library plus crypto primitives. No OIDC/OAuth/JOSE library
   outside chapter 00. Shared helpers live in `internal/`, never copy-pasted between chapters.
2. **`ANSWERS.md`.** Every question from the chapter README answered in the reader's own words,
   citing the trace step or code line that supports it. Spec quotes are not answers.
3. **One attack reproduction.** Remove exactly one check from our own code, show what breaks,
   put it back. Inert, local, against our own IdP only.

## Files to create

```
NN-name/
├── README.md      goal, run instructions, checklist, questions, traps
├── ANSWERS.md     the questions again, each with a "> (미작성)" placeholder
└── main.go        or several files if it genuinely needs them
```

Prose in these files is Korean, matching the root README.
Code comments are English.

## README skeleton

Mirror `00-first-login-trace/README.md`. Sections, in order:

- Title and one-paragraph statement of what this chapter takes apart.
- `## 실행` - exact commands, starting from `make kc-up`.
- `## 체크리스트` - the checkbox list, copied from the chapter's entry in the root README.
- `## 공격 재현` - which single check gets removed and what is expected to break.
- `## 답할 수 있어야 하는 질문` - copied from the root README, plus anything the
  implementation surfaced.
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
- The flow was run end to end in a browser, not just unit tested.
- `ANSWERS.md` has no `(미작성)` left.
- The attack repro was actually executed and its observed output is written down.
- `trace.md` is not staged for commit.
