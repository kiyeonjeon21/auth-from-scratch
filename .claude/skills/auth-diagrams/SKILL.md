---
name: auth-diagrams
description: Draw or update an Excalidraw diagram for a chapter of this repo, following the repo's collection, naming, colour and layout conventions. Use when a concept is spatial - what passes through where, what is absent from where - and prose is losing.
---

# Auth diagrams

Diagrams live in the Excalidraw workspace `kiyeon lab`, collection **`auth-from-scratch`**
(`collectionId: 84eGDSACiLI`, `workspace: AU3bkHPBsIE`).
Scene URLs are `https://app.excalidraw.com/s/AU3bkHPBsIE/<sceneId>`.

## Draw only what prose loses

Draw when the idea is **spatial**: what route a value takes, what is present in one region and
absent from another, what converges. Front channel versus back channel is the archetype.

Do not draw a picture of a list. If the content is a sequence of facts with no geometry, a table
in the chapter README is better and cheaper to maintain.

## Non-negotiables

- **Call `read_diagram_format` first**, once per session, before any scene write.
- **Never pre-create empty scenes.** The `Main` collection in this workspace has three
  zero-element scenes left by a session that created shells and never filled them. Create a scene
  only when you are about to fill it in the same turn.
- **Always `take_screenshot` and look at it.** Layout bugs (overlap, clipped text, stair-stepped
  arrows) are invisible from the payload. Iterate until the render is clean. Never report a
  diagram as done without having viewed it.
- **New elements land at the bottom of the z-order.** An element added in a later
  `edit_scene_content` call gets index `a0` and renders *underneath* anything added earlier,
  including opaque lane rectangles. Either write the whole scene in one call, or place late
  additions where no filled shape sits behind them, or fold the text into an element that is
  already visible.
- Update `notes/diagrams.md` with the new scene, and link it from the chapter README.

## Layout

**Two or more actors means swimlanes**, hand-built with `edit_scene_content`. `create_diagram`
cannot hold rows aligned across lanes.

**Put the browser lane in the middle.** Lane order `앱 | 브라우저 | Keycloak`. Then front-channel
hops visibly step through the middle lane and back-channel hops visibly skip it. The layout does
the teaching; without this the diagram is just prose in boxes.

Put a small box in the browser lane at every front-channel hop stating what leaks there
("주소창에 그대로 보인다 · 가루 · state · nonce"). The back-channel section then reads as an
absence, which is the point. Say so explicitly once, at the channel boundary.

Single-actor transformations (PKCE, JWT structure, token nesting) are hand-built too: a
transformation chain with a fork, plus an attacker section below a divider.

## Style

| | |
|---|---|
| `roughness` | `1` (hand-drawn). Study notes, not deliverables |
| `roundness` | `{"type": 3}` |
| prose labels | `fontFamily: 5` |
| headings, lane titles | `fontFamily: 7` |
| ASCII identifiers only | `fontFamily: 8` - `localhost:5556`, `code_verifier`. **Never Korean text in family 8** |
| language | Korean, matching repo prose |

Colours, consistent across every scene so they can be read side by side:

| meaning | background | stroke |
|---|---|---|
| 앱 | `#d0ebff` | `#1971c2` |
| Keycloak | `#f3f0ff` | `#6741d9` |
| 프론트채널 / 노출되는 자리 | `#fff4e6` | `#fd7e14` |
| 백채널 (arrows, width 4) | | `#0c8599` |
| 공격자 / 차단 | `#ffe3e3` | `#e03131` |
| 중립 연산 | `#f1f3f5` | `#495057` |

A blocked path uses a red arrow with `endArrowhead: "bar"`. It reads as a terminator, which is
exactly what "you cannot get from the hash back to the original" means.

Every arrow that points at a shape needs `startBinding` and `endBinding` with `mode: "inside"`.
Align the two bound edges on the same axis or the elbow router inserts a visible stair step - a
7px difference in box centres is enough to produce one.

## Procedure

1. `read_diagram_format`
2. `create_scene` into `84eGDSACiLI`, named `NN · 제목`, `pinned: true`
3. One `edit_scene_content` call for the whole scene
4. `take_screenshot`, inspect, fix, repeat
5. Update `notes/diagrams.md` and the chapter README
