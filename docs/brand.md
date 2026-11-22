# CHARADE Brand — Terminal Series

Source: [CHARADE.html](brand/CHARADE.html) (the brand page). The page is the visual
authority; this file translates it into terminal rules.

## Palette

| Token | Hex | Use |
|---|---|---|
| ground | `#111313` | Background |
| paper | `#e9e3cc` | Primary text |
| muted | `#a09c8c` | Secondary text, labels |
| line | `#383a34` | Borders, separators |
| accent | `#c7db7a` | Focus, success moment, header gradient |
| coral | `#dd6580` | Alerts, destructive emphasis |
| gold | `#f1be68` | Warnings, highlights |
| violet | `#a46e95` | Secondary accent |
| lime | `#a1d76b` | Optional success accent |

Typography on the web page is Archivo Black for display and Space Mono for body.
Terminals are monospace; use bold/dim/reverse for hierarchy rather than font
changes.

## Mascot

The chameleon is built from Unicode half blocks. It belongs in the header or splash,
never behind data. The wave field and psychedelic background belong to the brand page
or an optional paused header strip; data panes stay quiet.

## Motion

- Off by default.
- The only motion is the header mascot; pause with `Space`.
- Respect reduced-motion settings and `CHARADE_MOTION=off`.
- No motion while a confirmation dialog is open.

## Monochrome

`M` toggles monochrome. `NO_COLOR` forces it. Monochrome uses bold, dim, underline,
and reverse only. Status is never conveyed by color alone; every status has a glyph
and a word.

## Voice

Plain, direct, never shaming. Say what happened, what can be done next, what only the
owner can do, and what continues without them. No "obviously," no "simply," no
corporate hedging.

## TUI rules

- Dashboard-first; persistent header, side navigation, main pane, sticky footer.
- Bounded viewports for every stream; `e` expands, `f` follows.
- Every action is available as a CLI command.
- The plain mode (`charade tui --plain`) is a first-class fallback, not a punishment.
