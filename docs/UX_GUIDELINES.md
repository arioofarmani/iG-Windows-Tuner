# UX guidelines (3.3)

How every page of iG Windows Tuner is built, so the app stays calm, predictable and easy to use for everyone, including people with ADHD and other attention or memory differences.

**Sources**
- W3C [Making Content Usable for People with Cognitive and Learning Disabilities (COGA)](https://www.w3.org/TR/coga-usable/) design patterns.
- [WCAG 2.2](https://www.w3.org/TR/WCAG22/) AA contrast and focus rules, where they apply to a desktop app.

The checklist at the end is verified for every page in `docs\FINAL_REPORT_3.3.md`.

## 1. Attention first

- Every page opens with a **status summary** in one line (for example "2 things need attention" or "All 19 rules meet the recommendation") and **one primary action** (the accent button).
- Details sit behind expanders or in the details pane (progressive disclosure). Explanations come after the status, not before it.
- Lists show what needs attention first by default (sort by status), then everything else.

## 2. Small chunks

- Group items into short, labelled sections; show about 7 items before a "Show more" control.
- No walls of toggles: tweak pages are grouped by impact, and Focus mode hides advanced items.
- One idea per line of help text; hints start with a short first line, details go in the description.

## 3. Consistent placement

| Element | Place |
|---|---|
| Page header | Breadcrumb, title, one-line purpose, status summary, primary action, Refresh and "last updated" (always in this order) |
| Lists | SmartGrid: search and filter chips above, the "N of M shown" counter and "Clear filters" on the right, details pane on the right |
| Bulk actions | The sticky bar under the toolbar of a list, showing "N selected" |
| Staged changes | The bottom bar ("N pending", Preview, Apply, Discard); it is the same on every page |
| Messages | Inline result under the header, or a toast at the bottom right |

## 4. Status is never colour-only

- Every status has an icon and a word (On, Off, Below, Review, Needs attention, Locked).
- Text contrast is at least 4.5:1 against its background in every theme (checked by `tests\GuiTheme.Tests.ps1`); large text and non-text indicators at least 3:1.
- Keyboard focus is always visible: a 2 px focus ring in the accent or focus colour.

## 5. Immediate, visible feedback

- Every action shows what changed, inline or in a toast. Reversible actions get an **Undo** button in the toast for about 10 seconds.
- Long tasks show steps ("Step 2 of 4") and progress, and can be cancelled when the engine allows it.
- Buttons that cannot be used are visibly disabled (no accent fill), and their tooltip says why.

## 6. No surprises

- Confirmation dialogs only for risky actions, and they state the consequence in plain words ("Blocks inbound traffic for this program on public networks").
- Safe actions (sorting, filtering, opening details, previews, exports) never ask for confirmation.
- Refusals (a value that would turn a protection off) are shown inline next to the control, not in a dialog.

## 7. Keep my place

- The app remembers the last page, and per list the search, filters, sort, column layout, selection and scroll position, and which sections are expanded (`%LOCALAPPDATA%\iGWindowsTuner\gui-state.json`).
- Breadcrumbs show where you are. "Recently changed" on the Dashboard lists the last changes with Undo links.

## 8. Calm visuals

- No blinking and no auto-playing animation. Transitions are short (150 ms or less) and subtle.
- **Reduce motion** turns all transitions off; it is on automatically when Windows animation effects are off.
- Skeleton loaders are static (no shimmer).

## 9. Focus mode

A switch in the header. It hides advanced columns and sections and shows only "needs attention" and recommended items. Nothing is changed by the switch itself.

## 10. Readable text

- Sentence-case labels, plain language, no unexplained jargon.
- Body text 14 px or larger. Text size can be set from 100 to 150 %, and density can be Comfortable or Compact.
- Comfortable line length: long descriptions are limited to about 90 characters per line.
- Long text truncates with an ellipsis and shows the full text in a tooltip; nothing is clipped.

## 11. Wizards for multi-step flows

Firewall rule creation, ASR audit to block, and network optimization use wizards:
- a step counter ("Step 2 of 4") with Back and Next;
- no data is lost when going back;
- the last step summarizes what will change before anything changes.

## Checklist per page

| # | Check |
|---|---|
| C1 | Status summary line and one primary action at the top |
| C2 | Header in the standard order (breadcrumb, title, purpose, status, primary action, Refresh, last updated) |
| C3 | Details behind expanders or in the details pane |
| C4 | Sections of about 7 items with "Show more", or a SmartGrid |
| C5 | Status shown with icon and text; contrast 4.5:1 |
| C6 | Visible focus; every control has an accessible name |
| C7 | Inline result or toast for every action; Undo for reversible ones |
| C8 | Confirmation only for risky actions, with the consequence in plain words |
| C9 | Place, filters and sort remembered |
| C10 | No animation with Reduce motion; nothing blinks |
| C11 | Focus mode hides advanced content |
| C12 | Sentence case, 14 px body text, no clipping at 1100 x 720 and 200 % |
