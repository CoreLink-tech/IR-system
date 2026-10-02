# Reporting Engine

The reporting engine turns verified security data into plain-English reports for
two audiences: a non-technical owner or CEO, and the technical team. It is fully
deterministic. There is no AI in the loop: the same data always produces the same
report, and every number in a report comes from the database.

## How it works

1. `FactsService` reads facts about an incident from the database (event counts,
   the rules that fired, IP intelligence, blocks, the incident timeline).
2. Pure builder functions turn those facts into a report. Builders never touch the
   database and cannot invent facts. Wording lives in `rule-narratives.ts`.

## Report types

| Report            | Audience  | Content |
|-------------------|-----------|---------|
| Incident report   | CEO       | What happened, why it matters, risk level, evidence, action taken, current status, recommended action, and what the report cannot confirm |
| Technical report  | Engineers | Raw rule codes and reasons, event counts by type, top request paths, full IP intelligence, block history, incident timeline |
| Executive summary | CEO       | Overall posture, key numbers, incidents needing attention, notable incidents, trend against the previous period |

Each incident and summary report can also be rendered as plain text, ready for an
email or a PDF generator.

## Rules the engine follows

- Every sentence containing a number, time or address is built from a stored fact.
- Background text ("why it matters") is general knowledge about the attack type and
  makes no claim about the specific incident.
- Unknown is stated as unknown. Each report ends with "What this report cannot
  confirm", for example when no IP intelligence provider is configured, when the
  website never reports successful logins, or that block enforcement happens on the
  website side and cannot be verified here.
- Query strings are removed from request paths so tokens and personal data in URLs
  never reach a report.
- The risk shown is the highest score recorded on any event, never lower than the
  score stored on the incident.

## Executive posture

| Posture         | Meaning |
|-----------------|---------|
| `URGENT`        | A critical incident is open or under investigation |
| `ACTION_NEEDED` | A high incident is open or under investigation, or any open incident has no owner |
| `MONITORING`    | Other unresolved incidents remain |
| `ALL_CLEAR`     | Nothing unresolved |

## Evidence window

Activity for an incident is counted from the source address, from 60 minutes before
the incident was opened until it was resolved (or now, while it is open). The report
states this window in its limitations.

## Rule detail on events

Detection now stores which rules fired on each event (`security_events.matchedRules`,
a nullable JSON column). An empty list means "checked, nothing fired". A null value
means the event was recorded before this field existed; reports say so instead of
guessing. After updating, run `npx prisma db push` to add the column. The change is
additive and safe for existing data.

## Adding wording for a new rule

Add an entry to `NARRATIVES` in `src/reports/rule-narratives.ts` with a headline,
a `what` function that uses only `IncidentFacts`, a general `why`, and an `actions`
function. Rules without an entry get a safe generic description built from the rule's
stored name and description.
