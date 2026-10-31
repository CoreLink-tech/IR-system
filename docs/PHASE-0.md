# Phase 0 — defect fixes (Watcher)

| Defect | Fix |
|--------|-----|
| Auto-block unreachable (max ~80, threshold 85) | Default threshold **70**; admin base score **45** |
| `login_failed` MEDIUM invisible for incidents | Base **30** + MEDIUM = 40; incident threshold **35** |
| INVESTIGATING/CONTAINED caused unique `open_key` 500 | Attach by `open_key` regardless of OPEN-only filter; race-safe insert |
| Event lost when incident insert failed | Insert **event first**, then incident/block |
| Retention deleted evidence for open incidents | Cron skips events linked to OPEN/INVESTIGATING/CONTAINED |
| Cron only on root `vercel.json` | Also declared in `web/vercel.json` |
| Docs overstated detection | See `DETECTION-CURRENT.md` |

**Not fixed in Phase 0:** shared (multi-instance) rate limits — still per isolate until Upstash/Redis is added.
