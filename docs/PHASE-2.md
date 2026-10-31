# Phase 2 — detection intelligence (in progress)

## Shipped

| Feature | Implementation |
|---------|----------------|
| **Velocity windows** | DB counts over `windowMinutes` (multi-instance safe) |
| **brute_force** | `login_failed` count ≥ threshold → bonus score |
| **credential_stuffing** | Distinct `user_id` fails from one IP ≥ N |
| **wp_probe** | Log path hits (`wp-login` / `xmlrpc.php`) |
| **Entity IP score** | `entity_scores` with decay + contribution to risk |
| **Cooldown** | After auto-block, suppress re-block for N minutes |
| **Simulate** | `POST /api/v1/rules/simulate` backtest-lite for brute_force |
| **Migration** | `0003_phase2_detection` |

## Apply

```bash
cd web && npm run db:migrate
```

## Not yet

- Full sequence / absence rule DSL  
- ASN / device fingerprint signals  
- Formal backtest UI and precision tracking  
- ML (not justified yet)  
