# Cantina × Revert Finance — `v4lend` Security Audit Submission Package (`$50,000 USDC` Cash Pool)

![Banner](banner.png)

## 1. Competition Overview & Live Cash Verification
- **Competition:** Cantina × Revert Finance — `v4lend` Security Audit Competition
- **Cash Prize Pool:** **`$50,000 USDC` Guaranteed Cash Pool**
- **Window:** October 6 – November 3, 2026
- **Portal:** `https://cantina.xyz`
- **Target Repository:** `https://github.com/revert-finance/v4lend` (`main` branch, post-Scan #2 follow-up baseline)

---

## 2. Summary of Verified Defensive Findings (`CANTINA_FINDINGS_SUBMISSION.md`)

| ID | Severity | Contract & Lines | Summary of Vulnerability & Defensive Remediation |
| :--- | :--- | :--- | :--- |
| **`V4L-01`** | **High / Medium** | `src/hook/RevertHookAutoLendActions.sol:271-298, 378-387` | **Incomplete Scan #2 `V4LE-96` Fix in Hook AutoLend:** While `src/automators/AutoLend.sol` was updated in Scan #2 (`V4LE-96`) to cap redemptions at `IERC4626(vault).maxRedeem(address(this))` and transfer residual ERC-4626 shares on `forceExit`, `RevertHookAutoLendActions` still calls `redeem(shares)` for 100% of `state.autoLendShares`. Under high vault utilization, `autoLendForceExit` reverts with `InsufficientLiquidity()`, and `autoLendWithdraw` catches the revert *after* `_afterSwap` has already popped the position's swap trigger. |
| **`V4L-02`** | **Medium** | `src/oracle/V4Oracle.sol:129-135, 184-203` | **L2 Sequencer Restart Reference-Token Recovery Bypass:** `_requireRecoveredToken` returns early for `token == referenceToken` (`line 185`), never checks `_requireRecoveredFeed(referenceToken, restart)` for `Mode.TWAP` tokens (`line 190`), and returns early inside `_requireRecoveredFeed` when `referenceToken == chainlinkReferenceToken` (`line 198`), bypassing governance-configured `recoveryPeriods[referenceToken]`. |
| **`V4L-03`** | **Medium** | `src/vault/transformers/LeverageTransformer.sol:450-477` | **Negative-Tick Truncation & Near-Boundary Revert in `_getDummyTickRange`:** Uses Solidity truncation-toward-zero `(currentTick / tickSpacing) * tickSpacing` instead of floor division (`RevertHookTriggers._getTickLower`), and unconditionally subtracts/adds `tickSpacing` at `[minTick, minTick + tickSpacing]` / `[maxTick - tickSpacing, maxTick]`, reverting with `TicksMisordered` during `leverageIn`. |
| **`V4L-04`** | **Medium / Low** | `src/vault/V4Vault.sol:1214, 1239-1243, 1634-1659` | **Post-Reset Withdrawal Zero-Clamping of `dailyLendNetInflow`:** When a new UTC day starts with a withdrawal of settled prior-day capital, `_resetDailyLendIncreaseLimit` zeroes `dailyLendNetInflow` before `_withdraw` clamps `inflow - assets` at `0`. Subsequent replacement deposits inflate `dailyLendNetInflow` and understate `_settledLentAssets()` by the withdrawal amount. |

---

## 3. Package Structure & Deterministic Verification

- [`CANTINA_FINDINGS_SUBMISSION.md`](CANTINA_FINDINGS_SUBMISSION.md) — Full copy-paste Cantina submission reports with line-by-line root cause analysis and unified diff patches.
- [`verify_v4lend_audit.py`](verify_v4lend_audit.py) — Deterministic defensive invariant & patch verification suite (`exit code 0`).
- [`v4lend_audit_verification_report.json`](v4lend_audit_verification_report.json) — Machine-verifiable JSON report with SHA-256 integrity hash (`15c2b82fb58d57acad9c91a6dc40558c21395e7f3a21d267593bbf1c6a83ff6a`).
- [`index.html`](index.html) — Interactive browser simulator for all 4 `v4lend` invariants.
- [`banner.png`](banner.png) — `1200x630` competition submission banner.

### Run Verification
```bash
python CantinaRevertV4Lend2026/verify_v4lend_audit.py
```
