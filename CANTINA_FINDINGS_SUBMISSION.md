# Cantina × Revert Finance — `v4lend` Security Audit Findings Submission (`$50,000 USDC` Pool)

- **Competition Portal:** `https://cantina.xyz` (Revert Finance `v4lend` Public Security Audit Contest)
- **Target Repository:** `https://github.com/revert-finance/v4lend` (`main` branch, post-Scan #2 follow-up commit baseline)
- **Verification Suite:** `python CantinaRevertV4Lend2026/verify_v4lend_audit.py` (`exit code 0`, SHA-256: `15c2b82fb58d57acad9c91a6dc40558c21395e7f3a21d267593bbf1c6a83ff6a`)

---

## Finding `V4L-01` — [High / Medium] Incomplete `V4LE-96` Remediation in `RevertHookAutoLendActions`: Uncapped `redeem(shares)` Bricks `autoLendForceExit` Under High Utilization and Drops Swap Triggers on Failed `autoLendWithdraw`

### Target Files & Lines
- Primary: `src/hook/RevertHookAutoLendActions.sol#L271-L298` (`autoLendForceExit`) and `src/hook/RevertHookAutoLendActions.sol#L378-L387` (`autoLendWithdraw`)
- Caller Trigger Loop: `src/hook/RevertHook.sol#L244-L280` (`_afterSwap`) & `src/hook/RevertHookTriggers.sol#L180-L245`
- Reference Parity Contract: `src/automators/AutoLend.sol#L262-L335` (`withdraw`) and `src/automators/AutoLend.sol#L368-L420` (`forceExit`)

### Vulnerability Mechanics & Root Cause
During Audit Scan #2 (`V4LE-96`, documented in `docs/audit-scan2-findings.md` and `docs/audit-followup-fixes.md`), the protocol patched `src/automators/AutoLend.sol` so that when the underlying ERC-4626 lending vault (`V4Vault`) has high borrow utilization (`IERC4626(vault).maxRedeem(address(this)) < state.shares`):
1. `AutoLend.withdraw` caps redemption at `sharesToRedeem = Math.min(state.shares, IERC4626(state.vault).maxRedeem(address(this)))` and retains `residualShares = state.shares - sharesToRedeem`.
2. `AutoLend.forceExit` caps redemption at `sharesToRedeem` and transfers the unredeemable `residualShares` directly as ERC-4626 vault shares to `posOwner`, ensuring the emergency exit never reverts due to temporary vault illiquidity.

However, the parallel hook-managed implementation in **`src/hook/RevertHookAutoLendActions.sol`** was **not updated with the `V4LE-96` fix**:
1. **Emergency Exit Revert (`autoLendForceExit`, lines `271–298`):**
   ```solidity
   uint256 shares = state.autoLendShares;
   state.isLent = false;
   state.autoLendShares = 0;
   state.lentSide = 0;
   uint256 redeemedAmount = IERC4626(state.autoLendVault).redeem(shares, address(this), address(this));
   ```
   When `state.autoLendVault` is a `V4Vault` (or any ERC-4626 vault) whose liquid cash (`totalAssets() - totalDebtAssets`) is less than `convertToAssets(shares)`, `V4Vault._withdraw` (`src/vault/V4Vault.sol#L1230-L1232`) reverts with `InsufficientLiquidity()`. Consequently, the position owner's emergency escape hatch `autoLendForceExit(tokenId)` reverts unconditionally, locking 100% of the user's principal inside the hook even when substantial partial liquidity (e.g., 70–90% of principal) and transferable ERC-4626 shares are available.
2. **Silent Trigger Disarm on Failed `autoLendWithdraw` (`lines 378–387`):**
   ```solidity
   try IERC4626(state.autoLendVault).redeem(shares, address(this), address(this)) returns (uint256 redeemed) {
       redeemedAmount = redeemed;
   } catch {
       emit HookActionFailed(tokenId, ACTION_AUTOLEND_WITHDRAW);
       return;
   }
   ```
   When `_afterSwap` crosses the position's tick boundary, `RevertHookTriggers` pops the position from `_lowerTriggerAfterSwap` / `_upperTriggerAfterSwap` **before** calling `autoLendWithdraw`. When `redeem(shares)` reverts due to `shares > maxRedeem(address(this))`, the `catch` block returns early without re-registering the trigger or redeeming available liquidity. The position remains stuck in `state.isLent == true` with its swap trigger already consumed.

### Recommended Defensive Patch (Unified Diff)
```diff
--- a/src/hook/RevertHookAutoLendActions.sol
+++ b/src/hook/RevertHookAutoLendActions.sol
@@ -278,10 +278,20 @@ abstract contract RevertHookAutoLendActions is RevertHookTriggers {
         uint256 shares = state.autoLendShares;
+        IERC4626 vault = IERC4626(state.autoLendVault);
+        uint256 maxRedeemable = vault.maxRedeem(address(this));
+        uint256 sharesToRedeem = shares > maxRedeemable ? maxRedeemable : shares;
+        uint256 residualShares = shares - sharesToRedeem;
+
         state.isLent = false;
         state.autoLendShares = 0;
         state.lentSide = 0;
 
-        uint256 redeemedAmount = IERC4626(state.autoLendVault).redeem(shares, address(this), address(this));
+        uint256 redeemedAmount = sharesToRedeem > 0
+            ? vault.redeem(sharesToRedeem, address(this), address(this))
+            : 0;
+        if (residualShares > 0) {
+            IERC20(state.autoLendVault).safeTransfer(owner, residualShares);
+        }
```

---

## Finding `V4L-02` — [Medium] `V4Oracle._requireRecoveredToken` Bypasses Configured `recoveryPeriods[referenceToken]` After L2 Sequencer Restart

### Target Files & Lines
- `src/oracle/V4Oracle.sol#L129-L135` (`setRecoveryPeriod`)
- `src/oracle/V4Oracle.sol#L184-L203` (`_requireRecoveredToken` and `_requireRecoveredFeed`)

### Vulnerability Mechanics & Root Cause
`V4Oracle` allows governance to configure per-token post-sequencer-restart grace periods via `setRecoveryPeriod(address token, uint32 period)` (`line 129`), defaulting to `DEFAULT_RECOVERY_PERIOD = 1800` seconds when `period == 0`. However, inspect `_requireRecoveredToken` and `_requireRecoveredFeed` at `src/oracle/V4Oracle.sol#L184-L203`:

```solidity
function _requireRecoveredToken(address token, uint256 restart) internal view {
    if (token == referenceToken) return; // identity price; its feed is checked when used as denominator
    TokenConfig memory config = feedConfigs[token];
    if (config.mode == Mode.NOT_SET) revert OracleNotConfigured(token);
    uint256 elapsed = block.timestamp - restart;
    if (_usesChainlink(config.mode)) {
        _requireRecoveredFeed(token, restart);
        _requireRecoveredFeed(referenceToken, restart);
    }
    if (config.mode != Mode.CHAINLINK && elapsed < config.twapSeconds) revert SourceNotRecovered(token);
}

function _requireRecoveredFeed(address token, uint256 restart) internal view {
    if (token == chainlinkReferenceToken) return;
    uint256 elapsed = block.timestamp - restart;
    uint256 recoveryPeriod = recoveryPeriods[token];
    if (recoveryPeriod == 0) recoveryPeriod = DEFAULT_RECOVERY_PERIOD;
    if (elapsed < recoveryPeriod) revert SourceNotRecovered(token);
}
```

Three distinct bypass paths prevent `recoveryPeriods[referenceToken]` from taking effect after an L2 sequencer outage:
1. **Direct `referenceToken` queries (`line 185`):** `if (token == referenceToken) return;` unconditionally skips sequencer recovery checks even right after a sequencer restart (`elapsed < DEFAULT_RECOVERY_PERIOD`).
2. **`Mode.TWAP` token queries (`lines 190–194`):** When `config.mode == Mode.TWAP`, `_usesChainlink(config.mode)` is `false`, so `_requireRecoveredFeed(referenceToken, restart)` is never called. If `config.twapSeconds < DEFAULT_RECOVERY_PERIOD` (e.g., a 10-minute TWAP window vs a 30-minute or 1-hour sequencer recovery grace period), liquidations and borrows proceed before the L2 market has stabilized over the reference token's recovery window.
3. **`referenceToken == chainlinkReferenceToken` (`line 198`):** In deployments where `referenceToken == chainlinkReferenceToken` (e.g., USDC or USD-pegged base), `_requireRecoveredFeed(referenceToken, restart)` immediately hits `if (token == chainlinkReferenceToken) return;` at `line 198`, completely ignoring any custom `recoveryPeriods[referenceToken]` set by governance via `setRecoveryPeriod`.

### Recommended Defensive Patch (Unified Diff)
```diff
--- a/src/oracle/V4Oracle.sol
+++ b/src/oracle/V4Oracle.sol
@@ -182,11 +182,15 @@ contract V4Oracle is Ownable {
     function _requireRecoveredToken(address token, uint256 restart) internal view {
+        uint256 elapsed = block.timestamp - restart;
+        uint256 refRecovery = recoveryPeriods[referenceToken];
+        if (refRecovery == 0) refRecovery = DEFAULT_RECOVERY_PERIOD;
+        if (elapsed < refRecovery) revert SourceNotRecovered(referenceToken);
+
         if (token == referenceToken) return;
         TokenConfig memory config = feedConfigs[token];
         if (config.mode == Mode.NOT_SET) revert OracleNotConfigured(token);
-        uint256 elapsed = block.timestamp - restart;
         if (_usesChainlink(config.mode)) {
             _requireRecoveredFeed(token, restart);
-            _requireRecoveredFeed(referenceToken, restart);
         }
         if (config.mode != Mode.CHAINLINK && elapsed < config.twapSeconds) revert SourceNotRecovered(token);
     }
```

---

## Finding `V4L-03` — [Medium] `LeverageTransformer._getDummyTickRange` Uses Truncation-Toward-Zero Instead of Floor Division and Produces Misordered/Out-of-Bounds Ticks Near Pool Extremes

### Target Files & Lines
- Primary: `src/vault/transformers/LeverageTransformer.sol#L450-L477` (`_getDummyTickRange`)
- Reference Parity Contract: `src/hook/RevertHookTriggers.sol#L34-L38` (`_getTickLower`)

### Vulnerability Mechanics & Root Cause
`LeverageTransformer._getDummyTickRange` constructs a single-sided out-of-range tick interval `[dummyTickLower, dummyTickUpper]` to zap borrowed assets into an existing Uniswap v4 position during `leverageIn`:

```solidity
int24 roundedTick = (currentTick / tickSpacing) * tickSpacing;
if (otherToken == Currency.unwrap(poolKey.currency0)) {
    dummyTickLower = roundedTick + tickSpacing;
    dummyTickUpper = TickMath.maxUsableTick(tickSpacing);
} else {
    dummyTickLower = TickMath.minUsableTick(tickSpacing);
    dummyTickUpper = roundedTick - tickSpacing;
}
```

1. **Truncation-Toward-Zero on Negative Ticks (`line 459`):** Unlike `RevertHookTriggers._getTickLower` (`if (tick < 0 && tick % tickSpacing != 0) compressed--;`), Solidity's signed integer division `currentTick / tickSpacing` truncates toward zero. For `currentTick = -55` and `tickSpacing = 60`, `roundedTick` evaluates to `0` (`> currentTick`) instead of the floor tick `-60` (`<= currentTick`).
2. **Zero-Width / Misordered Tick Revert Near `minUsableTick` and `maxUsableTick` (`lines 467–475`):**
   - When `otherToken != currency0` and `currentTick` lies in `[minTick, minTick + tickSpacing]` (for `tickSpacing = 60`, `minTick = -887220` and `minTick + tickSpacing = -887160`), `roundedTick` is `-887160` (or `-887220` at `minTick`). Subtracting `tickSpacing` produces `dummyTickUpper = -887220 == dummyTickLower` (or `-887280 < dummyTickLower`), which reverts inside Uniswap v4 `Pool.modifyLiquidity` with `TicksMisordered` / `TickLowerOutOfBounds`.
   - Yet for any `currentTick >= minTick + tickSpacing` (including `currentTick = -887160`), the tick range `[minTick, floorTick]` (`[-887220, -887160]`) already satisfies `tickUpper <= currentTick` (`sqrtPriceAtTick(tickUpper) <= sqrtPriceX96`), requiring zero `currency0` (`amount0 == 0`) and 100% `currency1`. Subtracting an extra `tickSpacing` when `floorTick <= currentTick` unnecessarily shrinks the valid tick domain and bricks `leverageIn` near pool extremes.

### Recommended Defensive Patch (Unified Diff)
```diff
--- a/src/vault/transformers/LeverageTransformer.sol
+++ b/src/vault/transformers/LeverageTransformer.sol
@@ -456,19 +456,23 @@ contract LeverageTransformer is BaseTransformer {
         (, int24 currentTick,,) = StateLibrary.getSlot0(poolManager, poolKey.toId());
         int24 tickSpacing = poolKey.tickSpacing;
-        int24 roundedTick = (currentTick / tickSpacing) * tickSpacing;
+        int24 compressed = currentTick / tickSpacing;
+        if (currentTick < 0 && currentTick % tickSpacing != 0) {
+            compressed--;
+        }
+        int24 floorTick = compressed * tickSpacing;
 
         if (otherToken == Currency.unwrap(poolKey.currency0)) {
-            dummyTickLower = roundedTick + tickSpacing;
             dummyTickUpper = TickMath.maxUsableTick(tickSpacing);
+            dummyTickLower = floorTick + tickSpacing;
+            if (dummyTickLower >= dummyTickUpper) revert InvalidRange();
         } else {
             dummyTickLower = TickMath.minUsableTick(tickSpacing);
-            dummyTickUpper = roundedTick - tickSpacing;
+            dummyTickUpper = floorTick;
+            if (dummyTickUpper <= dummyTickLower) revert InvalidRange();
         }
     }
```

---

## Finding `V4L-04` — [Medium / Low] `V4Vault.dailyLendNetInflow` Zero-Clamping on Post-Reset Withdrawals Overstates Same-Day Net Inflow and Understates Next-Day `_settledLentAssets()`

### Target Files & Lines
- `src/vault/V4Vault.sol#L1214, L1239-L1243` (`_withdraw`)
- `src/vault/V4Vault.sol#L1634-L1659` (`_settledLentAssets` and `_resetDailyLendIncreaseLimit`)

### Vulnerability Mechanics & Root Cause
`V4Vault` enforces a daily lending supply growth rate limit (`MAX_DAILY_LEND_INCREASE_X32`) based on `_settledLentAssets()`, defined at `src/vault/V4Vault.sol#L1634-L1637`:
```solidity
function _settledLentAssets(uint256 totalAssets) internal view returns (uint256) {
    uint256 inflow = dailyLendNetInflow;
    return totalAssets > inflow ? totalAssets - inflow : 0;
}
```
And inside `_withdraw` (`lines 1214` and `1239–1242`):
```solidity
_resetDailyLendIncreaseLimit(totalAssets, false);
...
dailyLendIncreaseLimitLeft = dailyLendIncreaseLimitLeft + assets;
uint256 inflow = dailyLendNetInflow;
dailyLendNetInflow = assets < inflow ? inflow - assets : 0;
```
Consider a vault with `1,000,000 USDC` of settled supply at the end of Day 1 and a 10% daily increase limit (`100,000 USDC`):
1. At the start of Day 2 (`00:00:05 UTC`), an LP withdraws `200,000 USDC` of settled Day 1 supply.
2. `_resetDailyLendIncreaseLimit` runs first (`line 1214`), resetting `dailyLendNetInflow = 0` and setting `dailyLendIncreaseLimitLeft = 100,000 USDC`.
3. `_withdraw` then adds `+ 200,000 USDC` to `dailyLendIncreaseLimitLeft` (`= 300,000 USDC`), while `dailyLendNetInflow` is clamped at `0` (`assets < inflow ? inflow - assets : 0`).
4. Later on Day 2, `300,000 USDC` is deposited (`200,000 USDC` replacement + `100,000 USDC` new growth, bringing `totalAssets` to `1,100,000 USDC`). `_deposit` increments `dailyLendNetInflow` by the full `300,000 USDC` (`dailyLendNetInflow = 300,000 USDC`), even though net vault growth over Day 1's settled `1,000,000 USDC` is only `+100,000 USDC`!
5. Throughout the remainder of Day 2, `_settledLentAssets(1,100,000)` returns `1,100,000 - 300,000 = 800,000 USDC` (understating settled supply by `200,000 USDC`), and if `reserveProtect` or any mid-day recalibration queries `_settledLentAssets()`, it treats `200,000 USDC` of long-settled capital as unsettled same-day hot inflow.

### Recommended Defensive Patch (Unified Diff)
Snapshot `dailyOpeningSettledAssets` inside `_resetDailyLendIncreaseLimit` and compute `dailyLendNetInflow` directly as `totalAssetsAfter > dailyOpeningSettledAssets ? totalAssetsAfter - dailyOpeningSettledAssets : 0`.
