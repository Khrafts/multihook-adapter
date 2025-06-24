// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBaseTest} from "./MultiHookAdapterBaseTest.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {HookWithEvents} from "../mocks/HookWithEvents.sol";
import {BeforeSwapHook} from "../mocks/BeforeSwapHook.sol";
import {
    BeforeSwapDelta, toBeforeSwapDelta, BeforeSwapDeltaLibrary
} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta, toBalanceDelta, BalanceDeltaLibrary, add} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {LPFeeLibrary} from "@uniswap/v4-core/src/libraries/LPFeeLibrary.sol";
import {Vm} from "forge-std/Vm.sol";
import "forge-std/console.sol";

contract BeforeSwapTest is MultiHookAdapterBaseTest {
    using PoolIdLibrary for PoolKey;

    // Basic SwapParams for testing
    SwapParams public testParams;

    // Hooks for testing (renamed to avoid conflicts with base class)
    BeforeSwapHook public swapDeltaHook1;
    BeforeSwapHook public swapDeltaHook2;
    BeforeSwapHook public regularSwapHook; // Hook without RETURNS_DELTA_FLAG

    function setUp() public override {
        super.setUp();

        // Set up standard test parameters for swap
        testParams = SwapParams({zeroForOne: true, amountSpecified: 1e18, sqrtPriceLimitX96: 0});

        // Deploy hooks with the correct flags
        deployCustomHooks();
    }

    function deployCustomHooks() private {
        // First hook with BEFORE_SWAP_FLAG | BEFORE_SWAP_RETURNS_DELTA_FLAG
        address hookAddress = address(uint160(0x3000 | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG));
        deployCodeTo("BeforeSwapHook.sol", "", hookAddress);
        swapDeltaHook1 = BeforeSwapHook(hookAddress);

        // Second hook with same flags but different address
        address secondHookAddress =
            address(uint160(0x4000 | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG));
        deployCodeTo("BeforeSwapHook.sol", "", secondHookAddress);
        swapDeltaHook2 = BeforeSwapHook(secondHookAddress);

        // Regular hook without RETURNS_DELTA_FLAG
        address regularHookAddress = address(uint160(0x5000 | Hooks.BEFORE_SWAP_FLAG));
        deployCodeTo("BeforeSwapHook.sol", "", regularHookAddress);
        regularSwapHook = BeforeSwapHook(regularHookAddress);
    }

    /////////////////////////
    // Core Behavior Tests //
    /////////////////////////

    // Test a simple case with one hook returning a delta and no fee override
    function test_BeforeSwap_Basic() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set return values - small delta values and no fee override (using flag)
        BeforeSwapDelta hookDelta = toBeforeSwapDelta(5, 10);
        swapDeltaHook1.setReturnValues(hookDelta, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(swapDeltaHook1);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Verify the hook was called
        assertTrue(swapDeltaHook1.wasCalled(), "Hook was not called");

        // Verify results
        assertEq(selector, IHooks.beforeSwap.selector, "Incorrect selector returned");
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(resultDelta),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(hookDelta),
            "Specified delta mismatch"
        );
        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(resultDelta),
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(hookDelta),
            "Unspecified delta mismatch"
        );
        assertEq(resultFee, LPFeeLibrary.OVERRIDE_FEE_FLAG, "Fee override mismatch");
    }

    // Test with multiple hooks and delta aggregation
    function test_BeforeSwap_MultipleHooks_DeltaAggregation() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set return values for multiple hooks
        BeforeSwapDelta delta1 = toBeforeSwapDelta(10, 20);
        BeforeSwapDelta delta2 = toBeforeSwapDelta(30, 40);
        swapDeltaHook1.setReturnValues(delta1, LPFeeLibrary.OVERRIDE_FEE_FLAG);
        swapDeltaHook2.setReturnValues(delta2, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Register both hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(swapDeltaHook1);
        hooks[1] = address(swapDeltaHook2);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Verify both hooks were called
        assertTrue(swapDeltaHook1.wasCalled(), "First hook was not called");
        assertTrue(swapDeltaHook2.wasCalled(), "Second hook was not called");

        // Verify deltas were aggregated correctly
        BeforeSwapDelta expectedCombinedDelta = _addBeforeSwapDelta(delta1, delta2);
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(resultDelta),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(expectedCombinedDelta),
            "Combined specified delta is incorrect"
        );
        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(resultDelta),
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(expectedCombinedDelta),
            "Combined unspecified delta is incorrect"
        );
    }

    ///////////////////////////////
    // Advanced Delta Tests      //
    ///////////////////////////////

    // Test with positive and negative delta values (mixed signs)
    function test_BeforeSwap_MixedSignDeltaAggregation() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set mixed sign delta values
        BeforeSwapDelta delta1 = toBeforeSwapDelta(10, -20); // positive specified, negative unspecified
        BeforeSwapDelta delta2 = toBeforeSwapDelta(-30, 40); // negative specified, positive unspecified
        swapDeltaHook1.setReturnValues(delta1, LPFeeLibrary.OVERRIDE_FEE_FLAG);
        swapDeltaHook2.setReturnValues(delta2, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Register both hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(swapDeltaHook1);
        hooks[1] = address(swapDeltaHook2);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Expected combined delta: (10 + (-30), (-20) + 40) = (-20, 20)
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(resultDelta),
            int128(-20),
            "Mixed sign specified delta is incorrect"
        );
        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(resultDelta),
            int128(20),
            "Mixed sign unspecified delta is incorrect"
        );
    }

    // Test with large delta values (close to int128 limits)
    function test_BeforeSwap_LargeValues() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Use large but safe values (not too close to int128 limits)
        int128 largePositive = type(int128).max / 10; // 10% of max int128
        int128 largeNegative = type(int128).min / 10 + 1; // 10% of min int128

        // Create delta values
        BeforeSwapDelta delta1 = toBeforeSwapDelta(largePositive, largeNegative);
        BeforeSwapDelta delta2 = toBeforeSwapDelta(largeNegative, largePositive);

        swapDeltaHook1.setReturnValues(delta1, LPFeeLibrary.OVERRIDE_FEE_FLAG);
        swapDeltaHook2.setReturnValues(delta2, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Register both hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(swapDeltaHook1);
        hooks[1] = address(swapDeltaHook2);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Since large +/- values should approximately cancel out
        // Due to potential asymmetry in int128, we allow for a small delta
        assert(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(resultDelta) < 2
                && BeforeSwapDeltaLibrary.getSpecifiedDelta(resultDelta) > -2
        );
        assert(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(resultDelta) < 2
                && BeforeSwapDeltaLibrary.getUnspecifiedDelta(resultDelta) > -2
        );
    }

    function test_BeforeSwap_fuzz(int120 value) public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Use large but safe values (not too close to int128 limits)
        int128 largePositive = int128(value);
        int128 largeNegative = -largePositive;

        // Create delta values
        BeforeSwapDelta delta1 = toBeforeSwapDelta(largePositive, largeNegative);
        BeforeSwapDelta delta2 = toBeforeSwapDelta(largeNegative, largePositive);

        swapDeltaHook1.setReturnValues(delta1, LPFeeLibrary.OVERRIDE_FEE_FLAG);
        swapDeltaHook2.setReturnValues(delta2, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Register both hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(swapDeltaHook1);
        hooks[1] = address(swapDeltaHook2);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Since large +/- values should approximately cancel out
        // Due to potential asymmetry in int128, we allow for a small delta
        assert(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(resultDelta) < 2
                && BeforeSwapDeltaLibrary.getSpecifiedDelta(resultDelta) > -2
        );
        assert(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(resultDelta) < 2
                && BeforeSwapDeltaLibrary.getUnspecifiedDelta(resultDelta) > -2
        );
    }

    ///////////////////////////////
    // Fee Override Tests        //
    ///////////////////////////////

    // Test with fee override
    function test_BeforeSwap_WithFeeOverride() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set return values with a fee override
        BeforeSwapDelta hookDelta = toBeforeSwapDelta(5, 10);
        uint24 customFee = 1234; // Some custom fee
        swapDeltaHook1.setReturnValues(hookDelta, customFee);

        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(swapDeltaHook1);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Verify fee override was applied
        assertEq(resultFee, customFee, "Fee override was not applied");
    }

    // Test fee override from hook without RETURNS_DELTA_FLAG
    function test_BeforeSwap_FeeOverride_WithoutDeltaFlag() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set return values with a fee override for the regular hook (without RETURNS_DELTA_FLAG)
        uint24 customFee = 500; // Some custom fee
        regularSwapHook.setReturnValues(BeforeSwapDelta.wrap(0), customFee);
        regularSwapHook.setHasDeltaFlag(false); // Set to behave as a hook without RETURNS_DELTA_FLAG

        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(regularSwapHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Verify fee override was applied despite not having RETURNS_DELTA_FLAG
        assertEq(resultFee, customFee, "Fee override should be applied for hook without RETURNS_DELTA_FLAG");

        // The delta should remain zero since this hook doesn't contribute to delta
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(resultDelta),
            int128(0),
            "Delta should remain zero for hook without RETURNS_DELTA_FLAG"
        );
    }

    // Test with no fee override (using OVERRIDE_FEE_FLAG)
    function test_BeforeSwap_NoFeeOverride() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set return values with OVERRIDE_FEE_FLAG to indicate no override
        BeforeSwapDelta hookDelta = toBeforeSwapDelta(5, 10);
        swapDeltaHook1.setReturnValues(hookDelta, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(swapDeltaHook1);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Verify no fee override is applied
        assertEq(resultFee, LPFeeLibrary.OVERRIDE_FEE_FLAG, "Fee should remain at OVERRIDE_FEE_FLAG");
    }

    // Test multiple hooks with fee overrides (last one should win)
    function test_BeforeSwap_MultipleHooks_FeeOverride() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set different fee overrides for each hook
        uint24 fee1 = 100;
        uint24 fee2 = 200;
        swapDeltaHook1.setReturnValues(toBeforeSwapDelta(0, 0), fee1);
        swapDeltaHook2.setReturnValues(toBeforeSwapDelta(0, 0), fee2);

        // Register both hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(swapDeltaHook1);
        hooks[1] = address(swapDeltaHook2);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Verify that the last hook's fee override was used
        assertEq(resultFee, fee2, "Last hook's fee override should be used");

        // Log for clarity
        console.log("First hook fee:", fee1);
        console.log("Second hook fee:", fee2);
        console.log("Result fee (should be second hook's fee):", resultFee);
    }

    ///////////////////////////////
    // Storage Tests             //
    ///////////////////////////////

    // Test the adapter correctly stores deltas from hooks
    function test_BeforeSwap_Storage() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        poolId = testPoolKey.toId();
        bytes memory hookData = "test data";

        // Set delta values
        BeforeSwapDelta delta1 = toBeforeSwapDelta(5, 10);
        BeforeSwapDelta delta2 = toBeforeSwapDelta(15, 20);
        swapDeltaHook1.setReturnValues(delta1, LPFeeLibrary.OVERRIDE_FEE_FLAG);
        swapDeltaHook2.setReturnValues(delta2, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Register both hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(swapDeltaHook1);
        hooks[1] = address(swapDeltaHook2);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeSwap to populate the storage
        adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Expose and check stored values
        BeforeSwapDelta[] memory storedDeltas = adapter.getBeforeSwapHookReturns(poolId);

        // Verify correct storage
        assertEq(storedDeltas.length, 2, "Should store 2 deltas");

        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas[0]),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(delta1),
            "Stored specified delta for hook 1 incorrect"
        );

        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas[1]),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(delta2),
            "Stored specified delta for hook 2 incorrect"
        );

        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(storedDeltas[0]),
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(delta1),
            "Stored unspecified delta for hook 1 incorrect"
        );

        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(storedDeltas[1]),
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(delta2),
            "Stored unspecified delta for hook 2 incorrect"
        );
    }

    // Test the adapter correctly clears deltas between calls
    function test_BeforeSwap_ClearStorage() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        poolId = testPoolKey.toId();
        bytes memory hookData = "test data";

        // Set delta values
        BeforeSwapDelta delta = toBeforeSwapDelta(5, 10);
        swapDeltaHook1.setReturnValues(delta, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Register one hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(swapDeltaHook1);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // First call to populate storage
        adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Verify current delta stored
        BeforeSwapDelta[] memory storedDeltas = adapter.getBeforeSwapHookReturns(poolId);
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas[0]),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(delta),
            "Should store updated delta value"
        );
        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(storedDeltas[0]),
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(delta),
            "Should store updated unspecified delta value"
        );

        // Change the delta value
        BeforeSwapDelta newDelta = toBeforeSwapDelta(50, 100);
        swapDeltaHook1.setReturnValues(newDelta, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Second call should clear previous values
        impersonatePoolManager(); // Re-impersonate before second call
        adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Check stored values
        storedDeltas = adapter.getBeforeSwapHookReturns(poolId);

        // Verify new value is stored
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas[0]),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(newDelta),
            "Should store updated delta value"
        );

        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(storedDeltas[0]),
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(newDelta),
            "Should store updated unspecified delta value"
        );
    }

    // Test multiple pools have separate storage
    function test_BeforeSwap_MultiplePoolStorage() public {
        // Setup
        address sender = address(0x123);
        bytes memory hookData = "test data";

        // Create two different pools
        PoolKey memory pool1 = createTestPoolKey();
        PoolKey memory pool2 = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 500, // Different fee for second pool
            tickSpacing: 10,
            hooks: IHooks(address(adapter))
        });

        PoolId poolId1 = pool1.toId();
        PoolId poolId2 = pool2.toId();

        // Set different delta values
        BeforeSwapDelta delta1 = toBeforeSwapDelta(10, 20);
        BeforeSwapDelta delta2 = toBeforeSwapDelta(30, 40);
        swapDeltaHook1.setReturnValues(delta1, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Register the hook with both pools
        address[] memory hooks = new address[](1);
        hooks[0] = address(swapDeltaHook1);
        adapter.registerHooks(pool1, hooks);
        adapter.registerHooks(pool2, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call for first pool
        adapter.beforeSwap(sender, pool1, testParams, hookData);

        // Update delta for second pool call
        swapDeltaHook1.setReturnValues(delta2, LPFeeLibrary.OVERRIDE_FEE_FLAG);

        // Call for second pool
        impersonatePoolManager(); // Re-impersonate before second call
        adapter.beforeSwap(sender, pool2, testParams, hookData);

        // Check stored values for both pools
        BeforeSwapDelta[] memory storedDeltas1 = adapter.getBeforeSwapHookReturns(poolId1);
        BeforeSwapDelta[] memory storedDeltas2 = adapter.getBeforeSwapHookReturns(poolId2);

        // Verify pools have separate storage
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas1[0]), int128(10), "Pool 1 should have its own delta"
        );
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas2[0]), int128(30), "Pool 2 should have its own delta"
        );
        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(storedDeltas1[0]),
            int128(20),
            "Pool 1 should have its own unspecified delta"
        );
        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(storedDeltas2[0]),
            int128(40),
            "Pool 2 should have its own unspecified delta"
        );
    }

    // Helper function to add BeforeSwapDeltas
    function _addBeforeSwapDelta(BeforeSwapDelta a, BeforeSwapDelta b) internal pure returns (BeforeSwapDelta) {
        BalanceDelta res = add(
            toBalanceDelta(BeforeSwapDeltaLibrary.getSpecifiedDelta(a), BeforeSwapDeltaLibrary.getUnspecifiedDelta(a)),
            toBalanceDelta(BeforeSwapDeltaLibrary.getSpecifiedDelta(b), BeforeSwapDeltaLibrary.getUnspecifiedDelta(b))
        );
        return toBeforeSwapDelta(BalanceDeltaLibrary.amount0(res), BalanceDeltaLibrary.amount1(res));
    }
}
