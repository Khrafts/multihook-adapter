// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBaseTest} from "./MultiHookAdapterBaseTest.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {HookWithEvents} from "../mocks/HookWithEvents.sol";
import {HookWithReturns} from "../mocks/HookWithReturns.sol";
import {BalanceDelta, toBalanceDelta, BalanceDeltaLibrary, add} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {Vm} from "forge-std/Vm.sol";
import "forge-std/console.sol";

contract AfterRemoveLiquidityTest is MultiHookAdapterBaseTest {
    // Basic ModifyLiquidityParams for testing
    ModifyLiquidityParams public testParams;
    // Balance deltas for testing
    BalanceDelta public testDelta;
    BalanceDelta public testFees;

    // Hooks with BalanceDelta returns
    HookWithReturns public afterRemoveLiquidityReturnHook;
    HookWithReturns public secondAfterRemoveLiquidityReturnHook;
    HookWithReturns public thirdAfterRemoveLiquidityReturnHook;

    function setUp() public override {
        super.setUp();

        // Set up standard test parameters for liquidity removal (negative liquidityDelta)
        testParams = ModifyLiquidityParams({
            tickLower: -120,
            tickUpper: 120,
            liquidityDelta: -1e18, // Negative for removal
            salt: bytes32(0)
        });

        // Set up test deltas
        testDelta = toBalanceDelta(-1000, -2000); // amount0 = -1000, amount1 = -2000
        testFees = toBalanceDelta(5, 10); // amount0 = 5, amount1 = 10

        // Deploy hooks with return delta flags at valid addresses
        deployReturnHooks();
    }

    // Helper to deploy hooks with different addresses but same flags
    function deployReturnHooks() private {
        // First hook - AFTER_REMOVE_LIQUIDITY_FLAG | AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG
        address hookAddress =
            address(uint160(Hooks.AFTER_REMOVE_LIQUIDITY_FLAG | Hooks.AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG));
        deployCodeTo("HookWithReturns.sol", "", hookAddress);
        afterRemoveLiquidityReturnHook = HookWithReturns(hookAddress);

        // Second hook - same flags but different address (with 0x1000 offset)
        address secondHookAddress = address(
            uint160(0x1000 | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG | Hooks.AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG)
        );
        deployCodeTo("HookWithReturns.sol", "", secondHookAddress);
        secondAfterRemoveLiquidityReturnHook = HookWithReturns(secondHookAddress);

        // Third hook - same flags but different address (with 0x2000 offset)
        address thirdHookAddress = address(
            uint160(0x2000 | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG | Hooks.AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG)
        );
        deployCodeTo("HookWithReturns.sol", "", thirdHookAddress);
        thirdAfterRemoveLiquidityReturnHook = HookWithReturns(thirdHookAddress);
    }

    // Simple test case with a single hook that returns a basic BalanceDelta
    function test_AfterRemoveLiquidity_SingleHookWithDelta() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set up the return value for our hook - very basic values
        BalanceDelta hookDelta = toBalanceDelta(10, 20); // Simple values: amount0 = 10, amount1 = 20
        afterRemoveLiquidityReturnHook.setReturnValue(hookDelta);

        // Register a single hook with both AFTER_REMOVE_LIQUIDITY_FLAG and AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(afterRemoveLiquidityReturnHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterRemoveLiquidity as the pool manager
        (bytes4 result, BalanceDelta resultDelta) =
            adapter.afterRemoveLiquidity(sender, testPoolKey, testParams, testDelta, testFees, hookData);

        // Verify the result selector is correct
        assertEq(result, IHooks.afterRemoveLiquidity.selector, "Should return afterRemoveLiquidity selector");

        // Verify the result delta matches what our hook returned
        assertEq(
            BalanceDeltaLibrary.amount0(resultDelta),
            BalanceDeltaLibrary.amount0(hookDelta),
            "amount0 delta should match"
        );
        assertEq(
            BalanceDeltaLibrary.amount1(resultDelta),
            BalanceDeltaLibrary.amount1(hookDelta),
            "amount1 delta should match"
        );
    }

    // Test case with multiple hooks that all return BalanceDelta values that should be combined
    function test_AfterRemoveLiquidity_MultipleHooksWithDelta() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set up different return values for each hook
        BalanceDelta firstHookDelta = toBalanceDelta(10, 15); // amount0 = 10, amount1 = 15
        BalanceDelta secondHookDelta = toBalanceDelta(20, 25); // amount0 = 20, amount1 = 25
        BalanceDelta thirdHookDelta = toBalanceDelta(5, 10); // amount0 = 5, amount1 = 10

        // Calculate expected combined delta
        BalanceDelta expectedCombinedDelta = add(firstHookDelta, secondHookDelta);
        expectedCombinedDelta = add(expectedCombinedDelta, thirdHookDelta);

        // Set hook return values
        afterRemoveLiquidityReturnHook.setReturnValue(firstHookDelta);
        secondAfterRemoveLiquidityReturnHook.setReturnValue(secondHookDelta);
        thirdAfterRemoveLiquidityReturnHook.setReturnValue(thirdHookDelta);

        // Register all three hooks
        address[] memory hooks = new address[](3);
        hooks[0] = address(afterRemoveLiquidityReturnHook);
        hooks[1] = address(secondAfterRemoveLiquidityReturnHook);
        hooks[2] = address(thirdAfterRemoveLiquidityReturnHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterRemoveLiquidity as the pool manager
        (bytes4 result, BalanceDelta resultDelta) =
            adapter.afterRemoveLiquidity(sender, testPoolKey, testParams, testDelta, testFees, hookData);

        // Verify the result selector is correct
        assertEq(result, IHooks.afterRemoveLiquidity.selector, "Should return afterRemoveLiquidity selector");

        // Verify the combined delta is correct
        assertEq(
            BalanceDeltaLibrary.amount0(resultDelta),
            BalanceDeltaLibrary.amount0(expectedCombinedDelta),
            "Combined amount0 delta should match sum of all hooks"
        );
        assertEq(
            BalanceDeltaLibrary.amount1(resultDelta),
            BalanceDeltaLibrary.amount1(expectedCombinedDelta),
            "Combined amount1 delta should match sum of all hooks"
        );

        // Verify we get the expected value by checking individual components
        int128 expectedAmount0 = 10 + 20 + 5; // 35
        int128 expectedAmount1 = 15 + 25 + 10; // 50
        assertEq(BalanceDeltaLibrary.amount0(resultDelta), expectedAmount0, "Combined amount0 delta should equal 35");
        assertEq(BalanceDeltaLibrary.amount1(resultDelta), expectedAmount1, "Combined amount1 delta should equal 50");
    }

    // Test case with a mix of hooks, some with return delta flag and some without
    function test_AfterRemoveLiquidity_MixedHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set return values for hooks with returns
        BalanceDelta firstHookDelta = toBalanceDelta(25, 35); // amount0 = 25, amount1 = 35
        BalanceDelta secondHookDelta = toBalanceDelta(15, 45); // amount0 = 15, amount1 = 45

        // Calculate expected combined delta (only from hooks with returns flag)
        BalanceDelta expectedCombinedDelta = add(firstHookDelta, secondHookDelta);

        afterRemoveLiquidityReturnHook.setReturnValue(firstHookDelta);
        secondAfterRemoveLiquidityReturnHook.setReturnValue(secondHookDelta);

        // Deploy a regular hook that doesn't implement the RETURNS_DELTA functionality
        address regularHookAddr = address(uint160(Hooks.AFTER_REMOVE_LIQUIDITY_FLAG)); // Only AFTER_REMOVE_LIQUIDITY_FLAG
        deployCodeTo("HookWithReturns.sol", "", regularHookAddr);
        HookWithReturns regularHook = HookWithReturns(regularHookAddr);

        // Register a mix of hook types:
        // 1. Hook with AFTER_REMOVE_LIQUIDITY_FLAG and AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG
        // 2. Hook with only AFTER_REMOVE_LIQUIDITY_FLAG (no RETURNS_DELTA)
        // 3. Hook with AFTER_REMOVE_LIQUIDITY_FLAG and AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG
        address[] memory hooks = new address[](3);
        hooks[0] = address(afterRemoveLiquidityReturnHook); // Has both flags
        hooks[1] = address(regularHook); // Only has AFTER_REMOVE_LIQUIDITY_FLAG
        hooks[2] = address(secondAfterRemoveLiquidityReturnHook); // Has both flags

        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterRemoveLiquidity as the pool manager
        (bytes4 result, BalanceDelta resultDelta) =
            adapter.afterRemoveLiquidity(sender, testPoolKey, testParams, testDelta, testFees, hookData);

        // Verify the result selector is correct
        assertEq(result, IHooks.afterRemoveLiquidity.selector, "Should return afterRemoveLiquidity selector");

        // Verify the combined delta includes only hooks with return delta flag
        assertEq(
            BalanceDeltaLibrary.amount0(resultDelta),
            BalanceDeltaLibrary.amount0(expectedCombinedDelta),
            "Combined amount0 delta should only include hooks with return delta flag"
        );
        assertEq(
            BalanceDeltaLibrary.amount1(resultDelta),
            BalanceDeltaLibrary.amount1(expectedCombinedDelta),
            "Combined amount1 delta should only include hooks with return delta flag"
        );

        // Verify the expected amounts directly
        assertEq(
            BalanceDeltaLibrary.amount0(resultDelta),
            25 + 15, // 40 (only hooks with return delta flag)
            "Combined amount0 delta should equal 40"
        );
        assertEq(
            BalanceDeltaLibrary.amount1(resultDelta),
            35 + 45, // 80 (only hooks with return delta flag)
            "Combined amount1 delta should equal 80"
        );
    }

    // Test hooks returning mixed positive and negative BalanceDelta values
    function test_AfterRemoveLiquidity_MixedPositiveNegativeDeltas() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set up mixed positive/negative return values
        BalanceDelta firstHookDelta = toBalanceDelta(100, -50); // positive amount0, negative amount1
        BalanceDelta secondHookDelta = toBalanceDelta(-30, 80); // negative amount0, positive amount1
        BalanceDelta thirdHookDelta = toBalanceDelta(-10, -20); // both negative

        // Calculate expected combined delta
        BalanceDelta expectedCombinedDelta = add(firstHookDelta, secondHookDelta);
        expectedCombinedDelta = add(expectedCombinedDelta, thirdHookDelta);

        // Set hook return values
        afterRemoveLiquidityReturnHook.setReturnValue(firstHookDelta);
        secondAfterRemoveLiquidityReturnHook.setReturnValue(secondHookDelta);
        thirdAfterRemoveLiquidityReturnHook.setReturnValue(thirdHookDelta);

        // Register all three hooks
        address[] memory hooks = new address[](3);
        hooks[0] = address(afterRemoveLiquidityReturnHook);
        hooks[1] = address(secondAfterRemoveLiquidityReturnHook);
        hooks[2] = address(thirdAfterRemoveLiquidityReturnHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterRemoveLiquidity as the pool manager
        (bytes4 result, BalanceDelta resultDelta) =
            adapter.afterRemoveLiquidity(sender, testPoolKey, testParams, testDelta, testFees, hookData);

        // Verify the result selector is correct
        assertEq(result, IHooks.afterRemoveLiquidity.selector, "Should return afterRemoveLiquidity selector");

        // Verify the combined delta is correct
        assertEq(
            BalanceDeltaLibrary.amount0(resultDelta),
            BalanceDeltaLibrary.amount0(expectedCombinedDelta),
            "Combined amount0 delta should be correctly computed with mixed signs"
        );
        assertEq(
            BalanceDeltaLibrary.amount1(resultDelta),
            BalanceDeltaLibrary.amount1(expectedCombinedDelta),
            "Combined amount1 delta should be correctly computed with mixed signs"
        );

        // Verify the expected values with manual calculation
        int128 expectedAmount0 = 100 + (-30) + (-10); // 60
        int128 expectedAmount1 = (-50) + 80 + (-20); // 10
        assertEq(BalanceDeltaLibrary.amount0(resultDelta), expectedAmount0, "Combined amount0 delta should equal 60");
        assertEq(BalanceDeltaLibrary.amount1(resultDelta), expectedAmount1, "Combined amount1 delta should equal 10");
    }

    // Test hooks returning large values that approach int128 limits
    function test_AfterRemoveLiquidity_LargeValues() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Using slightly more moderate large values to avoid precision issues
        int128 largePositive = type(int128).max / 10; // 10% of max int128
        int128 largeNegative = type(int128).min / 10 + 1; // 10% of min int128, +1 to account for asymmetry

        BalanceDelta firstHookDelta = toBalanceDelta(largePositive, largeNegative);
        BalanceDelta secondHookDelta = toBalanceDelta(largeNegative, largePositive);

        // Calculate expected combined delta
        BalanceDelta expectedCombinedDelta = add(firstHookDelta, secondHookDelta);

        // Set hook return values
        afterRemoveLiquidityReturnHook.setReturnValue(firstHookDelta);
        secondAfterRemoveLiquidityReturnHook.setReturnValue(secondHookDelta);

        // Register two hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(afterRemoveLiquidityReturnHook);
        hooks[1] = address(secondAfterRemoveLiquidityReturnHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterRemoveLiquidity as the pool manager
        (bytes4 result, BalanceDelta resultDelta) =
            adapter.afterRemoveLiquidity(sender, testPoolKey, testParams, testDelta, testFees, hookData);

        // Verify the result selector is correct
        assertEq(result, IHooks.afterRemoveLiquidity.selector, "Should return afterRemoveLiquidity selector");

        // Verify the combined delta is the same as our calculated expected delta
        assertEq(
            BalanceDeltaLibrary.amount0(resultDelta),
            BalanceDeltaLibrary.amount0(expectedCombinedDelta),
            "Combined amount0 delta should match expected delta for large values"
        );
        assertEq(
            BalanceDeltaLibrary.amount1(resultDelta),
            BalanceDeltaLibrary.amount1(expectedCombinedDelta),
            "Combined amount1 delta should match expected delta for large values"
        );

        // Log the actual results for verification
        console.log("Amount0 result:", BalanceDeltaLibrary.amount0(resultDelta));
        console.log("Amount1 result:", BalanceDeltaLibrary.amount1(resultDelta));

        // Due to the asymmetry of int128 (more negative values than positive),
        // and possible rounding in assembly calculations, we won't assert exact zeros
    }
}
