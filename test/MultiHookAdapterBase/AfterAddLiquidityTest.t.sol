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

contract AfterAddLiquidityTest is MultiHookAdapterBaseTest {
    // Basic ModifyLiquidityParams for testing
    ModifyLiquidityParams public testParams;
    // Balance deltas for testing
    BalanceDelta public testDelta;
    BalanceDelta public testFees;

    // Hooks with BalanceDelta returns
    HookWithReturns public afterAddLiquidityReturnHook;
    HookWithReturns public secondAfterAddLiquidityReturnHook;
    HookWithReturns public thirdAfterAddLiquidityReturnHook;

    function setUp() public override {
        super.setUp();

        // Set up standard test parameters for liquidity addition (positive liquidityDelta)
        testParams = ModifyLiquidityParams({
            tickLower: -120,
            tickUpper: 120,
            liquidityDelta: 1e18, // Positive for addition
            salt: bytes32(0)
        });

        // Set up test deltas
        testDelta = toBalanceDelta(1000, 2000); // amount0 = 1000, amount1 = 2000
        testFees = toBalanceDelta(10, 20); // amount0 = 10, amount1 = 20

        // Deploy hooks with return delta flags at valid addresses
        deployReturnHooks();
    }

    // Helper to deploy hooks with different addresses but same flags
    function deployReturnHooks() private {
        // First hook - AFTER_ADD_LIQUIDITY_FLAG | AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG
        address hookAddress =
            address(uint160(Hooks.AFTER_ADD_LIQUIDITY_FLAG | Hooks.AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG));
        deployCodeTo("HookWithReturns.sol", "", hookAddress);
        afterAddLiquidityReturnHook = HookWithReturns(hookAddress);

        // Second hook - same flags but different address (with 0x1000 offset)
        address secondHookAddress =
            address(uint160(0x1000 | Hooks.AFTER_ADD_LIQUIDITY_FLAG | Hooks.AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG));
        deployCodeTo("HookWithReturns.sol", "", secondHookAddress);
        secondAfterAddLiquidityReturnHook = HookWithReturns(secondHookAddress);

        // Third hook - same flags but different address (with 0x2000 offset)
        address thirdHookAddress =
            address(uint160(0x2000 | Hooks.AFTER_ADD_LIQUIDITY_FLAG | Hooks.AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG));
        deployCodeTo("HookWithReturns.sol", "", thirdHookAddress);
        thirdAfterAddLiquidityReturnHook = HookWithReturns(thirdHookAddress);
    }

    // Simple test case with a single hook that returns a BalanceDelta
    function test_AfterAddLiquidity_SingleHookWithDelta() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set up the return value for our hook
        BalanceDelta hookDelta = toBalanceDelta(100, 200); // amount0 = 100, amount1 = 200
        afterAddLiquidityReturnHook.setReturnValue(hookDelta);

        // Register a single hook with both AFTER_ADD_LIQUIDITY_FLAG and AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(afterAddLiquidityReturnHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterAddLiquidity as the pool manager
        (bytes4 result, BalanceDelta resultDelta) =
            adapter.afterAddLiquidity(sender, testPoolKey, testParams, testDelta, testFees, hookData);

        // Verify the result selector is correct
        assertEq(result, IHooks.afterAddLiquidity.selector, "Should return afterAddLiquidity selector");

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
    function test_AfterAddLiquidity_MultipleHooksWithDelta() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set up different return values for each hook
        BalanceDelta firstHookDelta = toBalanceDelta(100, 200); // amount0 = 100, amount1 = 200
        BalanceDelta secondHookDelta = toBalanceDelta(300, 400); // amount0 = 300, amount1 = 400
        BalanceDelta thirdHookDelta = toBalanceDelta(50, 150); // amount0 = 50, amount1 = 150

        // Calculate expected combined delta
        BalanceDelta expectedCombinedDelta = add(firstHookDelta, secondHookDelta);
        expectedCombinedDelta = add(expectedCombinedDelta, thirdHookDelta);

        // Set hook return values
        afterAddLiquidityReturnHook.setReturnValue(firstHookDelta);
        secondAfterAddLiquidityReturnHook.setReturnValue(secondHookDelta);
        thirdAfterAddLiquidityReturnHook.setReturnValue(thirdHookDelta);

        // Register all three hooks
        address[] memory hooks = new address[](3);
        hooks[0] = address(afterAddLiquidityReturnHook);
        hooks[1] = address(secondAfterAddLiquidityReturnHook);
        hooks[2] = address(thirdAfterAddLiquidityReturnHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterAddLiquidity as the pool manager
        (bytes4 result, BalanceDelta resultDelta) =
            adapter.afterAddLiquidity(sender, testPoolKey, testParams, testDelta, testFees, hookData);

        // Verify the result selector is correct
        assertEq(result, IHooks.afterAddLiquidity.selector, "Should return afterAddLiquidity selector");

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
        int128 expectedAmount0 = 100 + 300 + 50; // 450
        int128 expectedAmount1 = 200 + 400 + 150; // 750
        assertEq(BalanceDeltaLibrary.amount0(resultDelta), expectedAmount0, "Combined amount0 delta should equal 450");
        assertEq(BalanceDeltaLibrary.amount1(resultDelta), expectedAmount1, "Combined amount1 delta should equal 750");
    }

    // Test case with a mix of hooks, some with return delta flag and some without
    function test_AfterAddLiquidity_MixedHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Set return values for hooks with returns
        BalanceDelta firstHookDelta = toBalanceDelta(100, 200); // amount0 = 100, amount1 = 200
        BalanceDelta secondHookDelta = toBalanceDelta(300, 400); // amount0 = 300, amount1 = 400

        // Calculate expected combined delta (only from hooks with returns flag)
        BalanceDelta expectedCombinedDelta = add(firstHookDelta, secondHookDelta);

        afterAddLiquidityReturnHook.setReturnValue(firstHookDelta);
        secondAfterAddLiquidityReturnHook.setReturnValue(secondHookDelta);

        // First, check if the HookWithEvents has a compatible afterAddLiquidity function signature
        // We need a regular hook that doesn't implement the RETURNS_DELTA functionality but still
        // has the compatible parameter list for afterAddLiquidity

        // We're going to test using a HookWithReturns for the regular hook too, but without the RETURNS_DELTA flag
        // This ensures it will have the right parameter signature
        address regularHookAddr = address(uint160(0x3000 | Hooks.AFTER_ADD_LIQUIDITY_FLAG)); // Only AFTER_ADD_LIQUIDITY_FLAG
        deployCodeTo("HookWithReturns.sol", "", regularHookAddr);
        HookWithReturns regularHook = HookWithReturns(regularHookAddr);

        // Register a mix of hook types:
        // 1. Hook with AFTER_ADD_LIQUIDITY_FLAG and AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG
        // 2. Hook with only AFTER_ADD_LIQUIDITY_FLAG (no RETURNS_DELTA)
        // 3. Hook with AFTER_ADD_LIQUIDITY_FLAG and AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG
        address[] memory hooks = new address[](3);
        hooks[0] = address(afterAddLiquidityReturnHook); // Has both flags
        hooks[1] = address(regularHook); // Only has AFTER_ADD_LIQUIDITY_FLAG
        hooks[2] = address(secondAfterAddLiquidityReturnHook); // Has both flags

        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterAddLiquidity as the pool manager
        (bytes4 result, BalanceDelta resultDelta) =
            adapter.afterAddLiquidity(sender, testPoolKey, testParams, testDelta, testFees, hookData);

        // Verify the result selector is correct
        assertEq(result, IHooks.afterAddLiquidity.selector, "Should return afterAddLiquidity selector");

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
            100 + 300, // 400 (only hooks with return delta flag)
            "Combined amount0 delta should equal 400"
        );
        assertEq(
            BalanceDeltaLibrary.amount1(resultDelta),
            200 + 400, // 600 (only hooks with return delta flag)
            "Combined amount1 delta should equal 600"
        );
    }
}
