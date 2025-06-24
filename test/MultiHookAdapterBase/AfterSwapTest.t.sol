// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBaseTest} from "./MultiHookAdapterBaseTest.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {
    BeforeSwapDelta, toBeforeSwapDelta, BeforeSwapDeltaLibrary
} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta, toBalanceDelta, BalanceDeltaLibrary, add} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {AfterSwapHook} from "../mocks/AfterSwapHook.sol";
import {Vm} from "forge-std/Vm.sol";
import "forge-std/console.sol";

/**
 * @title AfterSwapTest
 * @notice Test suite for the _afterSwap function
 */
contract AfterSwapTest is MultiHookAdapterBaseTest {
    using PoolIdLibrary for PoolKey;

    // Basic SwapParams for testing
    SwapParams testParams;

    // Test hooks
    AfterSwapHook public testAfterSwapHook;
    AfterSwapHook public testAfterSwapWithDeltaHook;
    AfterSwapHook public testSecondDeltaHook;

    // Test variables
    address sender;
    PoolKey testPoolKey;
    bytes hookData;
    BalanceDelta testSwapDelta;

    function setUp() public override {
        super.setUp();

        // Set up standard test parameters for swap
        testParams = SwapParams({zeroForOne: true, amountSpecified: 1e18, sqrtPriceLimitX96: 0});

        // Common test variables
        sender = address(0x123);
        testPoolKey = createTestPoolKey();
        hookData = "test data";
        testSwapDelta = toBalanceDelta(100, 200);

        // Deploy test hooks

        // Hook with just AFTER_SWAP_FLAG
        address hookAddress = address(uint160(0x3000 | Hooks.AFTER_SWAP_FLAG));
        deployCodeTo("AfterSwapHook.sol", "", hookAddress);
        testAfterSwapHook = AfterSwapHook(hookAddress);
        testAfterSwapHook.setHasDeltaFlag(false);

        // Hook with AFTER_SWAP_FLAG and AFTER_SWAP_RETURNS_DELTA_FLAG
        address deltaHookAddress =
            address(uint160(0x4000 | Hooks.AFTER_SWAP_FLAG | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG));
        deployCodeTo("AfterSwapHook.sol", "", deltaHookAddress);
        testAfterSwapWithDeltaHook = AfterSwapHook(deltaHookAddress);

        // Second delta hook for multiple hook tests
        address secondDeltaHookAddress =
            address(uint160(0x5000 | Hooks.AFTER_SWAP_FLAG | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG));
        deployCodeTo("AfterSwapHook.sol", "", secondDeltaHookAddress);
        testSecondDeltaHook = AfterSwapHook(secondDeltaHookAddress);
    }

    // Test basic afterSwap with a hook that doesn't return delta
    function test_AfterSwap_Basic() public {
        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(testAfterSwapHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Setup the beforeSwap hook return storage state
        poolId = testPoolKey.toId();
        BeforeSwapDelta[] memory emptyDeltas = new BeforeSwapDelta[](1);
        emptyDeltas[0] = BeforeSwapDelta.wrap(0);
        vm.prank(address(adapter));
        adapter.setBeforeSwapHookReturns(poolId, emptyDeltas);

        // Impersonate pool manager for the call
        impersonatePoolManager();

        // Call afterSwap
        (bytes4 selector, int128 resultDelta) =
            adapter.afterSwap(sender, testPoolKey, testParams, testSwapDelta, hookData);

        // Verify results
        assertEq(selector, IHooks.afterSwap.selector, "Incorrect selector returned");
        assertEq(resultDelta, 0, "Delta should be zero for hook without RETURNS_DELTA flag");

        // Verify the hook was called
        assertTrue(testAfterSwapHook.wasCalled(), "Hook was not called");

        // Verify storage was cleared
        BeforeSwapDelta[] memory storedDeltas = adapter.getBeforeSwapHookReturns(poolId);
        assertEq(storedDeltas.length, 0, "Storage should be cleared after afterSwap");
    }

    // Test afterSwap with a hook that returns delta
    function test_AfterSwap_WithDelta() public {
        // Register the hook with RETURNS_DELTA flag
        address[] memory hooks = new address[](1);
        hooks[0] = address(testAfterSwapWithDeltaHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Setup the beforeSwap hook return storage state
        poolId = testPoolKey.toId();
        BeforeSwapDelta[] memory deltas = new BeforeSwapDelta[](1);
        deltas[0] = toBeforeSwapDelta(5, 10); // Some beforeSwap delta
        vm.prank(address(adapter));
        adapter.setBeforeSwapHookReturns(poolId, deltas);

        // Configure the hook to return a specific delta
        int128 expectedDelta = 42;
        testAfterSwapWithDeltaHook.setReturnValues(expectedDelta);

        // Impersonate pool manager for the call
        impersonatePoolManager();

        // Call afterSwap
        (bytes4 selector, int128 resultDelta) =
            adapter.afterSwap(sender, testPoolKey, testParams, testSwapDelta, hookData);

        // Verify results
        assertEq(selector, IHooks.afterSwap.selector, "Incorrect selector returned");
        assertEq(resultDelta, expectedDelta, "Hook delta should be returned");

        // Verify the hook was called
        assertTrue(testAfterSwapWithDeltaHook.wasCalled(), "Hook was not called");
    }

    // Test multiple hooks with delta aggregation
    function test_AfterSwap_MultipleHooks_DeltaAggregation() public {
        // Register multiple hooks with RETURNS_DELTA flag
        address[] memory hooks = new address[](2);
        hooks[0] = address(testAfterSwapWithDeltaHook);
        hooks[1] = address(testSecondDeltaHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Setup the beforeSwap hook returns
        poolId = testPoolKey.toId();
        BeforeSwapDelta[] memory deltas = new BeforeSwapDelta[](2);
        deltas[0] = toBeforeSwapDelta(5, 10);
        deltas[1] = toBeforeSwapDelta(15, 20);
        vm.prank(address(adapter));
        adapter.setBeforeSwapHookReturns(poolId, deltas);

        // Configure the hooks to return different deltas
        int128 delta1 = 25;
        int128 delta2 = 75;
        testAfterSwapWithDeltaHook.setReturnValues(delta1);
        testSecondDeltaHook.setReturnValues(delta2);

        // Impersonate pool manager for the call
        impersonatePoolManager();

        // Call afterSwap
        (bytes4 selector, int128 resultDelta) =
            adapter.afterSwap(sender, testPoolKey, testParams, testSwapDelta, hookData);

        // Verify results
        assertEq(selector, IHooks.afterSwap.selector, "Incorrect selector returned");
        assertEq(resultDelta, delta1 + delta2, "Hook deltas should be aggregated");

        // Verify hooks were called
        assertTrue(testAfterSwapWithDeltaHook.wasCalled(), "First hook was not called");
        assertTrue(testSecondDeltaHook.wasCalled(), "Second hook was not called");
    }

    // Test mix of hooks with and without RETURNS_DELTA flag
    function test_AfterSwap_MixedHooks() public {
        // Register mix of hooks
        address[] memory hooks = new address[](3);
        hooks[0] = address(testAfterSwapHook); // No delta flag
        hooks[1] = address(testAfterSwapWithDeltaHook); // With delta flag
        hooks[2] = address(testSecondDeltaHook); // With delta flag
        adapter.registerHooks(testPoolKey, hooks);

        // Setup the beforeSwap hook returns
        poolId = testPoolKey.toId();
        BeforeSwapDelta[] memory deltas = new BeforeSwapDelta[](3);
        deltas[0] = BeforeSwapDelta.wrap(0);
        deltas[1] = toBeforeSwapDelta(5, 10);
        deltas[2] = toBeforeSwapDelta(15, 20);
        vm.prank(address(adapter));
        adapter.setBeforeSwapHookReturns(poolId, deltas);

        // Configure hooks
        testAfterSwapHook.setHasDeltaFlag(false);
        int128 delta1 = 30;
        int128 delta2 = 70;
        testAfterSwapWithDeltaHook.setReturnValues(delta1);
        testSecondDeltaHook.setReturnValues(delta2);

        // Impersonate pool manager for the call
        impersonatePoolManager();

        // Call afterSwap
        (bytes4 selector, int128 resultDelta) =
            adapter.afterSwap(sender, testPoolKey, testParams, testSwapDelta, hookData);

        // Verify results
        assertEq(selector, IHooks.afterSwap.selector, "Incorrect selector returned");
        assertEq(resultDelta, delta1 + delta2, "Only deltas from hooks with flag should be aggregated");

        // Verify all hooks were called
        assertTrue(testAfterSwapHook.wasCalled(), "Basic hook was not called");
        assertTrue(testAfterSwapWithDeltaHook.wasCalled(), "First delta hook was not called");
        assertTrue(testSecondDeltaHook.wasCalled(), "Second delta hook was not called");
    }

    // Test multiple pools with independent storage
    function test_AfterSwap_MultiplePoolsStorage() public {
        // Create a second pool key with different fee
        PoolKey memory secondPoolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 500, // Different fee
            tickSpacing: 10,
            hooks: IHooks(address(adapter))
        });

        PoolId poolId1 = testPoolKey.toId();
        PoolId poolId2 = secondPoolKey.toId();

        // Register the same hook with both pools
        address[] memory hooks = new address[](1);
        hooks[0] = address(testAfterSwapWithDeltaHook);
        adapter.registerHooks(testPoolKey, hooks);
        adapter.registerHooks(secondPoolKey, hooks);

        // Setup different beforeSwap hook returns for each pool
        BeforeSwapDelta[] memory deltas1 = new BeforeSwapDelta[](1);
        deltas1[0] = toBeforeSwapDelta(10, 20);
        BeforeSwapDelta[] memory deltas2 = new BeforeSwapDelta[](1);
        deltas2[0] = toBeforeSwapDelta(30, 40);

        vm.startPrank(address(adapter));
        adapter.setBeforeSwapHookReturns(poolId1, deltas1);
        adapter.setBeforeSwapHookReturns(poolId2, deltas2);
        vm.stopPrank();

        // Configure hook
        testAfterSwapWithDeltaHook.setReturnValues(50);

        // Call afterSwap for first pool
        impersonatePoolManager();
        adapter.afterSwap(sender, testPoolKey, testParams, testSwapDelta, hookData);

        // Verify first pool storage cleared but second pool storage intact
        BeforeSwapDelta[] memory storedDeltas1 = adapter.getBeforeSwapHookReturns(poolId1);
        BeforeSwapDelta[] memory storedDeltas2 = adapter.getBeforeSwapHookReturns(poolId2);

        assertEq(storedDeltas1.length, 0, "First pool storage should be cleared");
        assertEq(storedDeltas2.length, 1, "Second pool storage should remain intact");
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas2[0]),
            int128(30),
            "Second pool delta should be preserved"
        );

        // Reset for second call
        testAfterSwapWithDeltaHook.resetCalled();

        // Call afterSwap for second pool
        impersonatePoolManager();
        adapter.afterSwap(sender, secondPoolKey, testParams, testSwapDelta, hookData);

        // Now second pool storage should be cleared too
        storedDeltas2 = adapter.getBeforeSwapHookReturns(poolId2);
        assertEq(storedDeltas2.length, 0, "Second pool storage should be cleared after second call");
    }

    // Test that BeforeSwapDelta values are correctly stored in beforeSwap and cleared in afterSwap
    function test_BeforeSwap_Then_AfterSwap_Basic() public {
        // Create a hook with both BEFORE_SWAP and AFTER_SWAP flags including RETURNS_DELTA
        address hookAddress = address(
            uint160(
                0x6000 | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_SWAP_FLAG
                    | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG
            )
        );
        deployCodeTo("AfterSwapHook.sol", "", hookAddress);
        AfterSwapHook fullHook = AfterSwapHook(hookAddress);

        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(fullHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Setup expected values
        BeforeSwapDelta expectedBeforeDelta = toBeforeSwapDelta(15, 25);
        int128 expectedAfterDelta = 42;

        // Configure the hook to return these values
        fullHook.setBeforeSwapDelta(expectedBeforeDelta);
        fullHook.setReturnValues(expectedAfterDelta);

        // Get poolId for verification
        poolId = testPoolKey.toId();

        // First, simulate a beforeSwap call to populate the storage
        impersonatePoolManager();
        (bytes4 selector1, BeforeSwapDelta resultDelta, uint24 fee) =
            adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Verify the hook was called
        assertTrue(fullHook.wasCalled(), "Hook was not called in beforeSwap");

        // Verify the beforeSwapDelta was stored properly
        BeforeSwapDelta[] memory storedDeltas = adapter.getBeforeSwapHookReturns(poolId);
        assertEq(storedDeltas.length, 1, "Storage should have 1 entry");

        // Debug: Print stored BeforeSwapDelta values
        console.log("Stored specified:", int256(BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas[0])));
        console.log("Stored unspecified:", int256(BeforeSwapDeltaLibrary.getUnspecifiedDelta(storedDeltas[0])));

        // Verify the stored delta matches what the hook returned
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas[0]),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(expectedBeforeDelta),
            "Stored specified delta mismatch"
        );
        assertEq(
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(storedDeltas[0]),
            BeforeSwapDeltaLibrary.getUnspecifiedDelta(expectedBeforeDelta),
            "Stored unspecified delta mismatch"
        );

        // Reset the hook for afterSwap call
        fullHook.resetCalled();

        // Now simulate the afterSwap call
        impersonatePoolManager();
        (bytes4 selector2, int128 resultAfterDelta) =
            adapter.afterSwap(sender, testPoolKey, testParams, testSwapDelta, hookData);

        // Verify the hook was called
        assertTrue(fullHook.wasCalled(), "Hook was not called in afterSwap");

        // Verify the returned delta matches what we expected
        assertEq(resultAfterDelta, expectedAfterDelta, "Returned delta mismatch");

        // Verify the storage was cleared
        storedDeltas = adapter.getBeforeSwapHookReturns(poolId);
        assertEq(storedDeltas.length, 0, "Storage should be cleared after afterSwap");
    }

    // Test multiple hooks with both beforeSwap and afterSwap flow
    function test_BeforeSwap_Then_AfterSwap_MultipleHooks() public {
        // Create hooks with both BEFORE_SWAP and AFTER_SWAP flags
        address hook1Address = address(
            uint160(
                0x7000 | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_SWAP_FLAG
                    | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG
            )
        );

        address hook2Address = address(
            uint160(
                0x8000 | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_SWAP_FLAG
                    | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG
            )
        );

        deployCodeTo("AfterSwapHook.sol", "", hook1Address);
        deployCodeTo("AfterSwapHook.sol", "", hook2Address);

        AfterSwapHook hook1 = AfterSwapHook(hook1Address);
        AfterSwapHook hook2 = AfterSwapHook(hook2Address);

        // Register both hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(hook1);
        hooks[1] = address(hook2);
        adapter.registerHooks(testPoolKey, hooks);

        // Setup expected values
        BeforeSwapDelta beforeDelta1 = toBeforeSwapDelta(10, 20);
        BeforeSwapDelta beforeDelta2 = toBeforeSwapDelta(30, 40);
        int128 afterDelta1 = 25;
        int128 afterDelta2 = 75;

        // Configure hooks
        hook1.setBeforeSwapDelta(beforeDelta1);
        hook2.setBeforeSwapDelta(beforeDelta2);
        hook1.setReturnValues(afterDelta1);
        hook2.setReturnValues(afterDelta2);

        // Get poolId
        poolId = testPoolKey.toId();

        // Call beforeSwap to populate the storage
        impersonatePoolManager();
        adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Verify both hooks were called
        assertTrue(hook1.wasCalled(), "First hook not called in beforeSwap");
        assertTrue(hook2.wasCalled(), "Second hook not called in beforeSwap");

        // Verify storage contains both deltas
        BeforeSwapDelta[] memory storedDeltas = adapter.getBeforeSwapHookReturns(poolId);
        assertEq(storedDeltas.length, 2, "Storage should have two entries");

        // Verify stored deltas match what the hooks returned
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas[0]),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(beforeDelta1),
            "First stored delta mismatch"
        );
        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas[1]),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(beforeDelta2),
            "Second stored delta mismatch"
        );

        // Reset hooks for afterSwap
        hook1.resetCalled();
        hook2.resetCalled();

        // Call afterSwap
        impersonatePoolManager();
        (bytes4 afterSelector, int128 resultAfterDelta) =
            adapter.afterSwap(sender, testPoolKey, testParams, testSwapDelta, hookData);

        // Verify both hooks were called
        assertTrue(hook1.wasCalled(), "First hook not called in afterSwap");
        assertTrue(hook2.wasCalled(), "Second hook not called in afterSwap");

        // Verify returned delta is the sum of individual deltas
        assertEq(resultAfterDelta, afterDelta1 + afterDelta2, "Combined return delta incorrect");

        // Verify storage was cleared
        storedDeltas = adapter.getBeforeSwapHookReturns(poolId);
        assertEq(storedDeltas.length, 0, "Storage should be cleared after afterSwap");
    }

    // Test the full flow across multiple pools
    function test_BeforeSwap_Then_AfterSwap_MultiplePools() public {
        // Create a second pool key
        PoolKey memory secondPoolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 500, // Different fee
            tickSpacing: 10,
            hooks: IHooks(address(adapter))
        });

        PoolId poolId1 = testPoolKey.toId();
        PoolId poolId2 = secondPoolKey.toId();

        // Create hook with both BEFORE and AFTER flags
        address hookAddress = address(
            uint160(
                0x9000 | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_SWAP_FLAG
                    | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG
            )
        );
        deployCodeTo("AfterSwapHook.sol", "", hookAddress);
        AfterSwapHook testHook = AfterSwapHook(hookAddress);

        // Register hook with both pools
        address[] memory hooks = new address[](1);
        hooks[0] = address(testHook);
        adapter.registerHooks(testPoolKey, hooks);
        adapter.registerHooks(secondPoolKey, hooks);

        // Setup different values for each pool
        BeforeSwapDelta beforeDelta1 = toBeforeSwapDelta(10, 20);
        BeforeSwapDelta beforeDelta2 = toBeforeSwapDelta(30, 40);
        int128 afterDelta1 = 50;
        int128 afterDelta2 = 60;

        // Call beforeSwap for first pool
        testHook.setBeforeSwapDelta(beforeDelta1);
        testHook.setReturnValues(afterDelta1);

        impersonatePoolManager();
        adapter.beforeSwap(sender, testPoolKey, testParams, hookData);

        // Call beforeSwap for second pool
        testHook.resetCalled();
        testHook.setBeforeSwapDelta(beforeDelta2);
        testHook.setReturnValues(afterDelta2);

        impersonatePoolManager();
        adapter.beforeSwap(sender, secondPoolKey, testParams, hookData);

        // Verify storage state for both pools
        BeforeSwapDelta[] memory storedDeltas1 = adapter.getBeforeSwapHookReturns(poolId1);
        BeforeSwapDelta[] memory storedDeltas2 = adapter.getBeforeSwapHookReturns(poolId2);

        assertEq(storedDeltas1.length, 1, "First pool should have 1 entry");
        assertEq(storedDeltas2.length, 1, "Second pool should have 1 entry");

        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas1[0]),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(beforeDelta1),
            "First pool delta mismatch"
        );

        assertEq(
            BeforeSwapDeltaLibrary.getSpecifiedDelta(storedDeltas2[0]),
            BeforeSwapDeltaLibrary.getSpecifiedDelta(beforeDelta2),
            "Second pool delta mismatch"
        );

        // Call afterSwap for first pool
        testHook.resetCalled();
        testHook.setReturnValues(afterDelta1);

        impersonatePoolManager();
        adapter.afterSwap(sender, testPoolKey, testParams, testSwapDelta, hookData);

        // Verify first pool storage cleared but second still intact
        storedDeltas1 = adapter.getBeforeSwapHookReturns(poolId1);
        storedDeltas2 = adapter.getBeforeSwapHookReturns(poolId2);

        assertEq(storedDeltas1.length, 0, "First pool storage should be cleared");
        assertEq(storedDeltas2.length, 1, "Second pool storage should remain intact");

        // Call afterSwap for second pool
        testHook.resetCalled();
        testHook.setReturnValues(afterDelta2);

        impersonatePoolManager();
        adapter.afterSwap(sender, secondPoolKey, testParams, testSwapDelta, hookData);

        // Verify second pool storage also cleared
        storedDeltas2 = adapter.getBeforeSwapHookReturns(poolId2);
        assertEq(storedDeltas2.length, 0, "Second pool storage should be cleared");
    }

    // Helper to create a second test pool key with different fee
    function createSecondTestPoolKey() internal view returns (PoolKey memory) {
        return PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(address(1)),
            fee: 500, // Different fee from the default
            tickSpacing: 10,
            hooks: IHooks(address(adapter))
        });
    }

    // Helper function to add two BeforeSwapDeltas
    function _addBeforeSwapDelta(BeforeSwapDelta a, BeforeSwapDelta b) internal pure returns (BeforeSwapDelta) {
        BalanceDelta res = add(
            toBalanceDelta(BeforeSwapDeltaLibrary.getSpecifiedDelta(a), BeforeSwapDeltaLibrary.getUnspecifiedDelta(a)),
            toBalanceDelta(BeforeSwapDeltaLibrary.getSpecifiedDelta(b), BeforeSwapDeltaLibrary.getUnspecifiedDelta(b))
        );
        return toBeforeSwapDelta(BalanceDeltaLibrary.amount0(res), BalanceDeltaLibrary.amount1(res));
    }
}
