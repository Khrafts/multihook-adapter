// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBaseTest} from "./MultiHookAdapterBaseTest.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {HookWithEvents} from "../mocks/HookWithEvents.sol";
import {Vm} from "forge-std/Vm.sol";

contract BeforeRemoveLiquidityTest is MultiHookAdapterBaseTest {
    // Basic ModifyLiquidityParams for testing
    ModifyLiquidityParams public testParams;

    function setUp() public override {
        super.setUp();

        // Set up standard test parameters for liquidity removal (negative liquidityDelta)
        testParams = ModifyLiquidityParams({
            tickLower: -120,
            tickUpper: 120,
            liquidityDelta: -1e18, // Negative for removal
            salt: bytes32(0)
        });
    }

    function test_BeforeRemoveLiquidity_SingleHook() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Register a single hook with BEFORE_REMOVE_LIQUIDITY_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(beforeRemoveLiquidityHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Mock the hook's response
        vm.mockCall(
            address(beforeRemoveLiquidityHook),
            abi.encodeWithSelector(IHooks.beforeRemoveLiquidity.selector, sender, testPoolKey, testParams, hookData),
            abi.encode(IHooks.beforeRemoveLiquidity.selector)
        );

        // Impersonate the pool manager before calling beforeRemoveLiquidity
        impersonatePoolManager();

        // Call beforeRemoveLiquidity as the pool manager
        bytes4 result = adapter.beforeRemoveLiquidity(sender, testPoolKey, testParams, hookData);

        // Verify the result
        assertEq(result, IHooks.beforeRemoveLiquidity.selector, "Should return beforeRemoveLiquidity selector");
    }

    function test_BeforeRemoveLiquidity_MultipleHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Create additional hooks with BEFORE_REMOVE_LIQUIDITY_FLAG
        HookWithEvents secondBeforeRemoveLiquidityHook;
        HookWithEvents thirdBeforeRemoveLiquidityHook;

        // Deploying at different addresses but with same flags
        address secondHookAddress = address(uint160(0x2000 | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG));
        deployCodeTo("HookWithEvents.sol", "", secondHookAddress);
        secondBeforeRemoveLiquidityHook = HookWithEvents(secondHookAddress);

        address thirdHookAddress = address(uint160(0x3000 | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG));
        deployCodeTo("HookWithEvents.sol", "", thirdHookAddress);
        thirdBeforeRemoveLiquidityHook = HookWithEvents(thirdHookAddress);

        // Register multiple hooks that all implement beforeRemoveLiquidity
        address[] memory hooks = new address[](3);
        hooks[0] = address(beforeRemoveLiquidityHook);
        hooks[1] = address(secondBeforeRemoveLiquidityHook);
        hooks[2] = address(thirdBeforeRemoveLiquidityHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock calls for each hook - they all need to return the correct selector
        vm.mockCall(
            hooks[0],
            abi.encodeWithSelector(IHooks.beforeRemoveLiquidity.selector, sender, testPoolKey, testParams, hookData),
            abi.encode(IHooks.beforeRemoveLiquidity.selector)
        );

        vm.mockCall(
            hooks[1],
            abi.encodeWithSelector(IHooks.beforeRemoveLiquidity.selector, sender, testPoolKey, testParams, hookData),
            abi.encode(IHooks.beforeRemoveLiquidity.selector)
        );

        vm.mockCall(
            hooks[2],
            abi.encodeWithSelector(IHooks.beforeRemoveLiquidity.selector, sender, testPoolKey, testParams, hookData),
            abi.encode(IHooks.beforeRemoveLiquidity.selector)
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeRemoveLiquidity as the pool manager
        bytes4 result = adapter.beforeRemoveLiquidity(sender, testPoolKey, testParams, hookData);

        // Verify the result
        assertEq(result, IHooks.beforeRemoveLiquidity.selector, "Should return beforeRemoveLiquidity selector");
    }

    function test_BeforeRemoveLiquidity_MixedHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Register a mix of hooks - only beforeRemoveLiquidityHook has BEFORE_REMOVE_LIQUIDITY_FLAG
        address[] memory hooks = new address[](3);
        hooks[0] = address(beforeRemoveLiquidityHook);
        hooks[1] = address(afterRemoveLiquidityHook);
        hooks[2] = address(beforeDonateHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock response for beforeRemoveLiquidityHook
        vm.mockCall(
            address(beforeRemoveLiquidityHook),
            abi.encodeWithSelector(IHooks.beforeRemoveLiquidity.selector, sender, testPoolKey, testParams, hookData),
            abi.encode(IHooks.beforeRemoveLiquidity.selector)
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeRemoveLiquidity as the pool manager
        bytes4 result = adapter.beforeRemoveLiquidity(sender, testPoolKey, testParams, hookData);

        // Verify the result is correct
        assertEq(result, IHooks.beforeRemoveLiquidity.selector, "Should return beforeRemoveLiquidity selector");
    }

    function test_BeforeRemoveLiquidity_ExecutionOrder() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Create multiple hooks with BEFORE_REMOVE_LIQUIDITY_FLAG at different addresses
        HookWithEvents firstHook;
        HookWithEvents secondHook;
        HookWithEvents thirdHook;

        // Deploy hooks with the same flag but at different addresses
        address firstHookAddress = address(uint160(0x1000 | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG));
        deployCodeTo("HookWithEvents.sol", "", firstHookAddress);
        firstHook = HookWithEvents(firstHookAddress);

        address secondHookAddress = address(uint160(0x2000 | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG));
        deployCodeTo("HookWithEvents.sol", "", secondHookAddress);
        secondHook = HookWithEvents(secondHookAddress);

        address thirdHookAddress = address(uint160(0x3000 | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG));
        deployCodeTo("HookWithEvents.sol", "", thirdHookAddress);
        thirdHook = HookWithEvents(thirdHookAddress);

        // Register hooks in a specific order
        address[] memory hooks = new address[](3);
        hooks[0] = address(firstHook);
        hooks[1] = address(secondHook);
        hooks[2] = address(thirdHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Start recording logs to capture events
        vm.recordLogs();

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeRemoveLiquidity as the pool manager
        bytes4 result = adapter.beforeRemoveLiquidity(sender, testPoolKey, testParams, hookData);

        // Get recorded logs
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Filter logs for BeforeRemoveLiquidityCalled events
        bytes32 eventSignature = keccak256("BeforeRemoveLiquidityCalled(address,bytes32,bytes)");

        // Arrays to track which hooks were called and in what order
        address[] memory calledHooks = new address[](3);
        uint256 calledCount = 0;

        // Process logs to extract hook call order
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == eventSignature) {
                // This is a BeforeRemoveLiquidityCalled event
                address emitter = logs[i].emitter;

                // Add to our tracking array
                if (calledCount < 3) {
                    calledHooks[calledCount] = emitter;
                    calledCount++;
                }
            }
        }

        // Verify all hooks were called
        assertEq(calledCount, 3, "All three hooks should have been called");

        // Verify hooks were called in the correct order
        assertEq(calledHooks[0], address(firstHook), "First hook should be called first");
        assertEq(calledHooks[1], address(secondHook), "Second hook should be called second");
        assertEq(calledHooks[2], address(thirdHook), "Third hook should be called third");

        // Verify the result
        assertEq(result, IHooks.beforeRemoveLiquidity.selector, "Should return beforeRemoveLiquidity selector");
    }

    function test_BeforeRemoveLiquidity_HookFailure() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Register a hook with BEFORE_REMOVE_LIQUIDITY_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(beforeRemoveLiquidityHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock the hook to revert when called
        vm.mockCallRevert(
            address(beforeRemoveLiquidityHook),
            abi.encodeWithSelector(IHooks.beforeRemoveLiquidity.selector, sender, testPoolKey, testParams, hookData),
            "Hook execution failed"
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call should revert because hook reverts
        vm.expectRevert("Sub-hook beforeRemoveLiquidity failed");
        adapter.beforeRemoveLiquidity(sender, testPoolKey, testParams, hookData);
    }

    function test_BeforeRemoveLiquidity_InvalidHookReturn() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Register a hook with BEFORE_REMOVE_LIQUIDITY_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(beforeRemoveLiquidityHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock the hook to return an invalid selector
        bytes4 invalidSelector = bytes4(keccak256("invalidSelector()"));
        vm.mockCall(
            address(beforeRemoveLiquidityHook),
            abi.encodeWithSelector(IHooks.beforeRemoveLiquidity.selector, sender, testPoolKey, testParams, hookData),
            abi.encode(invalidSelector)
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call should revert because hook returns invalid selector
        vm.expectRevert("Invalid beforeRemoveLiquidity return");
        adapter.beforeRemoveLiquidity(sender, testPoolKey, testParams, hookData);
    }

    function test_BeforeRemoveLiquidity_NoImplementingHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Register hooks but none implement BEFORE_REMOVE_LIQUIDITY_FLAG
        address[] memory hooks = new address[](2);
        hooks[0] = address(afterInitializeHook);
        hooks[1] = address(beforeDonateHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeRemoveLiquidity as the pool manager
        bytes4 result = adapter.beforeRemoveLiquidity(sender, testPoolKey, testParams, hookData);

        // Verify the result - should still return selector even if no hooks processed
        assertEq(
            result,
            IHooks.beforeRemoveLiquidity.selector,
            "Should return beforeRemoveLiquidity selector even with no implementing hooks"
        );
    }

    function test_BeforeRemoveLiquidity_NoRegisteredHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Don't register any hooks for this pool

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeRemoveLiquidity as the pool manager
        bytes4 result = adapter.beforeRemoveLiquidity(sender, testPoolKey, testParams, hookData);

        // Should still return the correct selector even with no hooks registered
        assertEq(
            result,
            IHooks.beforeRemoveLiquidity.selector,
            "Should return beforeRemoveLiquidity selector with no hooks registered"
        );
    }

    function test_BeforeRemoveLiquidity_DifferentLiquidityParams() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        bytes memory hookData = "test data";

        // Test with different ModifyLiquidityParams
        ModifyLiquidityParams memory customParams = ModifyLiquidityParams({
            tickLower: -240,
            tickUpper: 240,
            liquidityDelta: -2e18, // Still negative for removal
            salt: bytes32(uint256(1))
        });

        // Register a hook with BEFORE_REMOVE_LIQUIDITY_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(beforeRemoveLiquidityHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Mock the hook's response with the custom params
        vm.mockCall(
            address(beforeRemoveLiquidityHook),
            abi.encodeWithSelector(IHooks.beforeRemoveLiquidity.selector, sender, testPoolKey, customParams, hookData),
            abi.encode(IHooks.beforeRemoveLiquidity.selector)
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeRemoveLiquidity as the pool manager with custom params
        bytes4 result = adapter.beforeRemoveLiquidity(sender, testPoolKey, customParams, hookData);

        // Verify the result
        assertEq(result, IHooks.beforeRemoveLiquidity.selector, "Should return beforeRemoveLiquidity selector");
    }
}
