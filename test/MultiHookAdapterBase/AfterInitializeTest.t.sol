// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBaseTest} from "./MultiHookAdapterBaseTest.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {HookWithEvents} from "../mocks/HookWithEvents.sol";
import {Vm} from "forge-std/Vm.sol";

contract AfterInitializeTest is MultiHookAdapterBaseTest {
    function test_AfterInitialize_SingleHook() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;
        int24 tick = 1;

        // Register a single hook with AFTER_INITIALIZE_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(afterInitializeHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Start recording logs to capture events
        vm.recordLogs();

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterInitialize as the pool manager
        bytes4 result = adapter.afterInitialize(sender, testPoolKey, sqrtPriceX96, tick);

        // Get recorded logs
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Filter logs for AfterInitializeCalled events
        bytes32 eventSignature = keccak256("AfterInitializeCalled(address,bytes32,uint160,int24)");

        // Track events
        bool hookCalled = false;

        // Process logs
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == eventSignature) {
                if (logs[i].emitter == address(afterInitializeHook)) {
                    hookCalled = true;
                    break;
                }
            }
        }

        // Verify the hook was called
        assertTrue(hookCalled, "afterInitializeHook should have been called");

        // Verify the result
        assertEq(result, IHooks.afterInitialize.selector, "Should return afterInitialize selector");
    }

    function test_AfterInitialize_ExecutionOrder() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;
        int24 tick = 5;

        // Create multiple hooks with AFTER_INITIALIZE_FLAG at different addresses
        HookWithEvents firstHook;
        HookWithEvents secondHook;
        HookWithEvents thirdHook;

        // Deploy hooks with the same flag but at different addresses
        address firstHookAddress = address(uint160(0x1000 | Hooks.AFTER_INITIALIZE_FLAG));
        deployCodeTo("HookWithEvents.sol", "", firstHookAddress);
        firstHook = HookWithEvents(firstHookAddress);

        address secondHookAddress = address(uint160(0x2000 | Hooks.AFTER_INITIALIZE_FLAG));
        deployCodeTo("HookWithEvents.sol", "", secondHookAddress);
        secondHook = HookWithEvents(secondHookAddress);

        address thirdHookAddress = address(uint160(0x3000 | Hooks.AFTER_INITIALIZE_FLAG));
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

        // Call afterInitialize as the pool manager
        bytes4 result = adapter.afterInitialize(sender, testPoolKey, sqrtPriceX96, tick);

        // Get recorded logs
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Filter logs for AfterInitializeCalled events
        bytes32 eventSignature = keccak256("AfterInitializeCalled(address,bytes32,uint160,int24)");

        // Arrays to track which hooks were called and in what order
        address[] memory calledHooks = new address[](3);
        uint256 calledCount = 0;

        // Process logs to extract hook call order
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == eventSignature) {
                // This is an AfterInitializeCalled event
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
        assertEq(result, IHooks.afterInitialize.selector, "Should return afterInitialize selector");
    }

    function test_AfterInitialize_MixedExecutionOrder() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;
        int24 tick = 10;

        // Deploy hooks with different flags - simplify by reusing existing hooks
        address[] memory hooks = new address[](5);
        hooks[0] = address(beforeInitializeHook); // Has BEFORE_INITIALIZE_FLAG
        hooks[1] = address(afterInitializeHook); // Has AFTER_INITIALIZE_FLAG
        hooks[2] = address(beforeSwapHook); // Has BEFORE_SWAP_FLAG
        hooks[3] = address(beforeDonateHook); // Has BEFORE_DONATE_FLAG

        // Deploy another hook with AFTER_INITIALIZE_FLAG at a different address
        address hookAddress = address(uint160(0x200 | Hooks.AFTER_INITIALIZE_FLAG));
        deployCodeTo("HookWithEvents.sol", "", hookAddress);
        hooks[4] = address(HookWithEvents(hookAddress));

        // Register hooks in a specific order
        adapter.registerHooks(testPoolKey, hooks);

        // Start recording logs to capture events
        vm.recordLogs();

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterInitialize as the pool manager
        bytes4 result = adapter.afterInitialize(sender, testPoolKey, sqrtPriceX96, tick);

        // Get recorded logs
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Filter logs for AfterInitializeCalled events
        bytes32 eventSignature = keccak256("AfterInitializeCalled(address,bytes32,uint160,int24)");

        // Count occurrences of each hook in the logs
        uint256 beforeInitializeCount = 0;
        uint256 afterInitializeCount = 0;
        uint256 beforeSwapCount = 0;
        uint256 beforeDonateCount = 0;
        uint256 secondAfterInitializeCount = 0;

        // Track the order (if any hooks with AFTER_INITIALIZE_FLAG are called)
        address firstCalled = address(0);
        address lastCalled = address(0);

        // Process logs
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == eventSignature) {
                address emitter = logs[i].emitter;

                if (emitter == address(beforeInitializeHook)) {
                    beforeInitializeCount++;
                } else if (emitter == address(afterInitializeHook)) {
                    afterInitializeCount++;
                    if (firstCalled == address(0)) {
                        firstCalled = emitter;
                    }
                } else if (emitter == address(beforeSwapHook)) {
                    beforeSwapCount++;
                } else if (emitter == address(beforeDonateHook)) {
                    beforeDonateCount++;
                } else if (emitter == hooks[4]) {
                    secondAfterInitializeCount++;
                    if (firstCalled == address(afterInitializeHook)) {
                        lastCalled = hooks[4];
                    }
                }
            }
        }

        // Verify only hooks with AFTER_INITIALIZE_FLAG were called
        assertEq(beforeInitializeCount, 0, "beforeInitializeHook should not be called");
        assertEq(afterInitializeCount, 1, "afterInitializeHook should be called once");
        assertEq(beforeSwapCount, 0, "beforeSwapHook should not be called");
        assertEq(beforeDonateCount, 0, "beforeDonateHook should not be called");
        assertEq(secondAfterInitializeCount, 1, "second afterInitializeHook should be called once");

        // Verify the first called hook is the afterInitializeHook
        assertEq(firstCalled, address(afterInitializeHook), "afterInitializeHook should be called first");
        assertEq(lastCalled, hooks[4], "hooks[4] should be called last");

        // Verify the result
        assertEq(result, IHooks.afterInitialize.selector, "Should return afterInitialize selector");
    }

    function test_AfterInitialize_InvalidHookReturn() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;
        int24 tick = 15;

        // Register a hook with AFTER_INITIALIZE_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(afterInitializeHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock the hook to return an invalid selector
        bytes4 invalidSelector = bytes4(keccak256("invalidSelector()"));
        vm.mockCall(
            address(afterInitializeHook),
            abi.encodeWithSelector(IHooks.afterInitialize.selector, sender, testPoolKey, sqrtPriceX96, tick),
            abi.encode(invalidSelector)
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call should revert because hook returns invalid selector
        vm.expectRevert("Invalid afterInitialize return");
        adapter.afterInitialize(sender, testPoolKey, sqrtPriceX96, tick);
    }

    function test_AfterInitialize_HookFailure() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;
        int24 tick = 20;

        // Register a hook with AFTER_INITIALIZE_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(afterInitializeHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock the hook to revert when called
        vm.mockCallRevert(
            address(afterInitializeHook),
            abi.encodeWithSelector(IHooks.afterInitialize.selector, sender, testPoolKey, sqrtPriceX96, tick),
            "Hook execution failed"
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call should revert because hook reverts
        vm.expectRevert("Sub-hook afterInitialize failed");
        adapter.afterInitialize(sender, testPoolKey, sqrtPriceX96, tick);
    }

    function test_AfterInitialize_NoRegisteredHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;
        int24 tick = 25;

        // Don't register any hooks for this pool

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterInitialize as the pool manager
        bytes4 result = adapter.afterInitialize(sender, testPoolKey, sqrtPriceX96, tick);

        // Should still return the correct selector even with no hooks registered
        assertEq(
            result, IHooks.afterInitialize.selector, "Should return afterInitialize selector with no hooks registered"
        );
    }

    function test_AfterInitialize_NoImplementingHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;
        int24 tick = 30;

        // Register hooks but none implement AFTER_INITIALIZE_FLAG
        address[] memory hooks = new address[](2);
        hooks[0] = address(beforeInitializeHook);
        hooks[1] = address(beforeDonateHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call afterInitialize as the pool manager
        bytes4 result = adapter.afterInitialize(sender, testPoolKey, sqrtPriceX96, tick);

        // Verify the result - should still return selector even if no hooks processed
        assertEq(
            result,
            IHooks.afterInitialize.selector,
            "Should return afterInitialize selector even with no implementing hooks"
        );
    }
}
