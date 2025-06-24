// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBaseTest} from "./MultiHookAdapterBaseTest.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {HookWithEvents} from "../mocks/HookWithEvents.sol";
import {Vm} from "forge-std/Vm.sol";

contract BeforeInitializeTest is MultiHookAdapterBaseTest {
    function test_BeforeInitialize_SingleHook() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;

        // Register a single hook with BEFORE_INITIALIZE_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(beforeInitializeHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Mock the hook's response
        vm.mockCall(
            address(beforeInitializeHook),
            abi.encodeWithSelector(IHooks.beforeInitialize.selector, sender, testPoolKey, sqrtPriceX96),
            abi.encode(IHooks.beforeInitialize.selector)
        );

        // Impersonate the pool manager before calling beforeInitialize
        impersonatePoolManager();

        // Call beforeInitialize as the pool manager
        bytes4 result = adapter.beforeInitialize(sender, testPoolKey, sqrtPriceX96);

        // Verify the result
        assertEq(result, IHooks.beforeInitialize.selector, "Should return beforeInitialize selector");
    }

    function test_BeforeInitialize_MultipleHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;

        // Create a custom hook that also has BEFORE_INITIALIZE_FLAG
        HookWithEvents secondBeforeInitializeHook;
        HookWithEvents thirdBeforeInitializeHook;

        // Deploying at different addresses but with same flags
        address secondHookAddress = address(uint160(0x2000 | Hooks.BEFORE_INITIALIZE_FLAG));
        deployCodeTo("HookWithEvents.sol", "", secondHookAddress);
        secondBeforeInitializeHook = HookWithEvents(secondHookAddress);

        address thirdHookAddress = address(uint160(0x3000 | Hooks.BEFORE_INITIALIZE_FLAG));
        deployCodeTo("HookWithEvents.sol", "", thirdHookAddress);
        thirdBeforeInitializeHook = HookWithEvents(thirdHookAddress);

        // Register multiple hooks that all implement beforeInitialize
        address[] memory hooks = new address[](3);
        hooks[0] = address(beforeInitializeHook);
        hooks[1] = address(secondBeforeInitializeHook);
        hooks[2] = address(thirdBeforeInitializeHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock calls for each hook - they all need to return the correct selector
        vm.mockCall(
            hooks[0],
            abi.encodeWithSelector(IHooks.beforeInitialize.selector, sender, testPoolKey, sqrtPriceX96),
            abi.encode(IHooks.beforeInitialize.selector)
        );

        vm.mockCall(
            hooks[1],
            abi.encodeWithSelector(IHooks.beforeInitialize.selector, sender, testPoolKey, sqrtPriceX96),
            abi.encode(IHooks.beforeInitialize.selector)
        );

        vm.mockCall(
            hooks[2],
            abi.encodeWithSelector(IHooks.beforeInitialize.selector, sender, testPoolKey, sqrtPriceX96),
            abi.encode(IHooks.beforeInitialize.selector)
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeInitialize as the pool manager
        bytes4 result = adapter.beforeInitialize(sender, testPoolKey, sqrtPriceX96);

        // Verify the result
        assertEq(result, IHooks.beforeInitialize.selector, "Should return beforeInitialize selector");
    }

    function test_BeforeInitialize_MixedHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;

        // Register a mix of hooks - only beforeInitializeHook has BEFORE_INITIALIZE_FLAG
        address[] memory hooks = new address[](3);
        hooks[0] = address(beforeInitializeHook);
        hooks[1] = address(afterInitializeHook);
        hooks[2] = address(beforeDonateHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock response for beforeInitializeHook
        vm.mockCall(
            address(beforeInitializeHook),
            abi.encodeWithSelector(IHooks.beforeInitialize.selector, sender, testPoolKey, sqrtPriceX96),
            abi.encode(IHooks.beforeInitialize.selector)
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeInitialize as the pool manager
        bytes4 result = adapter.beforeInitialize(sender, testPoolKey, sqrtPriceX96);

        // Verify the result is correct
        assertEq(result, IHooks.beforeInitialize.selector, "Should return beforeInitialize selector");
    }

    function test_BeforeInitialize_ExecutionOrder() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;

        // Create multiple hooks with BEFORE_INITIALIZE_FLAG at different addresses
        HookWithEvents firstHook;
        HookWithEvents secondHook;
        HookWithEvents thirdHook;

        // Deploy hooks with the same flag but at different addresses
        address firstHookAddress = address(uint160(0x1000 | Hooks.BEFORE_INITIALIZE_FLAG));
        deployCodeTo("HookWithEvents.sol", "", firstHookAddress);
        firstHook = HookWithEvents(firstHookAddress);

        address secondHookAddress = address(uint160(0x2000 | Hooks.BEFORE_INITIALIZE_FLAG));
        deployCodeTo("HookWithEvents.sol", "", secondHookAddress);
        secondHook = HookWithEvents(secondHookAddress);

        address thirdHookAddress = address(uint160(0x3000 | Hooks.BEFORE_INITIALIZE_FLAG));
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

        // Call beforeInitialize as the pool manager
        bytes4 result = adapter.beforeInitialize(sender, testPoolKey, sqrtPriceX96);

        // Get recorded logs
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Filter logs for BeforeInitializeCalled events
        bytes32 eventSignature = keccak256("BeforeInitializeCalled(address,bytes32,uint160)");

        // Arrays to track which hooks were called and in what order
        address[] memory calledHooks = new address[](3);
        uint256 calledCount = 0;

        // Process logs to extract hook call order
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == eventSignature) {
                // This is a BeforeInitializeCalled event
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
        assertEq(result, IHooks.beforeInitialize.selector, "Should return beforeInitialize selector");
    }

    function test_BeforeInitialize_MixedExecutionOrder() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;

        // Deploy hooks with different flags - simplify by reusing existing hooks
        address[] memory hooks = new address[](5);
        hooks[0] = address(beforeInitializeHook); // Has BEFORE_INITIALIZE_FLAG
        hooks[1] = address(afterInitializeHook); // Has AFTER_INITIALIZE_FLAG
        hooks[2] = address(beforeSwapHook); // Has BEFORE_SWAP_FLAG
        hooks[3] = address(beforeDonateHook); // Has BEFORE_DONATE_FLAG

        // Deploy another hook with BEFORE_INITIALIZE_FLAG at a different address
        address hookAddress = address(uint160(0x200 | Hooks.BEFORE_INITIALIZE_FLAG));
        deployCodeTo("HookWithEvents.sol", "", hookAddress);
        hooks[4] = address(HookWithEvents(hookAddress));

        // Register hooks in a specific order
        adapter.registerHooks(testPoolKey, hooks);

        // Start recording logs to capture events
        vm.recordLogs();

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeInitialize as the pool manager
        bytes4 result = adapter.beforeInitialize(sender, testPoolKey, sqrtPriceX96);

        // Get recorded logs
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Filter logs for BeforeInitializeCalled events
        bytes32 eventSignature = keccak256("BeforeInitializeCalled(address,bytes32,uint160)");

        // Count occurrences of each hook in the logs
        uint256 beforeInitializeCount = 0;
        uint256 afterInitializeCount = 0;
        uint256 beforeSwapCount = 0;
        uint256 beforeDonateCount = 0;

        // Track the order (if any hooks with BEFORE_INITIALIZE_FLAG are called)
        address firstCalled = address(0);
        address lastCalled = address(0);

        // Process logs
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == eventSignature) {
                address emitter = logs[i].emitter;

                if (emitter == address(beforeInitializeHook)) {
                    beforeInitializeCount++;
                    if (firstCalled == address(0)) {
                        firstCalled = emitter;
                    }
                } else if (emitter == address(afterInitializeHook)) {
                    afterInitializeCount++;
                } else if (emitter == address(beforeSwapHook)) {
                    beforeSwapCount++;
                } else if (emitter == address(beforeDonateHook)) {
                    beforeDonateCount++;
                } else if (emitter == hooks[4]) {
                    beforeInitializeCount++;
                    if (firstCalled == address(beforeInitializeHook)) {
                        lastCalled = hooks[4];
                    }
                }
            }
        }

        // Verify only hooks with BEFORE_INITIALIZE_FLAG were called
        assertEq(beforeInitializeCount, 2, "beforeInitializeHook should be called twice");
        assertEq(afterInitializeCount, 0, "afterInitializeHook should not be called");
        assertEq(beforeSwapCount, 0, "beforeSwapHook should not be called");
        assertEq(beforeDonateCount, 0, "beforeDonateHook should not be called");

        // Verify the first called hook is the beforeInitializeHook
        assertEq(firstCalled, address(beforeInitializeHook), "beforeInitializeHook should be called first");
        assertEq(lastCalled, hooks[4], "hooks[4] should be called last");

        // Verify the result
        assertEq(result, IHooks.beforeInitialize.selector, "Should return beforeInitialize selector");
    }

    function test_BeforeInitialize_NoImplementingHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;

        // Register hooks but none implement BEFORE_INITIALIZE_FLAG
        address[] memory hooks = new address[](2);
        hooks[0] = address(afterInitializeHook);
        hooks[1] = address(beforeDonateHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeInitialize as the pool manager
        bytes4 result = adapter.beforeInitialize(sender, testPoolKey, sqrtPriceX96);

        // Verify the result - should still return selector even if no hooks processed
        assertEq(
            result,
            IHooks.beforeInitialize.selector,
            "Should return beforeInitialize selector even with no implementing hooks"
        );
    }

    function test_BeforeInitialize_HookFailure() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;

        // Register a hook with BEFORE_INITIALIZE_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(beforeInitializeHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock the hook to revert when called
        vm.mockCallRevert(
            address(beforeInitializeHook),
            abi.encodeWithSelector(IHooks.beforeInitialize.selector, sender, testPoolKey, sqrtPriceX96),
            "Hook execution failed"
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call should revert because hook reverts
        vm.expectRevert("Sub-hook beforeInitialize failed");
        adapter.beforeInitialize(sender, testPoolKey, sqrtPriceX96);
    }

    function test_BeforeInitialize_InvalidHookReturn() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;

        // Register a hook with BEFORE_INITIALIZE_FLAG
        address[] memory hooks = new address[](1);
        hooks[0] = address(beforeInitializeHook);

        adapter.registerHooks(testPoolKey, hooks);

        // Mock the hook to return an invalid selector
        bytes4 invalidSelector = bytes4(keccak256("invalidSelector()"));
        vm.mockCall(
            address(beforeInitializeHook),
            abi.encodeWithSelector(IHooks.beforeInitialize.selector, sender, testPoolKey, sqrtPriceX96),
            abi.encode(invalidSelector)
        );

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call should revert because hook returns invalid selector
        vm.expectRevert("Invalid beforeInitialize return");
        adapter.beforeInitialize(sender, testPoolKey, sqrtPriceX96);
    }

    function test_BeforeInitialize_NoRegisteredHooks() public {
        // Setup
        address sender = address(0x123);
        PoolKey memory testPoolKey = createTestPoolKey();
        uint160 sqrtPriceX96 = SQRT_PRICE_1_1;

        // Don't register any hooks for this pool

        // Impersonate the pool manager
        impersonatePoolManager();

        // Call beforeInitialize as the pool manager
        bytes4 result = adapter.beforeInitialize(sender, testPoolKey, sqrtPriceX96);

        // Should still return the correct selector even with no hooks registered
        assertEq(
            result, IHooks.beforeInitialize.selector, "Should return beforeInitialize selector with no hooks registered"
        );
    }
}
