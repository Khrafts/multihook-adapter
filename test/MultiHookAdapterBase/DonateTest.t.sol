// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBaseTest} from "./MultiHookAdapterBaseTest.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {DonateHook} from "../mocks/DonateHook.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";

/**
 * @title DonateTest
 * @notice Test suite for the _beforeDonate and _afterDonate functions
 */
contract DonateTest is MultiHookAdapterBaseTest {
    using PoolIdLibrary for PoolKey;

    // Test hooks
    DonateHook public testDonateHook;
    DonateHook public testSecondDonateHook;
    DonateHook public testBeforeDonateOnlyHook;
    DonateHook public testAfterDonateOnlyHook;

    // Test variables
    address sender;
    PoolKey testPoolKey;
    bytes hookData;
    uint256 testAmount0;
    uint256 testAmount1;

    function setUp() public override {
        super.setUp();

        // Common test variables
        sender = address(0x123);
        testPoolKey = createTestPoolKey();
        hookData = "test data";
        testAmount0 = 1e18;
        testAmount1 = 2e18;

        // Deploy test hooks
        // Hook with BEFORE_DONATE_FLAG and AFTER_DONATE_FLAG
        address hookAddress = address(uint160(0x3000 | Hooks.BEFORE_DONATE_FLAG | Hooks.AFTER_DONATE_FLAG));
        deployCodeTo("DonateHook.sol", "", hookAddress);
        testDonateHook = DonateHook(hookAddress);

        // Second hook for multiple hook tests
        address secondHookAddress = address(uint160(0x4000 | Hooks.BEFORE_DONATE_FLAG | Hooks.AFTER_DONATE_FLAG));
        deployCodeTo("DonateHook.sol", "", secondHookAddress);
        testSecondDonateHook = DonateHook(secondHookAddress);

        // Hook with only BEFORE_DONATE_FLAG
        address beforeOnlyAddress = address(uint160(0x5000 | Hooks.BEFORE_DONATE_FLAG));
        deployCodeTo("DonateHook.sol", "", beforeOnlyAddress);
        testBeforeDonateOnlyHook = DonateHook(beforeOnlyAddress);

        // Hook with only AFTER_DONATE_FLAG
        address afterOnlyAddress = address(uint160(0x6000 | Hooks.AFTER_DONATE_FLAG));
        deployCodeTo("DonateHook.sol", "", afterOnlyAddress);
        testAfterDonateOnlyHook = DonateHook(afterOnlyAddress);
    }

    // Test basic beforeDonate with a single hook
    function test_BeforeDonate_Basic() public {
        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(testDonateHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate pool manager for the call
        impersonatePoolManager();

        // Call beforeDonate
        bytes4 selector = adapter.beforeDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);

        // Verify results
        assertEq(selector, IHooks.beforeDonate.selector, "Incorrect selector returned");

        // Verify the hook was called
        assertTrue(testDonateHook.wasCalled(), "Hook was not called");
        assertTrue(testDonateHook.beforeDonateCalled(), "beforeDonate was not called");

        // Verify the parameters were correctly passed
        assertEq(testDonateHook.lastSender(), sender, "Incorrect sender");
        assertEq(testDonateHook.lastAmount0(), testAmount0, "Incorrect amount0");
        assertEq(testDonateHook.lastAmount1(), testAmount1, "Incorrect amount1");
        assertEq(testDonateHook.lastData(), hookData, "Incorrect data");
    }

    // Test basic afterDonate with a single hook
    function test_AfterDonate_Basic() public {
        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(testDonateHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate pool manager for the call
        impersonatePoolManager();

        // Call afterDonate
        bytes4 selector = adapter.afterDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);

        // Verify results
        assertEq(selector, IHooks.afterDonate.selector, "Incorrect selector returned");

        // Verify the hook was called
        assertTrue(testDonateHook.wasCalled(), "Hook was not called");
        assertTrue(testDonateHook.afterDonateCalled(), "afterDonate was not called");

        // Verify the parameters were correctly passed
        assertEq(testDonateHook.lastSender(), sender, "Incorrect sender");
        assertEq(testDonateHook.lastAmount0(), testAmount0, "Incorrect amount0");
        assertEq(testDonateHook.lastAmount1(), testAmount1, "Incorrect amount1");
        assertEq(testDonateHook.lastData(), hookData, "Incorrect data");
    }

    // Test beforeDonate with multiple hooks
    function test_BeforeDonate_MultipleHooks() public {
        // Register multiple hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(testDonateHook);
        hooks[1] = address(testSecondDonateHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate pool manager for the call
        impersonatePoolManager();

        // Call beforeDonate
        bytes4 selector = adapter.beforeDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);

        // Verify results
        assertEq(selector, IHooks.beforeDonate.selector, "Incorrect selector returned");

        // Verify both hooks were called
        assertTrue(testDonateHook.wasCalled(), "First hook was not called");
        assertTrue(testDonateHook.beforeDonateCalled(), "beforeDonate was not called on first hook");
        assertTrue(testSecondDonateHook.wasCalled(), "Second hook was not called");
        assertTrue(testSecondDonateHook.beforeDonateCalled(), "beforeDonate was not called on second hook");

        // Verify the parameters were correctly passed to both hooks
        assertEq(testDonateHook.lastSender(), sender, "Incorrect sender for first hook");
        assertEq(testDonateHook.lastAmount0(), testAmount0, "Incorrect amount0 for first hook");
        assertEq(testDonateHook.lastAmount1(), testAmount1, "Incorrect amount1 for first hook");
        assertEq(testDonateHook.lastData(), hookData, "Incorrect data for first hook");

        assertEq(testSecondDonateHook.lastSender(), sender, "Incorrect sender for second hook");
        assertEq(testSecondDonateHook.lastAmount0(), testAmount0, "Incorrect amount0 for second hook");
        assertEq(testSecondDonateHook.lastAmount1(), testAmount1, "Incorrect amount1 for second hook");
        assertEq(testSecondDonateHook.lastData(), hookData, "Incorrect data for second hook");
    }

    // Test afterDonate with multiple hooks
    function test_AfterDonate_MultipleHooks() public {
        // Register multiple hooks
        address[] memory hooks = new address[](2);
        hooks[0] = address(testDonateHook);
        hooks[1] = address(testSecondDonateHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate pool manager for the call
        impersonatePoolManager();

        // Call afterDonate
        bytes4 selector = adapter.afterDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);

        // Verify results
        assertEq(selector, IHooks.afterDonate.selector, "Incorrect selector returned");

        // Verify both hooks were called
        assertTrue(testDonateHook.wasCalled(), "First hook was not called");
        assertTrue(testDonateHook.afterDonateCalled(), "afterDonate was not called on first hook");
        assertTrue(testSecondDonateHook.wasCalled(), "Second hook was not called");
        assertTrue(testSecondDonateHook.afterDonateCalled(), "afterDonate was not called on second hook");

        // Verify the parameters were correctly passed to both hooks
        assertEq(testDonateHook.lastSender(), sender, "Incorrect sender for first hook");
        assertEq(testDonateHook.lastAmount0(), testAmount0, "Incorrect amount0 for first hook");
        assertEq(testDonateHook.lastAmount1(), testAmount1, "Incorrect amount1 for first hook");
        assertEq(testDonateHook.lastData(), hookData, "Incorrect data for first hook");

        assertEq(testSecondDonateHook.lastSender(), sender, "Incorrect sender for second hook");
        assertEq(testSecondDonateHook.lastAmount0(), testAmount0, "Incorrect amount0 for second hook");
        assertEq(testSecondDonateHook.lastAmount1(), testAmount1, "Incorrect amount1 for second hook");
        assertEq(testSecondDonateHook.lastData(), hookData, "Incorrect data for second hook");
    }

    // Test hooks with specific flags
    function test_Donate_SpecificFlags() public {
        // Register hooks with specific flags
        address[] memory hooks = new address[](2);
        hooks[0] = address(testBeforeDonateOnlyHook);
        hooks[1] = address(testAfterDonateOnlyHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate pool manager for the calls
        impersonatePoolManager();

        // Call beforeDonate
        adapter.beforeDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);

        // Verify only the beforeDonate hook was called
        assertTrue(testBeforeDonateOnlyHook.wasCalled(), "Before-only hook was not called");
        assertTrue(testBeforeDonateOnlyHook.beforeDonateCalled(), "beforeDonate was not called on before-only hook");
        assertFalse(testAfterDonateOnlyHook.wasCalled(), "After-only hook should not be called during beforeDonate");
        assertFalse(
            testAfterDonateOnlyHook.beforeDonateCalled(), "beforeDonate should not be called on after-only hook"
        );

        // Reset the hooks
        testBeforeDonateOnlyHook.resetCalled();
        testAfterDonateOnlyHook.resetCalled();

        // Impersonate pool manager again for afterDonate call
        impersonatePoolManager();

        // Call afterDonate
        adapter.afterDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);

        // Verify only the afterDonate hook was called
        assertFalse(testBeforeDonateOnlyHook.wasCalled(), "Before-only hook should not be called during afterDonate");
        assertFalse(
            testBeforeDonateOnlyHook.afterDonateCalled(), "afterDonate should not be called on before-only hook"
        );
        assertTrue(testAfterDonateOnlyHook.wasCalled(), "After-only hook was not called");
        assertTrue(testAfterDonateOnlyHook.afterDonateCalled(), "afterDonate was not called on after-only hook");
    }

    // Test donate hooks with multiple pools
    function test_Donate_MultiplePools() public {
        // Create a second pool key with different fee
        PoolKey memory secondPoolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 500, // Different fee
            tickSpacing: 10,
            hooks: IHooks(address(adapter))
        });

        // Register different hooks for each pool
        address[] memory hooks1 = new address[](1);
        hooks1[0] = address(testDonateHook);
        adapter.registerHooks(testPoolKey, hooks1);

        address[] memory hooks2 = new address[](1);
        hooks2[0] = address(testSecondDonateHook);
        adapter.registerHooks(secondPoolKey, hooks2);

        // Impersonate pool manager for the calls
        impersonatePoolManager();

        // Call beforeDonate on first pool
        adapter.beforeDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);

        // Verify only the first hook was called
        assertTrue(testDonateHook.wasCalled(), "First hook was not called");
        assertTrue(testDonateHook.beforeDonateCalled(), "beforeDonate was not called on first hook");
        assertFalse(testSecondDonateHook.wasCalled(), "Second hook should not be called for first pool");

        // Reset hooks
        testDonateHook.resetCalled();
        testSecondDonateHook.resetCalled();

        // Impersonate pool manager again for second beforeDonate call
        impersonatePoolManager();

        // Call beforeDonate on second pool
        adapter.beforeDonate(sender, secondPoolKey, testAmount0, testAmount1, hookData);

        // Verify only the second hook was called
        assertFalse(testDonateHook.wasCalled(), "First hook should not be called for second pool");
        assertTrue(testSecondDonateHook.wasCalled(), "Second hook was not called");
        assertTrue(testSecondDonateHook.beforeDonateCalled(), "beforeDonate was not called on second hook");

        // Reset hooks
        testDonateHook.resetCalled();
        testSecondDonateHook.resetCalled();

        // Impersonate pool manager again for first afterDonate call
        impersonatePoolManager();

        // Similar tests for afterDonate
        adapter.afterDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);
        assertTrue(testDonateHook.wasCalled(), "First hook was not called");
        assertTrue(testDonateHook.afterDonateCalled(), "afterDonate was not called on first hook");
        assertFalse(testSecondDonateHook.wasCalled(), "Second hook should not be called for first pool");

        testDonateHook.resetCalled();
        testSecondDonateHook.resetCalled();

        // Impersonate pool manager again for second afterDonate call
        impersonatePoolManager();

        adapter.afterDonate(sender, secondPoolKey, testAmount0, testAmount1, hookData);
        assertFalse(testDonateHook.wasCalled(), "First hook should not be called for second pool");
        assertTrue(testSecondDonateHook.wasCalled(), "Second hook was not called");
        assertTrue(testSecondDonateHook.afterDonateCalled(), "afterDonate was not called on second hook");
    }

    // Test the full donate flow (beforeDonate then afterDonate)
    function test_FullDonate_Flow() public {
        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(testDonateHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate pool manager for the calls
        impersonatePoolManager();

        // Call beforeDonate
        bytes4 beforeSelector = adapter.beforeDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);
        assertEq(beforeSelector, IHooks.beforeDonate.selector, "Incorrect selector returned from beforeDonate");
        assertTrue(testDonateHook.beforeDonateCalled(), "beforeDonate was not called");

        // Reset the hook between calls
        testDonateHook.resetCalled();

        // Impersonate pool manager again for afterDonate call
        impersonatePoolManager();

        // Call afterDonate
        bytes4 afterSelector = adapter.afterDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);
        assertEq(afterSelector, IHooks.afterDonate.selector, "Incorrect selector returned from afterDonate");
        assertTrue(testDonateHook.afterDonateCalled(), "afterDonate was not called");
    }

    // Test with empty hook list
    function test_Donate_EmptyHookList() public {
        // Register empty hook list
        address[] memory hooks = new address[](0);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate pool manager for the calls
        impersonatePoolManager();

        // Call beforeDonate
        bytes4 beforeSelector = adapter.beforeDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);
        assertEq(beforeSelector, IHooks.beforeDonate.selector, "Incorrect selector returned from beforeDonate");

        // Impersonate pool manager again for afterDonate call
        impersonatePoolManager();

        // Call afterDonate
        bytes4 afterSelector = adapter.afterDonate(sender, testPoolKey, testAmount0, testAmount1, hookData);
        assertEq(afterSelector, IHooks.afterDonate.selector, "Incorrect selector returned from afterDonate");
    }

    // Test with zero amounts
    function test_Donate_ZeroAmounts() public {
        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(testDonateHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate pool manager for the calls
        impersonatePoolManager();

        // Call beforeDonate with zero amounts
        adapter.beforeDonate(sender, testPoolKey, 0, 0, hookData);

        // Verify the hook was called with zero amounts
        assertTrue(testDonateHook.wasCalled(), "Hook was not called");
        assertTrue(testDonateHook.beforeDonateCalled(), "beforeDonate was not called");
        assertEq(testDonateHook.lastAmount0(), 0, "Incorrect amount0");
        assertEq(testDonateHook.lastAmount1(), 0, "Incorrect amount1");

        // Reset the hook
        testDonateHook.resetCalled();

        // Impersonate pool manager again for afterDonate call
        impersonatePoolManager();

        // Call afterDonate with zero amounts
        adapter.afterDonate(sender, testPoolKey, 0, 0, hookData);

        // Verify the hook was called with zero amounts
        assertTrue(testDonateHook.wasCalled(), "Hook was not called");
        assertTrue(testDonateHook.afterDonateCalled(), "afterDonate was not called");
        assertEq(testDonateHook.lastAmount0(), 0, "Incorrect amount0");
        assertEq(testDonateHook.lastAmount1(), 0, "Incorrect amount1");
    }

    // Test with empty data
    function test_Donate_EmptyData() public {
        // Register the hook
        address[] memory hooks = new address[](1);
        hooks[0] = address(testDonateHook);
        adapter.registerHooks(testPoolKey, hooks);

        // Impersonate pool manager for the calls
        impersonatePoolManager();

        // Call beforeDonate with empty data
        bytes memory emptyData = "";
        adapter.beforeDonate(sender, testPoolKey, testAmount0, testAmount1, emptyData);

        // Verify the hook was called with empty data
        assertTrue(testDonateHook.wasCalled(), "Hook was not called");
        assertTrue(testDonateHook.beforeDonateCalled(), "beforeDonate was not called");
        assertEq(testDonateHook.lastData(), emptyData, "Incorrect data");

        // Reset the hook
        testDonateHook.resetCalled();

        // Impersonate pool manager again for afterDonate call
        impersonatePoolManager();

        // Call afterDonate with empty data
        adapter.afterDonate(sender, testPoolKey, testAmount0, testAmount1, emptyData);

        // Verify the hook was called with empty data
        assertTrue(testDonateHook.wasCalled(), "Hook was not called");
        assertTrue(testDonateHook.afterDonateCalled(), "afterDonate was not called");
        assertEq(testDonateHook.lastData(), emptyData, "Incorrect data");
    }
}
