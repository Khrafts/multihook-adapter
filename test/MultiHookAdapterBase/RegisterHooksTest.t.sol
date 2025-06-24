// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBaseTest} from "./MultiHookAdapterBaseTest.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";

contract RegisterHooksTest is MultiHookAdapterBaseTest {
    using PoolIdLibrary for PoolKey;

    function test_RegisterHooks_Success() public {
        // Setup hook addresses
        address[] memory hookAddresses = new address[](3);
        hookAddresses[0] = address(beforeInitializeHook);
        hookAddresses[1] = address(afterInitializeHook);
        hookAddresses[2] = address(beforeDonateHook);

        // Expect the HooksRegistered event to be emitted
        vm.expectEmit(true, true, true, true);
        emit HooksRegistered(poolId, hookAddresses);

        // Register hooks
        adapter.registerHooks(poolKey, hookAddresses);

        // Verify hooks were registered in the correct order
        IHooks[] memory registeredHooks = adapter.getHooksByPool(poolId);
        assertEq(registeredHooks.length, 3, "Should register 3 hooks");
        assertEq(address(registeredHooks[0]), address(beforeInitializeHook), "First hook should match");
        assertEq(address(registeredHooks[1]), address(afterInitializeHook), "Second hook should match");
        assertEq(address(registeredHooks[2]), address(beforeDonateHook), "Third hook should match");
    }

    function test_RegisterHooks_EmptyArray() public {
        // Setup empty hook addresses array
        address[] memory hookAddresses = new address[](0);

        // Register hooks with empty array
        adapter.registerHooks(poolKey, hookAddresses);

        // Verify no hooks were registered
        IHooks[] memory registeredHooks = adapter.getHooksByPool(poolId);
        assertEq(registeredHooks.length, 0, "Should register 0 hooks");
    }

    function test_RegisterHooks_Overwrite() public {
        // First registration with two hooks
        address[] memory hookAddresses1 = new address[](2);
        hookAddresses1[0] = address(beforeInitializeHook);
        hookAddresses1[1] = address(afterInitializeHook);

        adapter.registerHooks(poolKey, hookAddresses1);

        // Verify first registration
        IHooks[] memory registeredHooks1 = adapter.getHooksByPool(poolId);
        assertEq(registeredHooks1.length, 2, "Should register 2 hooks");

        // Second registration with different hooks
        address[] memory hookAddresses2 = new address[](1);
        hookAddresses2[0] = address(beforeDonateHook);

        adapter.registerHooks(poolKey, hookAddresses2);

        // Verify second registration overwrote the first
        IHooks[] memory registeredHooks2 = adapter.getHooksByPool(poolId);
        assertEq(registeredHooks2.length, 1, "Should now have 1 hook");
        assertEq(address(registeredHooks2[0]), address(beforeDonateHook), "Should be the beforeDonateHook");
    }

    function test_RegisterHooks_RevertOnZeroAddress() public {
        // Setup hook addresses with zero address
        address[] memory hookAddresses = new address[](3);
        hookAddresses[0] = address(beforeInitializeHook);
        hookAddresses[1] = address(0);
        hookAddresses[2] = address(afterInitializeHook);

        // Expect revert with custom error
        vm.expectRevert(abi.encodeWithSignature("HookAddressZero()"));
        adapter.registerHooks(poolKey, hookAddresses);
    }

    function test_RegisterHooks_DifferentPools() public {
        // Create a second pool key
        PoolKey memory poolKey2 = PoolKey({
            currency0: Currency.wrap(address(0x3)),
            currency1: Currency.wrap(address(0x4)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(adapter))
        });
        PoolId poolId2 = poolKey2.toId();

        // Register hooks for first pool
        address[] memory hookAddresses1 = new address[](1);
        hookAddresses1[0] = address(beforeInitializeHook);
        adapter.registerHooks(poolKey, hookAddresses1);

        // Register hooks for second pool
        address[] memory hookAddresses2 = new address[](2);
        hookAddresses2[0] = address(afterInitializeHook);
        hookAddresses2[1] = address(beforeDonateHook);
        adapter.registerHooks(poolKey2, hookAddresses2);

        // Verify hooks for first pool
        IHooks[] memory registeredHooks1 = adapter.getHooksByPool(poolId);
        assertEq(registeredHooks1.length, 1, "First pool should have 1 hook");
        assertEq(
            address(registeredHooks1[0]), address(beforeInitializeHook), "First pool should have beforeInitializeHook"
        );

        // Verify hooks for second pool
        IHooks[] memory registeredHooks2 = adapter.getHooksByPool(poolId2);
        assertEq(registeredHooks2.length, 2, "Second pool should have 2 hooks");
        assertEq(
            address(registeredHooks2[0]),
            address(afterInitializeHook),
            "Second pool first hook should be afterInitializeHook"
        );
        assertEq(
            address(registeredHooks2[1]),
            address(beforeDonateHook),
            "Second pool second hook should be beforeDonateHook"
        );
    }
}
