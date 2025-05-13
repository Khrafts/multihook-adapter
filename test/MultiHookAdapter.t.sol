// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MultiHookAdapter} from "../src/MultiHookAdapter.sol";
import {MultiHookAdapterBase} from "../src/base/MultiHookAdapterBase.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Vm} from "forge-std/Vm.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";

contract MultiHookAdapterTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;

    MultiHookAdapter public adapter;
    address public user1;
    address public user2;
    
    // Valid hook addresses
    address public beforeSwapHook;
    address public afterSwapHook;
    
    PoolKey public poolKey;
    PoolKey public poolKey2;
    PoolId public poolId;
    PoolId public poolId2;
    
    event HooksRegistered(PoolId indexed poolId, address[] hooks);

    function setUp() public {
        // Deploy a real PoolManager for testing
        deployFreshManagerAndRouters();
        
        // Set up test accounts
        user1 = address(0x1);
        user2 = address(0x2);
        
        // Create hook addresses with valid flags
        beforeSwapHook = address(uint160(Hooks.BEFORE_SWAP_FLAG));
        afterSwapHook = address(uint160(Hooks.AFTER_SWAP_FLAG));
        
        // Define all hook flags to create a valid hook address
        uint160 adapterFlags = uint160(
            Hooks.AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG | Hooks.AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG
                | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_DONATE_FLAG
                | Hooks.BEFORE_DONATE_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_SWAP_FLAG
                | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG | Hooks.AFTER_ADD_LIQUIDITY_FLAG
                | Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_INITIALIZE_FLAG
        );
        
        // Deploy adapter to a valid hook address using deployCodeTo
        address adapterAddress = address(uint160(adapterFlags));
        
        // Deploy the adapter
        deployCodeTo("MultiHookAdapter.sol", abi.encode(manager), adapterAddress);
        
        // Get the deployed adapter
        adapter = MultiHookAdapter(adapterAddress);
        
        // Setup pool information
        currency0 = Currency.wrap(address(0xA));
        currency1 = Currency.wrap(address(0xB));
        poolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(adapter))
        });
        poolId = poolKey.toId();

        // Setup second pool information
        poolKey2 = PoolKey({
            currency0: Currency.wrap(address(0xC)),
            currency1: Currency.wrap(address(0xD)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(adapter))
        });
        poolId2 = poolKey2.toId();
    }
    
    function test_RegisterHooks_AnyUserCanRegisterOnce() public {
        address[] memory hooks = new address[](2);
        hooks[0] = beforeSwapHook;
        hooks[1] = afterSwapHook;
        
        // User1 can register hooks for a pool
        vm.prank(user1);
        vm.expectEmit(true, true, true, true);
        emit HooksRegistered(poolId, hooks);
        adapter.registerHooks(poolKey, hooks);
        
        // Verify hooks are registered
        bytes memory keyHash = abi.encode(poolKey.currency0, poolKey.currency1, poolKey.fee, poolKey.tickSpacing, poolKey.hooks);
        assertTrue(adapter.isRegistered(keyHash), "Pool should be registered");
    }
    
    function test_RegisterHooks_OnlyOnce() public {
        address[] memory hooks1 = new address[](1);
        hooks1[0] = beforeSwapHook;
        
        address[] memory hooks2 = new address[](1);
        hooks2[0] = afterSwapHook;
        
        // First registration should succeed
        vm.prank(user1);
        adapter.registerHooks(poolKey, hooks1);
        
        // Second registration should fail, even from the same user
        vm.prank(user1);
        vm.expectRevert("Hooks already registered");
        adapter.registerHooks(poolKey, hooks2);
        
        // Second registration should fail from a different user
        vm.prank(user2);
        vm.expectRevert("Hooks already registered");
        adapter.registerHooks(poolKey, hooks2);
    }
    
    function test_RegisterHooks_EmptyArray() public {
        address[] memory hooks = new address[](0);
        
        // Should succeed with empty array
        vm.prank(user1);
        adapter.registerHooks(poolKey, hooks);
    }
    
    function test_RegisterHooks_DifferentPoolKeys() public {
        address[] memory hooks1 = new address[](1);
        hooks1[0] = beforeSwapHook;
        
        address[] memory hooks2 = new address[](1);
        hooks2[0] = afterSwapHook;
        
        // Register hooks for first pool
        vm.prank(user1);
        adapter.registerHooks(poolKey, hooks1);
        
        // Register hooks for second pool - should succeed because it's a different pool
        vm.prank(user2);
        adapter.registerHooks(poolKey2, hooks2);
        
        // Verify both pools are registered
        bytes memory keyHash1 = abi.encode(poolKey.currency0, poolKey.currency1, poolKey.fee, poolKey.tickSpacing, poolKey.hooks);
        bytes memory keyHash2 = abi.encode(poolKey2.currency0, poolKey2.currency1, poolKey2.fee, poolKey2.tickSpacing, poolKey2.hooks);
        
        assertTrue(adapter.isRegistered(keyHash1), "First pool should be registered");
        assertTrue(adapter.isRegistered(keyHash2), "Second pool should be registered");
    }
    
    function test_RegisterHooks_RevertOnZeroAddress() public {
        // Create an array with a zero address
        address[] memory hooks = new address[](3);
        hooks[0] = beforeSwapHook;
        hooks[1] = address(0); // Zero address
        hooks[2] = afterSwapHook;
        
        // Should revert with HookAddressZero error
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSignature("HookAddressZero()"));
        adapter.registerHooks(poolKey, hooks);
    }
} 