// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PermissionedMultiHookAdapter} from "../src/PermissionedMultiHookAdapter.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IFeeCalculationStrategy} from "../src/interfaces/IFeeCalculationStrategy.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";

contract PermissionedMultiHookAdapterConcreteTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    
    PermissionedMultiHookAdapter public adapter;
    
    PoolKey public poolKey;
    PoolId public poolId;
    
    uint24 constant DEFAULT_FEE = 3000;
    address constant GOVERNANCE = address(0x1111);
    address constant HOOK_MANAGER = address(0x2222);
    
    event HookApproved(address indexed hook, address indexed approver);
    event HookApprovalRevoked(address indexed hook, address indexed revoker);
    event HookManagerUpdated(address indexed oldManager, address indexed newManager);
    event HooksAdded(PoolId indexed poolId, address[] addedHooks);
    event HooksRemoved(PoolId indexed poolId, address[] removedHooks);
    event HooksRegistered(PoolId indexed poolId, address[] hookAddresses);

    function setUp() public {
        deployFreshManagerAndRouters();
        
        // Deploy adapter (needs valid hook address)//
        uint160 adapterFlags = uint160(
            Hooks.BEFORE_INITIALIZE_FLAG | Hooks.AFTER_INITIALIZE_FLAG |
            Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG |
            Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG
        );
        
        address adapterAddress = address(adapterFlags);
        deployCodeTo(
            "PermissionedMultiHookAdapter.sol",
            abi.encode(manager, DEFAULT_FEE, GOVERNANCE, HOOK_MANAGER, true),
            adapterAddress
        );
        adapter = PermissionedMultiHookAdapter(adapterAddress);
        
        // Setup pool key
        currency0 = Currency.wrap(address(0x1));
        currency1 = Currency.wrap(address(0x2));
        poolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(adapter))
        });
        poolId = poolKey.toId();
    }

    //////////////////////////////////
    // Constructor Tests            //
    //////////////////////////////////

    function test_Constructor_Success() public {
        assertEq(address(adapter.poolManager()), address(manager));
        assertEq(adapter.defaultFee(), DEFAULT_FEE);
        assertEq(adapter.governance(), GOVERNANCE);
        assertEq(adapter.hookManager(), HOOK_MANAGER);
        assertTrue(adapter.governanceEnabled());
        assertTrue(adapter.hookManagementEnabled());
    }

    function test_Constructor_WithoutHookManagement() public {
        uint160 adapterFlags = uint160(Hooks.BEFORE_SWAP_FLAG);
        address adapterAddress = address(adapterFlags | 0x1000);
        
        deployCodeTo(
            "PermissionedMultiHookAdapter.sol",
            abi.encode(manager, DEFAULT_FEE, GOVERNANCE, address(0), false),
            adapterAddress
        );
        
        PermissionedMultiHookAdapter testAdapter = PermissionedMultiHookAdapter(adapterAddress);
        assertFalse(testAdapter.hookManagementEnabled());
        assertEq(testAdapter.hookManager(), address(0));
    }

    //////////////////////////////////
    // Hook Approval Tests          //
    //////////////////////////////////

    function test_ApproveHook_Success() public {
        address hook = address(0x1000);
        
        vm.expectEmit(true, true, false, false);
        emit HookApproved(hook, HOOK_MANAGER);
        
        vm.prank(HOOK_MANAGER);
        adapter.approveHook(hook);
        
        assertTrue(adapter.isHookApproved(hook));
    }

    function test_ApproveHook_UnauthorizedCaller() public {
        address hook = address(0x1000);
        
        vm.expectRevert(PermissionedMultiHookAdapter.UnauthorizedHookManagement.selector);
        adapter.approveHook(hook);
    }

    function test_ApproveHook_ZeroAddress() public {
        vm.prank(HOOK_MANAGER);
        vm.expectRevert("Invalid hook address");
        adapter.approveHook(address(0));
    }

    function test_RevokeHookApproval_Success() public {
        address hook = address(0x1000);
        
        // Approve first
        vm.prank(HOOK_MANAGER);
        adapter.approveHook(hook);
        assertTrue(adapter.isHookApproved(hook));
        
        // Revoke
        vm.expectEmit(true, true, false, false);
        emit HookApprovalRevoked(hook, HOOK_MANAGER);
        
        vm.prank(HOOK_MANAGER);
        adapter.revokeHookApproval(hook);
        
        assertFalse(adapter.isHookApproved(hook));
    }

    function test_BatchApproveHooks_Success() public {
        address[] memory hooks = new address[](3);
        hooks[0] = address(0x1000);
        hooks[1] = address(0x2000);
        hooks[2] = address(0x3000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(hooks);
        
        for (uint256 i = 0; i < hooks.length; i++) {
            assertTrue(adapter.isHookApproved(hooks[i]));
        }
    }

    function test_BatchApproveHooks_WithZeroAddress() public {
        address[] memory hooks = new address[](2);
        hooks[0] = address(0x1000);
        hooks[1] = address(0); // Invalid
        
        vm.prank(HOOK_MANAGER);
        vm.expectRevert("Invalid hook address");
        adapter.batchApproveHooks(hooks);
    }

    function test_BatchRevokeHookApprovals_Success() public {
        address[] memory hooks = new address[](2);
        hooks[0] = address(0x1000);
        hooks[1] = address(0x2000);
        
        // Approve first
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(hooks);
        
        // Revoke
        vm.prank(HOOK_MANAGER);
        adapter.batchRevokeHookApprovals(hooks);
        
        for (uint256 i = 0; i < hooks.length; i++) {
            assertFalse(adapter.isHookApproved(hooks[i]));
        }
    }

    //////////////////////////////////
    // Hook Manager Tests           //
    //////////////////////////////////

    function test_SetHookManager_Success() public {
        address newHookManager = address(0x3333);
        
        vm.expectEmit(true, true, false, false);
        emit HookManagerUpdated(HOOK_MANAGER, newHookManager);
        
        vm.prank(GOVERNANCE);
        adapter.setHookManager(newHookManager);
        
        assertEq(adapter.hookManager(), newHookManager);
    }

    function test_SetHookManager_UnauthorizedCaller() public {
        vm.expectRevert(); // Should revert with governance check
        adapter.setHookManager(address(0x3333));
    }

    //////////////////////////////////
    // Hook Registration Tests      //
    //////////////////////////////////

    function test_RegisterHooks_WithApprovedHooks() public {
        address[] memory hooks = new address[](2);
        hooks[0] = address(0x1000);
        hooks[1] = address(0x2000);
        
        // Approve hooks first
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(hooks);
        
        // Register hooks
        vm.expectEmit(true, false, false, true);
        emit HooksRegistered(poolId, hooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.registerHooks(poolKey, hooks);
    }

    function test_RegisterHooks_UnapprovedHook() public {
        address[] memory hooks = new address[](2);
        hooks[0] = address(0x1000);
        hooks[1] = address(0x2000); // Not approved
        
        // Approve only first hook
        vm.prank(HOOK_MANAGER);
        adapter.approveHook(hooks[0]);
        
        // Should revert due to unapproved hook
        vm.prank(HOOK_MANAGER);
        vm.expectRevert(abi.encodeWithSelector(PermissionedMultiHookAdapter.HookNotApproved.selector, hooks[1]));
        adapter.registerHooks(poolKey, hooks);
    }

    function test_RegisterHooks_UnauthorizedCaller() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        vm.prank(HOOK_MANAGER);
        adapter.approveHook(hooks[0]);
        
        // Non-hook-manager should not be able to register
        vm.expectRevert(PermissionedMultiHookAdapter.UnauthorizedHookManagement.selector);
        adapter.registerHooks(poolKey, hooks);
    }

    //////////////////////////////////
    // Pool Hook Management Tests   //
    //////////////////////////////////

    function test_AddHooksToPool_Success() public {
        // First register some hooks
        address[] memory initialHooks = new address[](1);
        initialHooks[0] = address(0x1000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(initialHooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.registerHooks(poolKey, initialHooks);
        
        // Add more hooks
        address[] memory newHooks = new address[](2);
        newHooks[0] = address(0x2000);
        newHooks[1] = address(0x3000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(newHooks);
        
        vm.expectEmit(true, false, false, true);
        emit HooksAdded(poolId, newHooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.addHooksToPool(poolId, newHooks);
        
        // Verify all hooks are present
        address[] memory allHooks = adapter.getPoolHooks(poolId);
        assertEq(allHooks.length, 3);
    }

    function test_AddHooksToPool_DuplicateHook() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(hooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.registerHooks(poolKey, hooks);
        
        // Try to add same hook again
        vm.prank(HOOK_MANAGER);
        vm.expectRevert(abi.encodeWithSelector(PermissionedMultiHookAdapter.HookAlreadyRegistered.selector, poolId, hooks[0]));
        adapter.addHooksToPool(poolId, hooks);
    }

    function test_RemoveHooksFromPool_Success() public {
        address[] memory hooks = new address[](3);
        hooks[0] = address(0x1000);
        hooks[1] = address(0x2000);
        hooks[2] = address(0x3000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(hooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.registerHooks(poolKey, hooks);
        
        // Remove middle hook
        address[] memory hooksToRemove = new address[](1);
        hooksToRemove[0] = address(0x2000);
        
        vm.expectEmit(true, false, false, true);
        emit HooksRemoved(poolId, hooksToRemove);
        
        vm.prank(HOOK_MANAGER);
        adapter.removeHooksFromPool(poolId, hooksToRemove);
        
        // Verify hook was removed
        address[] memory remainingHooks = adapter.getPoolHooks(poolId);
        assertEq(remainingHooks.length, 2);
        
        // Verify the remaining hooks are correct (order may change due to swap-and-pop)
        bool found1000 = false;
        bool found3000 = false;
        for (uint256 i = 0; i < remainingHooks.length; i++) {
            if (remainingHooks[i] == address(0x1000)) found1000 = true;
            if (remainingHooks[i] == address(0x3000)) found3000 = true;
        }
        assertTrue(found1000 && found3000, "Should contain hooks 0x1000 and 0x3000");
    }

    function test_RemoveHooksFromPool_HookNotRegistered() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(hooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.registerHooks(poolKey, hooks);
        
        // Try to remove hook that's not registered
        address[] memory hooksToRemove = new address[](1);
        hooksToRemove[0] = address(0x9999);
        
        vm.prank(HOOK_MANAGER);
        vm.expectRevert(abi.encodeWithSelector(PermissionedMultiHookAdapter.HookNotRegistered.selector, poolId, address(0x9999)));
        adapter.removeHooksFromPool(poolId, hooksToRemove);
    }

    function test_ReplacePoolHooks_Success() public {
        // Initial hooks
        address[] memory initialHooks = new address[](2);
        initialHooks[0] = address(0x1000);
        initialHooks[1] = address(0x2000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(initialHooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.registerHooks(poolKey, initialHooks);
        
        // New hooks
        address[] memory newHooks = new address[](2);
        newHooks[0] = address(0x3000);
        newHooks[1] = address(0x4000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(newHooks);
        
        vm.expectEmit(true, false, false, true);
        emit HooksRegistered(poolId, newHooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.replacePoolHooks(poolId, newHooks);
        
        // Verify hooks were replaced
        address[] memory currentHooks = adapter.getPoolHooks(poolId);
        assertEq(currentHooks.length, 2);
        assertEq(currentHooks[0], address(0x3000));
        assertEq(currentHooks[1], address(0x4000));
    }

    function test_GetPoolHooks_EmptyPool() public {
        address[] memory hooks = adapter.getPoolHooks(poolId);
        assertEq(hooks.length, 0);
    }

    function test_GetPoolHooks_WithHooks() public {
        address[] memory hooks = new address[](2);
        hooks[0] = address(0x1000);
        hooks[1] = address(0x2000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(hooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.registerHooks(poolKey, hooks);
        
        address[] memory retrievedHooks = adapter.getPoolHooks(poolId);
        assertEq(retrievedHooks.length, 2);
        assertEq(retrievedHooks[0], address(0x1000));
        assertEq(retrievedHooks[1], address(0x2000));
    }

    //////////////////////////////////
    // Fee Configuration Tests      //
    //////////////////////////////////

    function test_SetPoolFeeCalculationMethod_Success() public {
        vm.prank(GOVERNANCE);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN);
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(uint8(config.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.MEAN));
    }

    function test_SetPoolSpecificFee_Success() public {
        vm.prank(GOVERNANCE);
        adapter.setPoolSpecificFee(poolId, 2500);
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(config.poolSpecificFee, 2500);
        assertTrue(config.poolSpecificFeeSet);
    }

    function test_SetGovernanceFee_Success() public {
        vm.prank(GOVERNANCE);
        adapter.setGovernanceFee(2000);
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(config.governanceFee, 2000);
        assertTrue(config.governanceFeeSet);
    }

    //////////////////////////////////
    // Access Control Tests         //
    //////////////////////////////////

    function test_GovernanceOnlyFunctions() public {
        // Non-governance should not be able to call these functions
        vm.expectRevert();
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN);
        
        vm.expectRevert();
        adapter.setPoolSpecificFee(poolId, 2500);
        
        vm.expectRevert();
        adapter.setGovernanceFee(2000);
        
        vm.expectRevert();
        adapter.setHookManager(address(0x3333));
    }

    function test_HookManagerOnlyFunctions() public {
        // Non-hook-manager should not be able to call these functions
        vm.expectRevert(PermissionedMultiHookAdapter.UnauthorizedHookManagement.selector);
        adapter.approveHook(address(0x1000));
        
        vm.expectRevert(PermissionedMultiHookAdapter.UnauthorizedHookManagement.selector);
        adapter.revokeHookApproval(address(0x1000));
        
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        vm.expectRevert(PermissionedMultiHookAdapter.UnauthorizedHookManagement.selector);
        adapter.registerHooks(poolKey, hooks);
        
        vm.expectRevert(PermissionedMultiHookAdapter.UnauthorizedHookManagement.selector);
        adapter.addHooksToPool(poolId, hooks);
        
        vm.expectRevert(PermissionedMultiHookAdapter.UnauthorizedHookManagement.selector);
        adapter.removeHooksFromPool(poolId, hooks);
        
        vm.expectRevert(PermissionedMultiHookAdapter.UnauthorizedHookManagement.selector);
        adapter.replacePoolHooks(poolId, hooks);
    }

    //////////////////////////////////
    // Integration Tests            //
    //////////////////////////////////

    function test_FullWorkflow_WithDynamicHookManagement() public {
        // 1. Approve initial hooks
        address[] memory initialHooks = new address[](2);
        initialHooks[0] = address(0x1000);
        initialHooks[1] = address(0x2000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(initialHooks);
        
        // 2. Register hooks for pool
        vm.prank(HOOK_MANAGER);
        adapter.registerHooks(poolKey, initialHooks);
        
        // 3. Set fee configuration
        vm.prank(GOVERNANCE);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN);
        
        vm.prank(GOVERNANCE);
        adapter.setPoolSpecificFee(poolId, 1500);
        
        // 4. Add more hooks dynamically
        address[] memory additionalHooks = new address[](1);
        additionalHooks[0] = address(0x3000);
        
        vm.prank(HOOK_MANAGER);
        adapter.batchApproveHooks(additionalHooks);
        
        vm.prank(HOOK_MANAGER);
        adapter.addHooksToPool(poolId, additionalHooks);
        
        // 5. Remove a hook
        address[] memory hooksToRemove = new address[](1);
        hooksToRemove[0] = address(0x2000);
        
        vm.prank(HOOK_MANAGER);
        adapter.removeHooksFromPool(poolId, hooksToRemove);
        
        // 6. Verify final state
        address[] memory finalHooks = adapter.getPoolHooks(poolId);
        assertEq(finalHooks.length, 2);
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(uint8(config.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN));
        assertEq(config.poolSpecificFee, 1500);
        assertTrue(config.poolSpecificFeeSet);
    }

    //////////////////////////////////
    // Edge Cases and Fuzz Tests    //
    //////////////////////////////////

    function testFuzz_ApproveAndRevokeHooks(address hookAddr) public {
        vm.assume(hookAddr != address(0));
        
        // Approve
        vm.prank(HOOK_MANAGER);
        adapter.approveHook(hookAddr);
        assertTrue(adapter.isHookApproved(hookAddr));
        
        // Revoke
        vm.prank(HOOK_MANAGER);
        adapter.revokeHookApproval(hookAddr);
        assertFalse(adapter.isHookApproved(hookAddr));
    }

    function testFuzz_SetFeeConfiguration(uint24 fee) public {
        vm.assume(fee <= 1_000_000);
        
        vm.prank(GOVERNANCE);
        adapter.setPoolSpecificFee(poolId, fee);
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(config.poolSpecificFee, fee);
        assertEq(config.poolSpecificFeeSet, fee > 0);
    }
}
