// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {MultiHookAdapterBase} from "./base/MultiHookAdapterBase.sol";
import {IFeeCalculationStrategy} from "./interfaces/IFeeCalculationStrategy.sol";

/// @title PermissionedMultiHookAdapter//
/// @notice Permissioned implementation allowing governance to manage hooks and fee configurations
/// @dev Hooks can be added/removed by approved addresses. Fee configurations can be updated by governance.
contract PermissionedMultiHookAdapter is MultiHookAdapterBase {
    
    /// @notice Error thrown when hook is not in approved registry
    error HookNotApproved(address hook);
    
    /// @notice Error thrown when caller is not authorized to manage hooks
    error UnauthorizedHookManagement();
    
    /// @notice Error thrown when trying to add hook that's already registered for a pool
    error HookAlreadyRegistered(PoolId poolId, address hook);
    
    /// @notice Error thrown when trying to remove hook that's not registered for a pool  
    error HookNotRegistered(PoolId poolId, address hook);
    
    /// @notice Emitted when a hook is approved for use
    /// @param hook The hook address that was approved
    /// @param approver The address that approved the hook
    event HookApproved(address indexed hook, address indexed approver);
    
    /// @notice Emitted when a hook approval is revoked
    /// @param hook The hook address that was revoked
    /// @param revoker The address that revoked the hook
    event HookApprovalRevoked(address indexed hook, address indexed revoker);
    
    /// @notice Emitted when hook manager is updated
    /// @param oldManager The previous hook manager
    /// @param newManager The new hook manager
    event HookManagerUpdated(address indexed oldManager, address indexed newManager);

    /// @notice Emitted when hooks are added to a pool
    /// @param poolId The pool ID
    /// @param addedHooks The hooks that were added
    event HooksAdded(PoolId indexed poolId, address[] addedHooks);
    
    /// @notice Emitted when hooks are removed from a pool
    /// @param poolId The pool ID
    /// @param removedHooks The hooks that were removed
    event HooksRemoved(PoolId indexed poolId, address[] removedHooks);
    
    /// @dev Registry of approved hooks that can be used with pools
    mapping(address => bool) public approvedHooks;
    
    /// @dev Address authorized to manage hook approvals (separate from fee governance)
    address public hookManager;
    
    /// @dev Whether hook management is enabled
    bool public immutable hookManagementEnabled;

    modifier onlyHookManager() {
        if (hookManagementEnabled && msg.sender != hookManager) revert UnauthorizedHookManagement();
        _;
    }

    constructor(
        IPoolManager _poolManager,
        uint24 _defaultFee,
        address _governance,
        address _hookManager,
        bool _hookManagementEnabled
    ) MultiHookAdapterBase(_poolManager, _defaultFee, _governance, true) {
        hookManager = _hookManager;
        hookManagementEnabled = _hookManagementEnabled;
    }

    /// @notice Approve a hook for use in pools
    /// @param hook The hook address to approve
    function approveHook(address hook) external onlyHookManager {
        require(hook != address(0), "Invalid hook address");
        approvedHooks[hook] = true;
        emit HookApproved(hook, msg.sender);
    }
    
    /// @notice Revoke approval for a hook
    /// @param hook The hook address to revoke
    function revokeHookApproval(address hook) external onlyHookManager {
        approvedHooks[hook] = false;
        emit HookApprovalRevoked(hook, msg.sender);
    }
    
    /// @notice Set the hook manager address
    /// @param newHookManager The new hook manager address
    function setHookManager(address newHookManager) external onlyGovernance {
        address oldManager = hookManager;
        hookManager = newHookManager;
        emit HookManagerUpdated(oldManager, newHookManager);
    }
    
    /// @notice Register hooks for a pool (with approval check)
    /// @param key The PoolKey identifying the pool
    /// @param hookAddresses The ordered list of hook contract addresses
    function registerHooks(PoolKey calldata key, address[] calldata hookAddresses) external override onlyHookManager {
        // Verify all hooks are approved
        for (uint256 i = 0; i < hookAddresses.length; i++) {
            if (!approvedHooks[hookAddresses[i]]) {
                revert HookNotApproved(hookAddresses[i]);
            }
        }
        
        // Register hooks using parent implementation
        _registerHooks(key, hookAddresses);
    }
    
    /// @notice Add hooks to an existing pool
    /// @param poolId The pool to add hooks to
    /// @param newHooks The hooks to add
    function addHooksToPool(PoolId poolId, address[] calldata newHooks) external onlyHookManager {
        // Verify all new hooks are approved
        for (uint256 i = 0; i < newHooks.length; i++) {
            if (!approvedHooks[newHooks[i]]) {
                revert HookNotApproved(newHooks[i]);
            }
        }
        
        // Get current hooks
        IHooks[] storage currentHooks = _hooksByPool[poolId];
        
        // Check for duplicates
        for (uint256 i = 0; i < newHooks.length; i++) {
            for (uint256 j = 0; j < currentHooks.length; j++) {
                if (address(currentHooks[j]) == newHooks[i]) {
                    revert HookAlreadyRegistered(poolId, newHooks[i]);
                }
            }
        }
        
        // Add new hooks
        for (uint256 i = 0; i < newHooks.length; i++) {
            currentHooks.push(IHooks(newHooks[i]));
        }
        
        emit HooksAdded(poolId, newHooks);
    }
    
    /// @notice Remove hooks from a pool
    /// @param poolId The pool to remove hooks from
    /// @param hooksToRemove The hook addresses to remove
    function removeHooksFromPool(PoolId poolId, address[] calldata hooksToRemove) external onlyHookManager {
        IHooks[] storage currentHooks = _hooksByPool[poolId];
        
        // For each hook to remove
        for (uint256 i = 0; i < hooksToRemove.length; i++) {
            bool found = false;
            
            // Find and remove the hook
            for (uint256 j = 0; j < currentHooks.length; j++) {
                if (address(currentHooks[j]) == hooksToRemove[i]) {
                    // Move last element to this position and pop
                    currentHooks[j] = currentHooks[currentHooks.length - 1];
                    currentHooks.pop();
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                revert HookNotRegistered(poolId, hooksToRemove[i]);
            }
        }
        
        emit HooksRemoved(poolId, hooksToRemove);
    }
    
    /// @notice Replace all hooks for a pool with new ones
    /// @param poolId The pool to update
    /// @param newHooks The new set of hooks
    function replacePoolHooks(PoolId poolId, address[] calldata newHooks) external onlyHookManager {
        // Verify all new hooks are approved
        for (uint256 i = 0; i < newHooks.length; i++) {
            if (!approvedHooks[newHooks[i]]) {
                revert HookNotApproved(newHooks[i]);
            }
        }
        
        // Clear existing hooks
        delete _hooksByPool[poolId];
        
        // Add new hooks
        IHooks[] storage hookList = _hooksByPool[poolId];
        for (uint256 i = 0; i < newHooks.length; i++) {
            hookList.push(IHooks(newHooks[i]));
        }
        
        emit HooksRegistered(poolId, newHooks);
    }
    
    /// @notice Get current hooks for a pool
    /// @param poolId The pool ID
    /// @return hooks Array of hook addresses
    function getPoolHooks(PoolId poolId) external view returns (address[] memory hooks) {
        IHooks[] storage poolHooks = _hooksByPool[poolId];
        hooks = new address[](poolHooks.length);
        for (uint256 i = 0; i < poolHooks.length; i++) {
            hooks[i] = address(poolHooks[i]);
        }
    }
    
    /// @notice Check if a hook is approved
    /// @param hook The hook address to check
    /// @return approved True if the hook is approved
    function isHookApproved(address hook) external view returns (bool approved) {
        return approvedHooks[hook];
    }
    
    /// @notice Batch approve multiple hooks
    /// @param hooks Array of hook addresses to approve
    function batchApproveHooks(address[] calldata hooks) external onlyHookManager {
        for (uint256 i = 0; i < hooks.length; i++) {
            require(hooks[i] != address(0), "Invalid hook address");
            approvedHooks[hooks[i]] = true;
            emit HookApproved(hooks[i], msg.sender);
        }
    }
    
    /// @notice Batch revoke approval for multiple hooks
    /// @param hooks Array of hook addresses to revoke
    function batchRevokeHookApprovals(address[] calldata hooks) external onlyHookManager {
        for (uint256 i = 0; i < hooks.length; i++) {
            approvedHooks[hooks[i]] = false;
            emit HookApprovalRevoked(hooks[i], msg.sender);
        }
    }
}