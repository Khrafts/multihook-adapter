// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {MultiHookAdapterBase} from "./base/MultiHookAdapterBase.sol";
import {IFeeCalculationStrategy} from "./interfaces/IFeeCalculationStrategy.sol";

/// @title MultiHookAdapter//
/// @notice Immutable implementation of MultiHookAdapterBase with fixed hook sets and fee strategies
/// @dev Once hooks are registered for a pool, they cannot be changed. Fee configuration is immutable.
contract MultiHookAdapter is MultiHookAdapterBase {
    
    /// @notice Error thrown when trying to modify hooks after they have been set
    error HooksAlreadyRegistered(PoolId poolId);
    
    /// @notice Error thrown when trying to modify fee configuration after deployment
    error FeeConfigurationImmutable();
    
    /// @dev Track which pools have hooks registered (immutable after first registration)
    mapping(PoolId => bool) private _poolHooksRegistered;

    constructor(
        IPoolManager _poolManager,
        uint24 _defaultFee
    ) MultiHookAdapterBase(_poolManager, _defaultFee, address(0), false) {
        // Governance is disabled for immutable version
    }

    /// @notice Register hooks for a pool (can only be done once per pool)
    /// @param key The PoolKey identifying the pool
    /// @param hookAddresses The ordered list of hook contract addresses
    function registerHooks(PoolKey calldata key, address[] calldata hookAddresses) external override {
        PoolId poolId = key.toId();
        
        // Check if hooks are already registered for this pool
        if (_poolHooksRegistered[poolId]) {
            revert HooksAlreadyRegistered(poolId);
        }
        
        // Register hooks using parent implementation
        _registerHooks(key, hookAddresses);
        
        // Mark this pool as having hooks registered (immutable)
        _poolHooksRegistered[poolId] = true;
    }
    
    /// @notice Check if hooks are already registered for a pool
    /// @param poolId The pool ID to check
    /// @return registered True if hooks are already registered
    function areHooksRegistered(PoolId poolId) external view returns (bool registered) {
        return _poolHooksRegistered[poolId];
    }
    
    /// @notice Set fee calculation method for a pool (disabled - immutable)
    function setPoolFeeCalculationMethod(
        PoolId,
        IFeeCalculationStrategy.FeeCalculationMethod
    ) external pure override {
        revert FeeConfigurationImmutable();
    }
    
    /// @notice Set pool-specific fee (disabled - immutable)
    function setPoolSpecificFee(PoolId, uint24) external pure override {
        revert FeeConfigurationImmutable();
    }
    
    /// @notice Set governance fee (disabled - no governance)
    function setGovernanceFee(uint24) external pure override {
        revert FeeConfigurationImmutable();
    }
    
    /// @notice Register hooks with specific fee calculation method
    /// @param key The PoolKey identifying the pool
    /// @param hookAddresses The ordered list of hook contract addresses
    /// @param feeMethod The fee calculation method to use for this pool
    function registerHooksWithFeeMethod(
        PoolKey calldata key,
        address[] calldata hookAddresses,
        IFeeCalculationStrategy.FeeCalculationMethod feeMethod
    ) external {
        PoolId poolId = key.toId();
        
        // Check if hooks are already registered for this pool
        if (_poolHooksRegistered[poolId]) {
            revert HooksAlreadyRegistered(poolId);
        }
        
        // Register hooks first
        _registerHooks(key, hookAddresses);
        
        // Set the fee calculation method for this pool
        _poolFeeConfigs[poolId].method = feeMethod;
        
        // Mark this pool as having hooks registered (immutable)
        _poolHooksRegistered[poolId] = true;
        
        emit PoolFeeConfigurationUpdated(poolId, feeMethod, 0);
    }
    
    /// @notice Register hooks with specific fee calculation method and pool-specific fee
    /// @param key The PoolKey identifying the pool
    /// @param hookAddresses The ordered list of hook contract addresses
    /// @param feeMethod The fee calculation method to use for this pool
    /// @param poolSpecificFee The pool-specific fee override (0 = no override)
    function registerHooksWithFullFeeConfig(
        PoolKey calldata key,
        address[] calldata hookAddresses,
        IFeeCalculationStrategy.FeeCalculationMethod feeMethod,
        uint24 poolSpecificFee
    ) external {
        PoolId poolId = key.toId();
        
        // Check if hooks are already registered for this pool
        if (_poolHooksRegistered[poolId]) {
            revert HooksAlreadyRegistered(poolId);
        }
        
        // Validate fee if provided
        if (poolSpecificFee > 1_000_000) revert InvalidFee(poolSpecificFee);
        
        // Register hooks first
        _registerHooks(key, hookAddresses);
        
        // Set the fee configuration for this pool
        _poolFeeConfigs[poolId].method = feeMethod;
        _poolFeeConfigs[poolId].poolSpecificFee = poolSpecificFee;
        _poolFeeConfigs[poolId].poolSpecificFeeSet = (poolSpecificFee > 0);
        
        // Mark this pool as having hooks registered (immutable)
        _poolHooksRegistered[poolId] = true;
        
        emit PoolFeeConfigurationUpdated(poolId, feeMethod, poolSpecificFee);
    }
}