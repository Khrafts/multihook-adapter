// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId} from "v4-core/types/PoolId.sol";
import {IFeeCalculationStrategy} from "./IFeeCalculationStrategy.sol";

/// @title IMultiHookAdapterBase//
/// @notice Unified interface for MultiHookAdapterBase with complete hook aggregation and fee calculation capabilities
/// @dev Consolidates functionality from IMultiHookAdapterBase and IMultiHookAdapterBaseV2 into a single comprehensive interface
interface IMultiHookAdapterBase {
    /// @notice Thrown when a zero address is provided as a hook
    error HookAddressZero();

    /// @notice Thrown when a hook address is invalid for the given fee tier
    error InvalidHookAddress();

    /// @notice Thrown when trying to perform a reentrant call
    error Reentrancy();
    
    /// @notice Thrown when an invalid fee value is provided
    error InvalidFee(uint24 fee);
    
    /// @notice Thrown when an invalid fee calculation method is provided
    error InvalidFeeCalculationMethod();
    
    /// @notice Thrown when caller is not authorized for governance operations
    error UnauthorizedGovernance();

    /// @notice Emitted when hooks are registered for a pool
    /// @param poolId The ID of the pool for which hooks were registered
    /// @param hookAddresses The addresses of the hooks registered
    event HooksRegistered(PoolId indexed poolId, address[] hookAddresses);
    
    /// @notice Emitted when fee configuration is updated for a pool
    /// @param poolId The pool ID
    /// @param method The new fee calculation method
    /// @param poolSpecificFee The pool-specific fee (0 if not set)
    event PoolFeeConfigurationUpdated(
        PoolId indexed poolId, 
        IFeeCalculationStrategy.FeeCalculationMethod method,
        uint24 poolSpecificFee
    );
    
    /// @notice Emitted when governance fee is updated
    /// @param oldFee The previous governance fee
    /// @param newFee The new governance fee
    event GovernanceFeeUpdated(uint24 oldFee, uint24 newFee);

    /// @notice Registers an array of sub-hooks to be used for a given pool.
    /// @param key The PoolKey identifying the pool for which to register hooks.
    /// @param hookAddresses The ordered list of hook contract addresses to attach.
    /// Each hook in the list will be invoked in sequence for each relevant callback.
    function registerHooks(PoolKey calldata key, address[] calldata hookAddresses) external;
    
    /// @notice Set fee calculation method for a specific pool
    /// @param poolId The pool to configure
    /// @param method The fee calculation method to use
    function setPoolFeeCalculationMethod(
        PoolId poolId, 
        IFeeCalculationStrategy.FeeCalculationMethod method
    ) external;
    
    /// @notice Set pool-specific fee override
    /// @param poolId The pool to configure  
    /// @param fee The fee in basis points (0 to disable override)
    function setPoolSpecificFee(PoolId poolId, uint24 fee) external;
    
    /// @notice Set governance fee (if governance is enabled)
    /// @param fee The governance fee in basis points (0 to disable)
    function setGovernanceFee(uint24 fee) external;
    
    /// @notice Get fee configuration for a pool
    /// @param poolId The pool ID
    /// @return config The fee configuration
    function getFeeConfiguration(PoolId poolId) 
        external 
        view 
        returns (IFeeCalculationStrategy.FeeConfiguration memory config);
    
    /// @notice Get the calculated fee for a pool given hook inputs
    /// @param poolId The pool ID
    /// @param hookFees Array of fees from hooks
    /// @param hookWeights Array of weights from hooks  
    /// @return finalFee The calculated final fee
    function calculatePoolFee(
        PoolId poolId,
        uint24[] memory hookFees,
        uint256[] memory hookWeights
    ) external view returns (uint24 finalFee);
}