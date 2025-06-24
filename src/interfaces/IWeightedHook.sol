// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";

/// @title IWeightedHook//
/// @notice Extended hook interface that supports weighted fee contributions
/// @dev Hooks implementing this interface can provide both fee and weight for calculations
interface IWeightedHook is IHooks {
    
    /// @notice Weighted hook result for beforeSwap operations
    struct WeightedHookResult {
        bytes4 selector;           // Function selector for validation
        BeforeSwapDelta delta;     // Balance delta (if applicable)
        uint24 fee;               // Fee in basis points
        uint256 weight;           // Weight for this hook's fee contribution
        bool hasFeeOverride;      // Whether this hook provides a fee override
    }
    
    /// @notice Enhanced beforeSwap with weighted fee contribution
    /// @param sender The address that initiated the swap
    /// @param key The PoolKey for the pool
    /// @param params The swap parameters
    /// @param hookData Arbitrary data passed to the hook
    /// @return result The weighted hook result including fee and weight
    function beforeSwapWeighted(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        bytes calldata hookData
    ) external returns (WeightedHookResult memory result);
    
    /// @notice Get the weight this hook should have in fee calculations
    /// @param key The PoolKey for the pool
    /// @param params The swap parameters
    /// @return weight The weight for this hook (0 = skip this hook)
    function getHookWeight(
        PoolKey calldata key,
        SwapParams calldata params
    ) external view returns (uint256 weight);
    
    /// @notice Check if this hook supports weighted fee calculations
    /// @return supported True if the hook implements weighted fee logic
    function supportsWeightedFees() external view returns (bool supported);
}
