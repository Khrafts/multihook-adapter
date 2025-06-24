// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";

/// @title IFeeCalculationStrategy//
/// @notice Interface for fee calculation strategies in MultiHookAdapter
interface IFeeCalculationStrategy {
    /// @notice Represents a hook's fee contribution with weight
    struct WeightedFee {
        uint24 fee;      // Fee in basis points (e.g., 3000 = 0.3%)
        uint256 weight;  // Weight for this fee (0 = skip this hook)
        bool isValid;    // Whether this fee is valid
    }
    
    /// @notice Fee configuration for a pool
    struct FeeConfiguration {
        uint24 defaultFee;      // Immutable fallback fee set at deployment
        uint24 governanceFee;   // Optional governance override (0 = not set)
        bool governanceFeeSet;  // Whether governance fee is active
        uint24 poolSpecificFee; // Pool-specific override (0 = not set)
        bool poolSpecificFeeSet; // Whether pool-specific fee is active
        FeeCalculationMethod method; // Calculation method for this pool
    }
    
    /// @notice Available fee calculation methods
    enum FeeCalculationMethod {
        WEIGHTED_AVERAGE,    // Default: weighted average of all hook fees
        MEAN,               // Arithmetic mean of all valid fees
        MEDIAN,             // Median of all valid fees
        FIRST_OVERRIDE,     // First hook with valid fee wins
        LAST_OVERRIDE,      // Last hook with valid fee wins
        MIN_FEE,            // Minimum fee from all hooks
        MAX_FEE,            // Maximum fee from all hooks
        GOVERNANCE_ONLY     // Only use governance/default fees, ignore hooks
    }
    
    /// @notice Calculate the final fee for a pool given hook contributions
    /// @param poolId The pool identifier
    /// @param weightedFees Array of weighted fee contributions from hooks
    /// @param config Fee configuration for this pool
    /// @return finalFee The calculated fee in basis points
    function calculateFee(
        PoolId poolId,
        WeightedFee[] memory weightedFees,
        FeeConfiguration memory config
    ) external pure returns (uint24 finalFee);
    
    /// @notice Validate that a fee is within acceptable bounds
    /// @param fee Fee to validate in basis points
    /// @return isValid Whether the fee is valid
    function isValidFee(uint24 fee) external pure returns (bool isValid);
    
    /// @notice Get the fallback fee using priority: poolSpecific -> governance -> default
    /// @param config Fee configuration for this pool
    /// @return fallbackFee The appropriate fallback fee
    function getFallbackFee(FeeConfiguration memory config) external pure returns (uint24 fallbackFee);
}
