// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {IFeeCalculationStrategy} from "../interfaces/IFeeCalculationStrategy.sol";

/// @title FeeCalculationStrategy//
/// @notice Concrete implementation of fee calculation strategies
contract FeeCalculationStrategy is IFeeCalculationStrategy {
    
    /// @notice Maximum allowed fee (100% = 1,000,000 basis points)
    uint24 public constant MAX_FEE = 1_000_000;
    
    /// @notice Minimum allowed fee (0 basis points)
    uint24 public constant MIN_FEE = 0;
    
    /// @inheritdoc IFeeCalculationStrategy
    function calculateFee(
        PoolId, // poolId unused in current implementation
        WeightedFee[] memory weightedFees,
        FeeConfiguration memory config
    ) external pure override returns (uint24 finalFee) {
        // First, filter valid fees
        WeightedFee[] memory validFees = _filterValidFees(weightedFees);
        
        // If no valid hook fees, use fallback
        if (validFees.length == 0) {
            return getFallbackFee(config);
        }
        
        // Apply the specified calculation method
        if (config.method == FeeCalculationMethod.WEIGHTED_AVERAGE) {
            return _calculateWeightedAverage(validFees, config);
        } else if (config.method == FeeCalculationMethod.MEAN) {
            return _calculateMean(validFees, config);
        } else if (config.method == FeeCalculationMethod.MEDIAN) {
            return _calculateMedian(validFees, config);
        } else if (config.method == FeeCalculationMethod.FIRST_OVERRIDE) {
            return _calculateFirstOverride(validFees, config);
        } else if (config.method == FeeCalculationMethod.LAST_OVERRIDE) {
            return _calculateLastOverride(validFees, config);
        } else if (config.method == FeeCalculationMethod.MIN_FEE) {
            return _calculateMinFee(validFees, config);
        } else if (config.method == FeeCalculationMethod.MAX_FEE) {
            return _calculateMaxFee(validFees, config);
        } else if (config.method == FeeCalculationMethod.GOVERNANCE_ONLY) {
            return getFallbackFee(config);
        }
        
        // Default to weighted average if method not recognized
        return _calculateWeightedAverage(validFees, config);
    }
    
    /// @inheritdoc IFeeCalculationStrategy
    function isValidFee(uint24 fee) external pure override returns (bool isValid) {
        return fee > MIN_FEE && fee <= MAX_FEE;
    }
    
    /// @inheritdoc IFeeCalculationStrategy
    function getFallbackFee(FeeConfiguration memory config) public pure override returns (uint24 fallbackFee) {
        // Priority: poolSpecific -> governance -> default
        if (config.poolSpecificFeeSet && config.poolSpecificFee > MIN_FEE && config.poolSpecificFee <= MAX_FEE) {
            return config.poolSpecificFee;
        }
        
        if (config.governanceFeeSet && config.governanceFee > MIN_FEE && config.governanceFee <= MAX_FEE) {
            return config.governanceFee;
        }
        
        return config.defaultFee;
    }
    
    /// @notice Filter out invalid fees and zero-weight entries
    /// @param weightedFees Array of weighted fees to filter
    /// @return validFees Array containing only valid fees
    function _filterValidFees(WeightedFee[] memory weightedFees) internal pure returns (WeightedFee[] memory validFees) {
        // Count valid fees first
        uint256 validCount = 0;
        for (uint256 i = 0; i < weightedFees.length; i++) {
            if (weightedFees[i].isValid && 
                weightedFees[i].weight > 0 && 
                weightedFees[i].fee > MIN_FEE && 
                weightedFees[i].fee <= MAX_FEE) {
                validCount++;
            }
        }
        
        // Create array with exact size
        validFees = new WeightedFee[](validCount);
        uint256 index = 0;
        
        for (uint256 i = 0; i < weightedFees.length; i++) {
            if (weightedFees[i].isValid && 
                weightedFees[i].weight > 0 && 
                weightedFees[i].fee > MIN_FEE && 
                weightedFees[i].fee <= MAX_FEE) {
                validFees[index] = weightedFees[i];
                index++;
            }
        }
    }
    
    /// @notice Calculate weighted average fee
    function _calculateWeightedAverage(WeightedFee[] memory validFees, FeeConfiguration memory config) 
        internal pure returns (uint24) {
        if (validFees.length == 0) return getFallbackFee(config);
        
        uint256 totalWeightedFee = 0;
        uint256 totalWeight = 0;
        
        for (uint256 i = 0; i < validFees.length; i++) {
            totalWeightedFee += uint256(validFees[i].fee) * validFees[i].weight;
            totalWeight += validFees[i].weight;
        }
        
        if (totalWeight == 0) return getFallbackFee(config);
        
        return uint24(totalWeightedFee / totalWeight);
    }
    
    /// @notice Calculate arithmetic mean fee
    function _calculateMean(WeightedFee[] memory validFees, FeeConfiguration memory config) 
        internal pure returns (uint24) {
        if (validFees.length == 0) return getFallbackFee(config);
        
        uint256 totalFee = 0;
        
        for (uint256 i = 0; i < validFees.length; i++) {
            totalFee += validFees[i].fee;
        }
        
        return uint24(totalFee / validFees.length);
    }
    
    /// @notice Calculate median fee
    function _calculateMedian(WeightedFee[] memory validFees, FeeConfiguration memory config) 
        internal pure returns (uint24) {
        if (validFees.length == 0) return getFallbackFee(config);
        
        // Sort fees (simple bubble sort for small arrays)
        uint24[] memory sortedFees = new uint24[](validFees.length);
        for (uint256 i = 0; i < validFees.length; i++) {
            sortedFees[i] = validFees[i].fee;
        }
        
        // Bubble sort
        for (uint256 i = 0; i < sortedFees.length; i++) {
            for (uint256 j = 0; j < sortedFees.length - 1 - i; j++) {
                if (sortedFees[j] > sortedFees[j + 1]) {
                    uint24 temp = sortedFees[j];
                    sortedFees[j] = sortedFees[j + 1];
                    sortedFees[j + 1] = temp;
                }
            }
        }
        
        uint256 length = sortedFees.length;
        if (length % 2 == 0) {
            // Even number: average of two middle values
            return uint24((uint256(sortedFees[length / 2 - 1]) + uint256(sortedFees[length / 2])) / 2);
        } else {
            // Odd number: middle value
            return sortedFees[length / 2];
        }
    }
    
    /// @notice Use first hook's fee
    function _calculateFirstOverride(WeightedFee[] memory validFees, FeeConfiguration memory config) 
        internal pure returns (uint24) {
        if (validFees.length == 0) return getFallbackFee(config);
        return validFees[0].fee;
    }
    
    /// @notice Use last hook's fee
    function _calculateLastOverride(WeightedFee[] memory validFees, FeeConfiguration memory config) 
        internal pure returns (uint24) {
        if (validFees.length == 0) return getFallbackFee(config);
        return validFees[validFees.length - 1].fee;
    }
    
    /// @notice Use minimum fee from all hooks
    function _calculateMinFee(WeightedFee[] memory validFees, FeeConfiguration memory config) 
        internal pure returns (uint24) {
        if (validFees.length == 0) return getFallbackFee(config);
        
        uint24 minFee = validFees[0].fee;
        for (uint256 i = 1; i < validFees.length; i++) {
            if (validFees[i].fee < minFee) {
                minFee = validFees[i].fee;
            }
        }
        return minFee;
    }
    
    /// @notice Use maximum fee from all hooks
    function _calculateMaxFee(WeightedFee[] memory validFees, FeeConfiguration memory config) 
        internal pure returns (uint24) {
        if (validFees.length == 0) return getFallbackFee(config);
        
        uint24 maxFee = validFees[0].fee;
        for (uint256 i = 1; i < validFees.length; i++) {
            if (validFees[i].fee > maxFee) {
                maxFee = validFees[i].fee;
            }
        }
        return maxFee;
    }
}
