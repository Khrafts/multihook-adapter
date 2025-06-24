// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FeeCalculationStrategy} from "../src/strategies/FeeCalculationStrategy.sol";
import {IFeeCalculationStrategy} from "../src/interfaces/IFeeCalculationStrategy.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import "forge-std/console.sol";

contract FeeCalculationStrategyTest is Test {
    FeeCalculationStrategy public strategy;
    PoolId public poolId;
    
    // Standard fee configuration for testing//
    IFeeCalculationStrategy.FeeConfiguration public defaultConfig;
    
    function setUp() public {
        strategy = new FeeCalculationStrategy();
        poolId = PoolId.wrap(keccak256("test-pool"));
        
        // Set up default configuration
        defaultConfig = IFeeCalculationStrategy.FeeConfiguration({
            defaultFee: 3000, // 0.3%
            governanceFee: 0,
            governanceFeeSet: false,
            poolSpecificFee: 0,
            poolSpecificFeeSet: false,
            method: IFeeCalculationStrategy.FeeCalculationMethod.WEIGHTED_AVERAGE
        });
    }
    
    //////////////////////////////////
    // Fee Validation Tests         //
    //////////////////////////////////
    
    function testIsValidFee() public {
        assertTrue(strategy.isValidFee(1), "Fee of 1 should be valid");
        assertTrue(strategy.isValidFee(3000), "Fee of 3000 should be valid");
        assertTrue(strategy.isValidFee(1000000), "Max fee should be valid");
        
        assertFalse(strategy.isValidFee(0), "Fee of 0 should be invalid");
        assertFalse(strategy.isValidFee(1000001), "Fee > 1000000 should be invalid");
    }
    
    //////////////////////////////////
    // Fallback Fee Tests           //
    //////////////////////////////////
    
    function testGetFallbackFee_DefaultOnly() public {
        uint24 fallbackFee = strategy.getFallbackFee(defaultConfig);
        assertEq(fallbackFee, 3000, "Should return default fee");
    }
    
    function testGetFallbackFee_WithGovernance() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.governanceFee = 2500;
        config.governanceFeeSet = true;
        
        uint24 fallbackFee = strategy.getFallbackFee(config);
        assertEq(fallbackFee, 2500, "Should return governance fee");
    }
    
    function testGetFallbackFee_WithPoolSpecific() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.governanceFee = 2500;
        config.governanceFeeSet = true;
        config.poolSpecificFee = 4000;
        config.poolSpecificFeeSet = true;
        
        uint24 fallbackFee = strategy.getFallbackFee(config);
        assertEq(fallbackFee, 4000, "Should return pool-specific fee (highest priority)");
    }
    
    function testGetFallbackFee_InvalidGovernanceFee() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.governanceFee = 0; // Invalid
        config.governanceFeeSet = true;
        
        uint24 fallbackFee = strategy.getFallbackFee(config);
        assertEq(fallbackFee, 3000, "Should fallback to default when governance fee is invalid");
    }
    
    //////////////////////////////////
    // Weighted Average Tests       //
    //////////////////////////////////
    
    function testCalculateFee_WeightedAverage_Basic() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](2);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 4000, weight: 1, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 3000, "Should return weighted average: (2000*1 + 4000*1) / 2 = 3000");
    }
    
    function testCalculateFee_WeightedAverage_DifferentWeights() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](3);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 2, isValid: true}); // Weight 2
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 4000, weight: 1, isValid: true}); // Weight 1
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 1000, weight: 1, isValid: true}); // Weight 1
        
        // Expected: (2000*2 + 4000*1 + 1000*1) / (2+1+1) = 9000/4 = 2250
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 2250, "Should return weighted average with different weights");
    }
    
    function testCalculateFee_WeightedAverage_ZeroWeight() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](3);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 9999, weight: 0, isValid: true}); // Should be ignored
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 4000, weight: 1, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 3000, "Should ignore zero-weight fees");
    }
    
    //////////////////////////////////
    // Mean Calculation Tests       //
    //////////////////////////////////
    
    function testCalculateFee_Mean() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.method = IFeeCalculationStrategy.FeeCalculationMethod.MEAN;
        
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](3);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 1000, weight: 999, isValid: true}); // Weight ignored for mean
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1, isValid: true});
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 3000, weight: 1, isValid: true});
        
        // Expected: (1000 + 2000 + 3000) / 3 = 2000
        uint24 result = strategy.calculateFee(poolId, fees, config);
        assertEq(result, 2000, "Should return arithmetic mean ignoring weights");
    }
    
    //////////////////////////////////
    // Median Calculation Tests     //
    //////////////////////////////////
    
    function testCalculateFee_Median_Odd() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.method = IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN;
        
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](5);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 5000, weight: 1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 1000, weight: 1, isValid: true});
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 3000, weight: 1, isValid: true});
        fees[3] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1, isValid: true});
        fees[4] = IFeeCalculationStrategy.WeightedFee({fee: 4000, weight: 1, isValid: true});
        
        // Sorted: [1000, 2000, 3000, 4000, 5000] -> median = 3000
        uint24 result = strategy.calculateFee(poolId, fees, config);
        assertEq(result, 3000, "Should return median for odd number of fees");
    }
    
    function testCalculateFee_Median_Even() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.method = IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN;
        
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](4);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 4000, weight: 1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 1000, weight: 1, isValid: true});
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 3000, weight: 1, isValid: true});
        fees[3] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1, isValid: true});
        
        // Sorted: [1000, 2000, 3000, 4000] -> median = (2000 + 3000) / 2 = 2500
        uint24 result = strategy.calculateFee(poolId, fees, config);
        assertEq(result, 2500, "Should return average of middle two for even number of fees");
    }
    
    //////////////////////////////////
    // First/Last Override Tests    //
    //////////////////////////////////
    
    function testCalculateFee_FirstOverride() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.method = IFeeCalculationStrategy.FeeCalculationMethod.FIRST_OVERRIDE;
        
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](3);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 1500, weight: 1, isValid: true}); // Should be returned
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 2500, weight: 1, isValid: true});
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 3500, weight: 1, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, config);
        assertEq(result, 1500, "Should return first hook's fee");
    }
    
    function testCalculateFee_LastOverride() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.method = IFeeCalculationStrategy.FeeCalculationMethod.LAST_OVERRIDE;
        
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](3);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 1500, weight: 1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 2500, weight: 1, isValid: true});
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 3500, weight: 1, isValid: true}); // Should be returned
        
        uint24 result = strategy.calculateFee(poolId, fees, config);
        assertEq(result, 3500, "Should return last hook's fee");
    }
    
    //////////////////////////////////
    // Min/Max Fee Tests            //
    //////////////////////////////////
    
    function testCalculateFee_MinFee() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.method = IFeeCalculationStrategy.FeeCalculationMethod.MIN_FEE;
        
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](4);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 3000, weight: 1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 1000, weight: 1, isValid: true}); // Minimum
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 5000, weight: 1, isValid: true});
        fees[3] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, config);
        assertEq(result, 1000, "Should return minimum fee");
    }
    
    function testCalculateFee_MaxFee() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.method = IFeeCalculationStrategy.FeeCalculationMethod.MAX_FEE;
        
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](4);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 3000, weight: 1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 1000, weight: 1, isValid: true});
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 5000, weight: 1, isValid: true}); // Maximum
        fees[3] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, config);
        assertEq(result, 5000, "Should return maximum fee");
    }
    
    //////////////////////////////////
    // Governance Only Tests        //
    //////////////////////////////////
    
    function testCalculateFee_GovernanceOnly() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = defaultConfig;
        config.method = IFeeCalculationStrategy.FeeCalculationMethod.GOVERNANCE_ONLY;
        config.governanceFee = 2500;
        config.governanceFeeSet = true;
        
        // These hook fees should be ignored
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](2);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 1000, weight: 1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 5000, weight: 1, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, config);
        assertEq(result, 2500, "Should ignore hook fees and return governance fee");
    }
    
    //////////////////////////////////
    // Invalid Fee Filtering Tests //
    //////////////////////////////////
    
    function testCalculateFee_InvalidFeesFiltered() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](4);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1, isValid: true}); // Valid
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 0, weight: 1, isValid: true}); // Invalid (zero fee)
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 1000001, weight: 1, isValid: true}); // Invalid (too high)
        fees[3] = IFeeCalculationStrategy.WeightedFee({fee: 4000, weight: 1, isValid: true}); // Valid
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 3000, "Should filter invalid fees and calculate from valid ones only");
    }
    
    function testCalculateFee_InvalidFeesMarked() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](3);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1, isValid: true}); // Valid
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 3000, weight: 1, isValid: false}); // Marked invalid
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 4000, weight: 1, isValid: true}); // Valid
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 3000, "Should filter fees marked as invalid");
    }
    
    //////////////////////////////////
    // No Valid Fees Tests         //
    //////////////////////////////////
    
    function testCalculateFee_NoValidFees_UsesDefault() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](2);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 0, weight: 1, isValid: true}); // Invalid
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 0, isValid: true}); // Zero weight
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 3000, "Should return default fee when no valid weighted fees");
    }
    
    function testCalculateFee_EmptyFees_UsesDefault() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](0);
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 3000, "Should return default fee when no fees provided");
    }
    
    //////////////////////////////////
    // Edge Cases                   //
    //////////////////////////////////
    
    function testCalculateFee_SingleFee() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](1);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 2500, weight: 5, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 2500, "Should return single fee regardless of weight");
    }
    
    function testCalculateFee_IdenticalFees() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](3);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 2500, weight: 1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 2500, weight: 3, isValid: true});
        fees[2] = IFeeCalculationStrategy.WeightedFee({fee: 2500, weight: 2, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 2500, "Should return same fee when all fees are identical");
    }
    
    function testCalculateFee_LargeWeights() public {
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](2);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: 1000, weight: 1000000, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: 2000, weight: 1000000, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        assertEq(result, 1500, "Should handle large weights correctly");
    }
    
    //////////////////////////////////
    // Fuzz Tests                   //
    //////////////////////////////////
    
    function testFuzz_WeightedAverage(uint24 fee1, uint24 fee2, uint256 weight1, uint256 weight2) public {
        // Bound inputs to valid ranges
        fee1 = uint24(bound(fee1, 1, 1000000));
        fee2 = uint24(bound(fee2, 1, 1000000));
        weight1 = bound(weight1, 1, 1000000);
        weight2 = bound(weight2, 1, 1000000);
        
        IFeeCalculationStrategy.WeightedFee[] memory fees = new IFeeCalculationStrategy.WeightedFee[](2);
        fees[0] = IFeeCalculationStrategy.WeightedFee({fee: fee1, weight: weight1, isValid: true});
        fees[1] = IFeeCalculationStrategy.WeightedFee({fee: fee2, weight: weight2, isValid: true});
        
        uint24 result = strategy.calculateFee(poolId, fees, defaultConfig);
        
        // Calculate expected result
        uint256 expected = (uint256(fee1) * weight1 + uint256(fee2) * weight2) / (weight1 + weight2);
        
        assertEq(result, uint24(expected), "Fuzz test: weighted average should be correct");
        assertTrue(result >= 1 && result <= 1000000, "Result should be in valid range");
    }
}
