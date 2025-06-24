// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TestMultiHookAdapter} from "./mocks/TestMultiHookAdapterV2.sol";
import {WeightedHookMock} from "./mocks/WeightedHookMock.sol";
import {BeforeSwapHook} from "./mocks/BeforeSwapHook.sol";
import {MultiHookAdapterBase} from "../src/base/MultiHookAdapterBase.sol";
import {IMultiHookAdapterBase} from "../src/interfaces/IMultiHookAdapterBase.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BeforeSwapDelta, toBeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {LPFeeLibrary} from "@uniswap/v4-core/src/libraries/LPFeeLibrary.sol";
import {IFeeCalculationStrategy} from "../src/interfaces/IFeeCalculationStrategy.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {Vm} from "forge-std/Vm.sol";
import "forge-std/console.sol";

/// @title MultiHookAdapterTest
/// @notice Test suite for the unified MultiHookAdapterBase functionality
contract MultiHookAdapterTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;

    TestMultiHookAdapter adapter;
    WeightedHookMock public weightedHook1;
    WeightedHookMock public weightedHook2;
    WeightedHookMock public weightedHook3;
    BeforeSwapHook public standardHook;

    PoolKey public poolKey;
    PoolId public poolId;
    SwapParams public testParams;

    uint24 constant DEFAULT_FEE = 3000; // 0.3%
    address constant GOVERNANCE = address(0x1111);

    event PoolFeeConfigurationUpdated(
        PoolId indexed poolId, 
        IFeeCalculationStrategy.FeeCalculationMethod method,
        uint24 poolSpecificFee
    );

    function setUp() public virtual {
        // Deploy a real PoolManager for testing
        deployFreshManagerAndRouters();

        // Define flags for the adapter
        uint160 adapterFlags = uint160(
            Hooks.AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG | Hooks.AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG
                | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_DONATE_FLAG
                | Hooks.BEFORE_DONATE_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_SWAP_FLAG
                | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG | Hooks.AFTER_ADD_LIQUIDITY_FLAG
                | Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_INITIALIZE_FLAG
        );

        // Deploy adapter to a valid hook address//
        address adapterAddress = address(uint160(adapterFlags));
        deployCodeTo(
            "TestMultiHookAdapterV2.sol", 
            abi.encode(manager, DEFAULT_FEE, GOVERNANCE, true), 
            adapterAddress
        );
        adapter = TestMultiHookAdapter(adapterAddress);

        // Deploy weighted hooks
        deployWeightedHookWithFlag("weightedHook1", Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG, 0x2000);
        deployWeightedHookWithFlag("weightedHook2", Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG, 0x3000);
        deployWeightedHookWithFlag("weightedHook3", Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG, 0x4000);

        // Deploy standard hook
        address standardHookAddress = address(uint160(0x5000 | Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG));
        deployCodeTo("BeforeSwapHook.sol", "", standardHookAddress);
        standardHook = BeforeSwapHook(standardHookAddress);

        // Setup pool information
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

        // Set up standard test parameters for swap
        testParams = SwapParams({zeroForOne: true, amountSpecified: 1e18, sqrtPriceLimitX96: 0});
    }

    function deployWeightedHookWithFlag(string memory hookName, uint160 flag, uint160 offset) internal {
        address hookAddress = address(uint160(flag | offset));
        deployCodeTo("WeightedHookMock.sol", "", hookAddress);

        if (keccak256(bytes(hookName)) == keccak256(bytes("weightedHook1"))) {
            weightedHook1 = WeightedHookMock(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("weightedHook2"))) {
            weightedHook2 = WeightedHookMock(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("weightedHook3"))) {
            weightedHook3 = WeightedHookMock(hookAddress);
        }
    }

    function impersonatePoolManager() internal returns (address) {
        address poolManagerAddress = address(adapter.poolManager());
        vm.prank(poolManagerAddress);
        return poolManagerAddress;
    }

    //////////////////////////////////
    // Fee Configuration Tests      //
    //////////////////////////////////

    function test_SetPoolFeeCalculationMethod() public {
        vm.prank(GOVERNANCE);
        
        vm.expectEmit(true, false, false, true);
        emit PoolFeeConfigurationUpdated(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN, 0);
        
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN);
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(uint8(config.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.MEAN));
    }

    function test_SetPoolSpecificFee() public {
        vm.prank(GOVERNANCE);
        
        vm.expectEmit(true, false, false, true);
        emit PoolFeeConfigurationUpdated(poolId, IFeeCalculationStrategy.FeeCalculationMethod.WEIGHTED_AVERAGE, 2500);
        
        adapter.setPoolSpecificFee(poolId, 2500);
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(config.poolSpecificFee, 2500);
        assertTrue(config.poolSpecificFeeSet);
    }

    function test_SetGovernanceFee() public {
        vm.prank(GOVERNANCE);
        adapter.setGovernanceFee(2000);
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(config.governanceFee, 2000);
        assertTrue(config.governanceFeeSet);
    }

    function test_GetFeeConfiguration_FallbackPriority() public {
        // Test priority: poolSpecific -> governance -> default
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(config.defaultFee, DEFAULT_FEE);
        assertFalse(config.governanceFeeSet);
        assertFalse(config.poolSpecificFeeSet);

        // Set governance fee
        vm.prank(GOVERNANCE);
        adapter.setGovernanceFee(2500);
        config = adapter.getFeeConfiguration(poolId);
        assertEq(config.governanceFee, 2500);
        assertTrue(config.governanceFeeSet);

        // Set pool-specific fee (should have highest priority)
        vm.prank(GOVERNANCE);
        adapter.setPoolSpecificFee(poolId, 3500);
        config = adapter.getFeeConfiguration(poolId);
        assertEq(config.poolSpecificFee, 3500);
        assertTrue(config.poolSpecificFeeSet);
    }

    //////////////////////////////////
    // Weighted Fee Calculation Tests //
    //////////////////////////////////

    function test_BeforeSwap_WeightedFees_Basic() public {
        // Setup weighted hooks with different fees and weights
        weightedHook1.setMockValues(2000, 1, toBeforeSwapDelta(0, 0), true, true); // 2000 bps, weight 1
        weightedHook2.setMockValues(4000, 1, toBeforeSwapDelta(0, 0), true, true); // 4000 bps, weight 1

        address[] memory hooks = new address[](2);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (bytes4 selector, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        // Expected weighted average: (2000*1 + 4000*1) / (1+1) = 3000
        assertEq(resultFee, 3000, "Should return weighted average of fees");
        assertEq(selector, IHooks.beforeSwap.selector);
        assertTrue(weightedHook1.beforeSwapWeightedCalled(), "First weighted hook should be called");
        assertTrue(weightedHook2.beforeSwapWeightedCalled(), "Second weighted hook should be called");
    }

    function test_BeforeSwap_WeightedFees_DifferentWeights() public {
        // Setup hooks with different weights
        weightedHook1.setMockValues(2000, 3, toBeforeSwapDelta(0, 0), true, true); // 2000 bps, weight 3
        weightedHook2.setMockValues(5000, 1, toBeforeSwapDelta(0, 0), true, true); // 5000 bps, weight 1

        address[] memory hooks = new address[](2);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        // Expected: (2000*3 + 5000*1) / (3+1) = 11000/4 = 2750
        assertEq(resultFee, 2750, "Should return weighted average with different weights");
    }

    function test_BeforeSwap_WeightedFees_ZeroWeight() public {
        // Setup hooks where one has zero weight (should be ignored)
        weightedHook1.setMockValues(2000, 1, toBeforeSwapDelta(0, 0), true, true); // 2000 bps, weight 1
        weightedHook2.setMockValues(9999, 0, toBeforeSwapDelta(0, 0), true, true); // 9999 bps, weight 0 (ignored)
        weightedHook3.setMockValues(4000, 1, toBeforeSwapDelta(0, 0), true, true); // 4000 bps, weight 1

        address[] memory hooks = new address[](3);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        hooks[2] = address(weightedHook3);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        // Expected: (2000*1 + 4000*1) / (1+1) = 3000 (ignoring zero weight)
        assertEq(resultFee, 3000, "Should ignore zero-weight hooks");
    }

    function test_BeforeSwap_WeightedFees_NoFeeOverride() public {
        // Setup hooks where some don't provide fee overrides
        weightedHook1.setMockValues(2000, 2, toBeforeSwapDelta(0, 0), true, true);  // Has fee override
        weightedHook2.setMockValues(9999, 1, toBeforeSwapDelta(0, 0), false, true); // No fee override
        weightedHook3.setMockValues(4000, 1, toBeforeSwapDelta(0, 0), true, true);  // Has fee override

        address[] memory hooks = new address[](3);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        hooks[2] = address(weightedHook3);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        // Expected: (2000*2 + 4000*1) / (2+1) = 8000/3 = 2666
        assertEq(resultFee, 2666, "Should ignore hooks without fee overrides");
    }

    //////////////////////////////////
    // Mixed Hook Types Tests       //
    //////////////////////////////////

    function test_BeforeSwap_MixedWeightedAndStandard() public {
        // Setup mixed hook types
        weightedHook1.setMockValues(2000, 2, toBeforeSwapDelta(0, 0), true, true); // Weighted
        standardHook.setReturnValues(toBeforeSwapDelta(0, 0), 6000); // Standard hook with fee

        address[] memory hooks = new address[](2);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(standardHook);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        // Expected: (2000*2 + 6000*1) / (2+1) = 10000/3 = 3333
        assertEq(resultFee, 3333, "Should handle mixed weighted and standard hooks");
        assertTrue(weightedHook1.beforeSwapWeightedCalled(), "Weighted hook should use weighted interface");
        assertTrue(standardHook.wasCalled(), "Standard hook should be called");
    }

    function test_BeforeSwap_StandardHookFallback() public {
        // Test standard hook that claims to support weighted fees but fails
        weightedHook1.setMockValues(2000, 1, toBeforeSwapDelta(0, 0), true, false); // Doesn't support weighted

        address[] memory hooks = new address[](1);
        hooks[0] = address(weightedHook1);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        // Should fallback to standard hook call and use default weight of 1
        assertEq(resultFee, 2000, "Should fallback to standard hook interface");
        assertTrue(weightedHook1.beforeSwapCalled(), "Should call standard beforeSwap");
    }

    //////////////////////////////////
    // Fee Strategy Tests           //
    //////////////////////////////////

    function test_BeforeSwap_MeanStrategy() public {
        // Set strategy to MEAN
        vm.prank(GOVERNANCE);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN);

        // Setup hooks with different weights (should be ignored for mean)
        weightedHook1.setMockValues(1000, 10, toBeforeSwapDelta(0, 0), true, true); // Weight ignored
        weightedHook2.setMockValues(2000, 1, toBeforeSwapDelta(0, 0), true, true);  // Weight ignored
        weightedHook3.setMockValues(3000, 1, toBeforeSwapDelta(0, 0), true, true);  // Weight ignored

        address[] memory hooks = new address[](3);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        hooks[2] = address(weightedHook3);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        // Expected mean: (1000 + 2000 + 3000) / 3 = 2000
        assertEq(resultFee, 2000, "Should return arithmetic mean ignoring weights");
    }

    function test_BeforeSwap_MedianStrategy() public {
        // Set strategy to MEDIAN
        vm.prank(GOVERNANCE);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN);

        // Setup hooks with unsorted fees
        weightedHook1.setMockValues(5000, 1, toBeforeSwapDelta(0, 0), true, true);
        weightedHook2.setMockValues(1000, 1, toBeforeSwapDelta(0, 0), true, true);
        weightedHook3.setMockValues(3000, 1, toBeforeSwapDelta(0, 0), true, true);

        address[] memory hooks = new address[](3);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        hooks[2] = address(weightedHook3);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        // Sorted: [1000, 3000, 5000] -> median = 3000
        assertEq(resultFee, 3000, "Should return median fee");
    }

    function test_BeforeSwap_FirstOverrideStrategy() public {
        // Set strategy to FIRST_OVERRIDE
        vm.prank(GOVERNANCE);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.FIRST_OVERRIDE);

        weightedHook1.setMockValues(1500, 1, toBeforeSwapDelta(0, 0), true, true); // Should be returned
        weightedHook2.setMockValues(2500, 1, toBeforeSwapDelta(0, 0), true, true);
        weightedHook3.setMockValues(3500, 1, toBeforeSwapDelta(0, 0), true, true);

        address[] memory hooks = new address[](3);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        hooks[2] = address(weightedHook3);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        assertEq(resultFee, 1500, "Should return first hook's fee");
    }

    function test_BeforeSwap_LastOverrideStrategy() public {
        // Set strategy to LAST_OVERRIDE
        vm.prank(GOVERNANCE);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.LAST_OVERRIDE);

        weightedHook1.setMockValues(1500, 1, toBeforeSwapDelta(0, 0), true, true);
        weightedHook2.setMockValues(2500, 1, toBeforeSwapDelta(0, 0), true, true);
        weightedHook3.setMockValues(3500, 1, toBeforeSwapDelta(0, 0), true, true); // Should be returned

        address[] memory hooks = new address[](3);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        hooks[2] = address(weightedHook3);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        assertEq(resultFee, 3500, "Should return last hook's fee");
    }

    function test_BeforeSwap_MinFeeStrategy() public {
        // Set strategy to MIN_FEE
        vm.prank(GOVERNANCE);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MIN_FEE);

        weightedHook1.setMockValues(3000, 1, toBeforeSwapDelta(0, 0), true, true);
        weightedHook2.setMockValues(1000, 1, toBeforeSwapDelta(0, 0), true, true); // Minimum
        weightedHook3.setMockValues(5000, 1, toBeforeSwapDelta(0, 0), true, true);

        address[] memory hooks = new address[](3);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        hooks[2] = address(weightedHook3);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        assertEq(resultFee, 1000, "Should return minimum fee");
    }

    function test_BeforeSwap_MaxFeeStrategy() public {
        // Set strategy to MAX_FEE
        vm.prank(GOVERNANCE);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MAX_FEE);

        weightedHook1.setMockValues(3000, 1, toBeforeSwapDelta(0, 0), true, true);
        weightedHook2.setMockValues(1000, 1, toBeforeSwapDelta(0, 0), true, true);
        weightedHook3.setMockValues(5000, 1, toBeforeSwapDelta(0, 0), true, true); // Maximum

        address[] memory hooks = new address[](3);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        hooks[2] = address(weightedHook3);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        assertEq(resultFee, 5000, "Should return maximum fee");
    }

    //////////////////////////////////
    // Fallback Behavior Tests      //
    //////////////////////////////////

    function test_BeforeSwap_NoValidFees_UsesDefault() public {
        // Setup hooks with no fee overrides
        weightedHook1.setMockValues(2000, 1, toBeforeSwapDelta(0, 0), false, true); // No fee override
        weightedHook2.setMockValues(3000, 0, toBeforeSwapDelta(0, 0), true, true);  // Zero weight

        address[] memory hooks = new address[](2);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        assertEq(resultFee, DEFAULT_FEE, "Should return default fee when no valid hook fees");
    }

    function test_BeforeSwap_NoValidFees_UsesGovernanceFee() public {
        // Set governance fee
        vm.prank(GOVERNANCE);
        adapter.setGovernanceFee(2500);

        // Setup hooks with no fee overrides
        weightedHook1.setMockValues(2000, 1, toBeforeSwapDelta(0, 0), false, true); // No fee override

        address[] memory hooks = new address[](1);
        hooks[0] = address(weightedHook1);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        assertEq(resultFee, 2500, "Should return governance fee when no valid hook fees");
    }

    function test_BeforeSwap_NoValidFees_UsesPoolSpecificFee() public {
        // Set pool-specific fee (highest priority)
        vm.prank(GOVERNANCE);
        adapter.setGovernanceFee(2500);
        vm.prank(GOVERNANCE);
        adapter.setPoolSpecificFee(poolId, 3500);

        // Setup hooks with no fee overrides
        weightedHook1.setMockValues(2000, 1, toBeforeSwapDelta(0, 0), false, true); // No fee override

        address[] memory hooks = new address[](1);
        hooks[0] = address(weightedHook1);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (,, uint24 resultFee) = adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        assertEq(resultFee, 3500, "Should return pool-specific fee when no valid hook fees");
    }

    //////////////////////////////////
    // Calculate Pool Fee Tests     //
    //////////////////////////////////

    function test_CalculatePoolFee_Basic() public {
        uint24[] memory hookFees = new uint24[](2);
        hookFees[0] = 2000;
        hookFees[1] = 4000;

        uint256[] memory hookWeights = new uint256[](2);
        hookWeights[0] = 1;
        hookWeights[1] = 1;

        uint24 result = adapter.calculatePoolFee(poolId, hookFees, hookWeights);
        assertEq(result, 3000, "Should return weighted average");
    }

    function test_CalculatePoolFee_DifferentWeights() public {
        uint24[] memory hookFees = new uint24[](2);
        hookFees[0] = 2000;
        hookFees[1] = 5000;

        uint256[] memory hookWeights = new uint256[](2);
        hookWeights[0] = 3;
        hookWeights[1] = 1;

        uint24 result = adapter.calculatePoolFee(poolId, hookFees, hookWeights);
        // Expected: (2000*3 + 5000*1) / (3+1) = 11000/4 = 2750
        assertEq(result, 2750, "Should return weighted average with different weights");
    }

    //////////////////////////////////
    // Access Control Tests         //
    //////////////////////////////////

    function test_SetPoolFeeCalculationMethod_OnlyGovernance() public {
        vm.expectRevert(IMultiHookAdapterBase.UnauthorizedGovernance.selector);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN);

        // Should work with governance
        vm.prank(GOVERNANCE);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN);
    }

    function test_SetPoolSpecificFee_OnlyGovernance() public {
        vm.expectRevert(IMultiHookAdapterBase.UnauthorizedGovernance.selector);
        adapter.setPoolSpecificFee(poolId, 2500);

        // Should work with governance
        vm.prank(GOVERNANCE);
        adapter.setPoolSpecificFee(poolId, 2500);
    }

    function test_SetGovernanceFee_OnlyGovernance() public {
        vm.expectRevert(IMultiHookAdapterBase.UnauthorizedGovernance.selector);
        adapter.setGovernanceFee(2500);

        // Should work with governance
        vm.prank(GOVERNANCE);
        adapter.setGovernanceFee(2500);
    }

    //////////////////////////////////
    // Delta Aggregation Tests      //
    //////////////////////////////////

    function test_BeforeSwap_DeltaAggregation_WithWeightedFees() public {
        // Setup weighted hooks with deltas
        BeforeSwapDelta delta1 = toBeforeSwapDelta(10, 20);
        BeforeSwapDelta delta2 = toBeforeSwapDelta(30, 40);
        
        weightedHook1.setMockValues(2000, 1, delta1, true, true);
        weightedHook2.setMockValues(4000, 1, delta2, true, true);

        address[] memory hooks = new address[](2);
        hooks[0] = address(weightedHook1);
        hooks[1] = address(weightedHook2);
        adapter.registerHooks(poolKey, hooks);

        impersonatePoolManager();
        (, BeforeSwapDelta resultDelta, uint24 resultFee) =
            adapter.beforeSwap(address(0x123), poolKey, testParams, "");

        // Fee should be weighted average: (2000*1 + 4000*1) / 2 = 3000
        assertEq(resultFee, 3000, "Should return weighted average fee");

        // Delta should be aggregated: (10+30, 20+40) = (40, 60)
        assertEq(BeforeSwapDeltaLibrary.getSpecifiedDelta(resultDelta), 40, "Should aggregate specified deltas");
        assertEq(BeforeSwapDeltaLibrary.getUnspecifiedDelta(resultDelta), 60, "Should aggregate unspecified deltas");
    }

    //////////////////////////////////
    // Edge Cases and Error Tests   //
    //////////////////////////////////

    function test_InvalidFee_Reverts() public {
        vm.prank(GOVERNANCE);
        vm.expectRevert(abi.encodeWithSelector(IMultiHookAdapterBase.InvalidFee.selector, 1000001));
        adapter.setGovernanceFee(1000001); // Too high

        vm.prank(GOVERNANCE);
        vm.expectRevert(abi.encodeWithSelector(IMultiHookAdapterBase.InvalidFee.selector, 1000001));
        adapter.setPoolSpecificFee(poolId, 1000001); // Too high
    }

    function test_ArrayLengthMismatch_Reverts() public {
        uint24[] memory hookFees = new uint24[](2);
        uint256[] memory hookWeights = new uint256[](3); // Different length

        vm.expectRevert("Array length mismatch");
        adapter.calculatePoolFee(poolId, hookFees, hookWeights);
    }
}