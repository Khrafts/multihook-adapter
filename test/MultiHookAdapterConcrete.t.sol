// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MultiHookAdapter} from "../src/MultiHookAdapter.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IFeeCalculationStrategy} from "../src/interfaces/IFeeCalculationStrategy.sol";
import {IMultiHookAdapterBase} from "../src/interfaces/IMultiHookAdapterBase.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";

contract MultiHookAdapterConcreteTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    
    MultiHookAdapter public adapter;
    
    PoolKey public poolKey;
    PoolId public poolId;
    
    uint24 constant DEFAULT_FEE = 3000;
    
    event HooksRegistered(PoolId indexed poolId, address[] hookAddresses);
    event PoolFeeConfigurationUpdated(
        PoolId indexed poolId, 
        IFeeCalculationStrategy.FeeCalculationMethod method,
        uint24 poolSpecificFee
    );

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
            "MultiHookAdapter.sol",
            abi.encode(manager, DEFAULT_FEE),
            adapterAddress
        );
        adapter = MultiHookAdapter(adapterAddress);
        
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
        assertFalse(adapter.governanceEnabled());
    }

    //////////////////////////////////
    // Hook Registration Tests      //
    //////////////////////////////////

    function test_RegisterHooks_FirstTime() public {
        address[] memory hooks = new address[](2);
        hooks[0] = address(0x1000);
        hooks[1] = address(0x2000);
        
        assertFalse(adapter.areHooksRegistered(poolId));
        
        vm.expectEmit(true, false, false, true);
        emit HooksRegistered(poolId, hooks);
        
        adapter.registerHooks(poolKey, hooks);
        
        assertTrue(adapter.areHooksRegistered(poolId));
    }

    function test_RegisterHooks_AlreadyRegistered() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        // Register once
        adapter.registerHooks(poolKey, hooks);
        
        // Try to register again - should revert
        vm.expectRevert(abi.encodeWithSelector(MultiHookAdapter.HooksAlreadyRegistered.selector, poolId));
        adapter.registerHooks(poolKey, hooks);
    }

    function test_RegisterHooksWithFeeMethod_Success() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        vm.expectEmit(true, false, false, true);
        emit PoolFeeConfigurationUpdated(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN, 0);
        
        adapter.registerHooksWithFeeMethod(
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.MEAN
        );
        
        assertTrue(adapter.areHooksRegistered(poolId));
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(uint8(config.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.MEAN));
    }

    function test_RegisterHooksWithFeeMethod_AlreadyRegistered() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        adapter.registerHooksWithFeeMethod(
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.MEAN
        );
        
        vm.expectRevert(abi.encodeWithSelector(MultiHookAdapter.HooksAlreadyRegistered.selector, poolId));
        adapter.registerHooksWithFeeMethod(
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN
        );
    }

    function test_RegisterHooksWithFullFeeConfig_Success() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        uint24 poolSpecificFee = 2500;
        
        vm.expectEmit(true, false, false, true);
        emit PoolFeeConfigurationUpdated(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN, poolSpecificFee);
        
        adapter.registerHooksWithFullFeeConfig(
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN,
            poolSpecificFee
        );
        
        assertTrue(adapter.areHooksRegistered(poolId));
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(uint8(config.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN));
        assertEq(config.poolSpecificFee, poolSpecificFee);
        assertTrue(config.poolSpecificFeeSet);
    }

    function test_RegisterHooksWithFullFeeConfig_InvalidFee() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        vm.expectRevert(abi.encodeWithSelector(IMultiHookAdapterBase.InvalidFee.selector, 1_000_001));
        adapter.registerHooksWithFullFeeConfig(
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN,
            1_000_001 // Too high
        );
    }

    function test_RegisterHooksWithFullFeeConfig_ZeroFee() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        adapter.registerHooksWithFullFeeConfig(
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN,
            0 // Zero fee - should not set poolSpecificFeeSet
        );
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(config.poolSpecificFee, 0);
        assertFalse(config.poolSpecificFeeSet);
    }

    //////////////////////////////////
    // Immutable Fee Config Tests   //
    //////////////////////////////////

    function test_SetPoolFeeCalculationMethod_Disabled() public {
        vm.expectRevert(MultiHookAdapter.FeeConfigurationImmutable.selector);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN);
    }

    function test_SetPoolSpecificFee_Disabled() public {
        vm.expectRevert(MultiHookAdapter.FeeConfigurationImmutable.selector);
        adapter.setPoolSpecificFee(poolId, 2500);
    }

    function test_SetGovernanceFee_Disabled() public {
        vm.expectRevert(MultiHookAdapter.FeeConfigurationImmutable.selector);
        adapter.setGovernanceFee(2500);
    }

    //////////////////////////////////
    // Fee Configuration Tests      //
    //////////////////////////////////

    function test_GetFeeConfiguration_Defaults() public {
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        
        assertEq(config.defaultFee, DEFAULT_FEE);
        assertFalse(config.governanceFeeSet);
        assertFalse(config.poolSpecificFeeSet);
        assertEq(uint8(config.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.WEIGHTED_AVERAGE));
    }

    function test_GetFeeConfiguration_AfterRegistration() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        adapter.registerHooksWithFullFeeConfig(
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.FIRST_OVERRIDE,
            1500
        );
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        
        assertEq(config.defaultFee, DEFAULT_FEE);
        assertEq(uint8(config.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.FIRST_OVERRIDE));
        assertEq(config.poolSpecificFee, 1500);
        assertTrue(config.poolSpecificFeeSet);
    }

    //////////////////////////////////
    // Access Control Tests         //
    //////////////////////////////////

    function test_AreHooksRegistered_InitiallyFalse() public {
        assertFalse(adapter.areHooksRegistered(poolId));
    }

    function test_AreHooksRegistered_TrueAfterRegistration() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        adapter.registerHooks(poolKey, hooks);
        assertTrue(adapter.areHooksRegistered(poolId));
    }

    function test_AreHooksRegistered_DifferentPools() public {
        // Register hooks for one pool
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        adapter.registerHooks(poolKey, hooks);
        
        // Check different pool
        PoolKey memory differentPoolKey = PoolKey({
            currency0: Currency.wrap(address(0x3)),
            currency1: Currency.wrap(address(0x4)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(adapter))
        });
        PoolId differentPoolId = differentPoolKey.toId();
        
        assertTrue(adapter.areHooksRegistered(poolId));
        assertFalse(adapter.areHooksRegistered(differentPoolId));
    }

    //////////////////////////////////
    // Edge Cases and Integration   //
    //////////////////////////////////

    function test_MultiplePoolsIndependentRegistration() public {
        // Pool 1
        address[] memory hooks1 = new address[](1);
        hooks1[0] = address(0x1000);
        
        adapter.registerHooksWithFeeMethod(
            poolKey,
            hooks1,
            IFeeCalculationStrategy.FeeCalculationMethod.MEAN
        );
        
        // Pool 2
        PoolKey memory poolKey2 = PoolKey({
            currency0: Currency.wrap(address(0x5)),
            currency1: Currency.wrap(address(0x6)),
            fee: 5000,
            tickSpacing: 120,
            hooks: IHooks(address(adapter))
        });
        PoolId poolId2 = poolKey2.toId();
        
        address[] memory hooks2 = new address[](2);
        hooks2[0] = address(0x2000);
        hooks2[1] = address(0x3000);
        
        adapter.registerHooksWithFeeMethod(
            poolKey2,
            hooks2,
            IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN
        );
        
        // Verify both pools are independently configured
        assertTrue(adapter.areHooksRegistered(poolId));
        assertTrue(adapter.areHooksRegistered(poolId2));
        
        IFeeCalculationStrategy.FeeConfiguration memory config1 = adapter.getFeeConfiguration(poolId);
        IFeeCalculationStrategy.FeeConfiguration memory config2 = adapter.getFeeConfiguration(poolId2);
        
        assertEq(uint8(config1.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.MEAN));
        assertEq(uint8(config2.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN));
    }

    function test_CalculatePoolFee_Integration() public {
        // Register hooks first
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        adapter.registerHooksWithFeeMethod(
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.WEIGHTED_AVERAGE
        );
        
        // Test fee calculation
        uint24[] memory hookFees = new uint24[](2);
        hookFees[0] = 2000;
        hookFees[1] = 4000;
        
        uint256[] memory hookWeights = new uint256[](2);
        hookWeights[0] = 1;
        hookWeights[1] = 1;
        
        uint24 result = adapter.calculatePoolFee(poolId, hookFees, hookWeights);
        assertEq(result, 3000); // (2000*1 + 4000*1) / (1+1) = 3000
    }

    //////////////////////////////////
    // Fuzz Tests                   //
    //////////////////////////////////

    function testFuzz_RegisterHooks_DifferentHookCounts(uint8 hookCount) public {
        vm.assume(hookCount <= 10); // Reasonable limit
        
        address[] memory hooks = new address[](hookCount);
        for (uint256 i = 0; i < hookCount; i++) {
            hooks[i] = address(uint160(0x1000 + i));
        }
        
        if (hookCount == 0) {
            // Should succeed with empty hooks
            adapter.registerHooks(poolKey, hooks);
        } else {
            // Should succeed with any number of hooks
            adapter.registerHooks(poolKey, hooks);
        }
        
        assertTrue(adapter.areHooksRegistered(poolId));
    }

    function testFuzz_RegisterHooksWithFee_DifferentMethods(uint8 methodIndex) public {
        // Limit to valid enum values
        vm.assume(methodIndex <= uint8(IFeeCalculationStrategy.FeeCalculationMethod.GOVERNANCE_ONLY));
        
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        IFeeCalculationStrategy.FeeCalculationMethod method = 
            IFeeCalculationStrategy.FeeCalculationMethod(methodIndex);
        
        adapter.registerHooksWithFeeMethod(poolKey, hooks, method);
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(uint8(config.method), methodIndex);
    }

    function testFuzz_RegisterHooksWithFullConfig_ValidFees(uint24 fee) public {
        vm.assume(fee <= 1_000_000);
        
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        adapter.registerHooksWithFullFeeConfig(
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.MEAN,
            fee
        );
        
        IFeeCalculationStrategy.FeeConfiguration memory config = adapter.getFeeConfiguration(poolId);
        assertEq(config.poolSpecificFee, fee);
        assertEq(config.poolSpecificFeeSet, fee > 0);
    }

    //////////////////////////////////
    // Error Cases                  //
    //////////////////////////////////

    function test_DoubleRegistration_SamePool() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        // First registration
        adapter.registerHooks(poolKey, hooks);
        
        // Second registration should fail
        vm.expectRevert(abi.encodeWithSelector(MultiHookAdapter.HooksAlreadyRegistered.selector, poolId));
        adapter.registerHooks(poolKey, hooks);
    }

    function test_ImmutableMethods_AllReverts() public {
        // All governance methods should revert
        vm.expectRevert(MultiHookAdapter.FeeConfigurationImmutable.selector);
        adapter.setPoolFeeCalculationMethod(poolId, IFeeCalculationStrategy.FeeCalculationMethod.MEAN);
        
        vm.expectRevert(MultiHookAdapter.FeeConfigurationImmutable.selector);
        adapter.setPoolSpecificFee(poolId, 2500);
        
        vm.expectRevert(MultiHookAdapter.FeeConfigurationImmutable.selector);
        adapter.setGovernanceFee(2500);
    }
}
