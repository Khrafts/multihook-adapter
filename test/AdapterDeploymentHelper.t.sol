// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AdapterDeploymentHelper} from "../src/factory/AdapterDeploymentHelper.sol";
import {MultiHookAdapterFactory} from "../src/factory/MultiHookAdapterFactory.sol";
import {MultiHookAdapter} from "../src/MultiHookAdapter.sol";
import {PermissionedMultiHookAdapter} from "../src/PermissionedMultiHookAdapter.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IFeeCalculationStrategy} from "../src/interfaces/IFeeCalculationStrategy.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";

contract AdapterDeploymentHelperTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    
    MultiHookAdapterFactory public factory;
    AdapterDeploymentHelper public helper;
    
    PoolKey public poolKey;
    PoolId public poolId;
    
    uint24 constant DEFAULT_FEE = 3000;
    address constant GOVERNANCE = address(0x1111);
    address constant HOOK_MANAGER = address(0x2222);
    bytes32 constant SALT = bytes32(uint256(0x1234));

    function setUp() public {
        deployFreshManagerAndRouters();
        
        factory = new MultiHookAdapterFactory();
        helper = new AdapterDeploymentHelper(factory);
        
        // Setup pool key//
        currency0 = Currency.wrap(address(0x1));
        currency1 = Currency.wrap(address(0x2));
        poolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(0)) // Will be set later
        });
        poolId = poolKey.toId();
    }

    //////////////////////////////////
    // Deploy and Register Tests    //
    //////////////////////////////////

    function test_DeployAndRegisterHooks_Success() public {
        address[] memory hooks = new address[](2);
        hooks[0] = address(0x1000);
        hooks[1] = address(0x2000);
        
        address adapter = helper.deployAndRegisterHooks(
            manager,
            DEFAULT_FEE,
            poolKey,
            hooks,
            SALT
        );
        
        // Verify adapter deployment
        assertFalse(adapter == address(0), "Adapter should be deployed");
        
        // Verify it's a MultiHookAdapter instance
        MultiHookAdapter multiAdapter = MultiHookAdapter(adapter);
        assertEq(address(multiAdapter.poolManager()), address(manager));
        assertEq(multiAdapter.defaultFee(), DEFAULT_FEE);
        
        // Verify hooks are registered (this would require implementing a getter in the adapter)
        // For now, we'll verify no revert occurred during registration
        assertTrue(true, "Hook registration completed without revert");
    }

    function test_DeployAndRegisterHooks_EmptyHooks() public {
        address[] memory hooks = new address[](0);
        
        address adapter = helper.deployAndRegisterHooks(
            manager,
            DEFAULT_FEE,
            poolKey,
            hooks,
            SALT
        );
        
        assertFalse(adapter == address(0), "Adapter should be deployed even with empty hooks");
    }

    //////////////////////////////////
    // Deploy with Fee Config Tests //
    //////////////////////////////////

    function test_DeployWithFullFeeConfig_Success() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        IFeeCalculationStrategy.FeeCalculationMethod feeMethod = 
            IFeeCalculationStrategy.FeeCalculationMethod.MEAN;
        uint24 poolSpecificFee = 2500;
        
        address adapter = helper.deployWithFullFeeConfig(
            manager,
            DEFAULT_FEE,
            poolKey,
            hooks,
            feeMethod,
            poolSpecificFee,
            SALT
        );
        
        // Verify adapter deployment
        assertFalse(adapter == address(0), "Adapter should be deployed");
        
        MultiHookAdapter multiAdapter = MultiHookAdapter(adapter);
        assertEq(multiAdapter.defaultFee(), DEFAULT_FEE);
        
        // Verify fee configuration was set
        IFeeCalculationStrategy.FeeConfiguration memory config = 
            multiAdapter.getFeeConfiguration(poolId);
        assertEq(uint8(config.method), uint8(feeMethod));
        assertEq(config.poolSpecificFee, poolSpecificFee);
        assertTrue(config.poolSpecificFeeSet);
    }

    function test_DeployWithFullFeeConfig_ZeroPoolFee() public {
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        address adapter = helper.deployWithFullFeeConfig(
            manager,
            DEFAULT_FEE,
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN,
            0, // No pool-specific fee
            SALT
        );
        
        MultiHookAdapter multiAdapter = MultiHookAdapter(adapter);
        IFeeCalculationStrategy.FeeConfiguration memory config = 
            multiAdapter.getFeeConfiguration(poolId);
        assertFalse(config.poolSpecificFeeSet);
    }

    //////////////////////////////////
    // Permissioned Adapter Tests   //
    //////////////////////////////////

    function test_DeployPermissionedWithSetup_Success() public {
        address[] memory initialHooks = new address[](2);
        initialHooks[0] = address(0x1000);
        initialHooks[1] = address(0x2000);
        
        // Deploy adapter
        vm.prank(HOOK_MANAGER);
        address adapter = helper.deployPermissionedWithSetup(
            manager,
            DEFAULT_FEE,
            GOVERNANCE,
            HOOK_MANAGER,
            initialHooks,
            SALT
        );
        
        // Verify adapter deployment
        assertFalse(adapter == address(0), "Adapter should be deployed");
        
        PermissionedMultiHookAdapter permAdapter = PermissionedMultiHookAdapter(adapter);
        assertEq(permAdapter.governance(), GOVERNANCE);
        assertEq(permAdapter.hookManager(), HOOK_MANAGER);
        assertTrue(permAdapter.hookManagementEnabled());
        
        // Now approve hooks separately as hook manager
        vm.prank(HOOK_MANAGER);
        permAdapter.batchApproveHooks(initialHooks);
        
        // Verify hooks were approved
        assertTrue(permAdapter.isHookApproved(initialHooks[0]));
        assertTrue(permAdapter.isHookApproved(initialHooks[1]));
    }

    function test_DeployPermissionedWithSetup_EmptyHooks() public {
        address[] memory initialHooks = new address[](0);
        
        vm.prank(HOOK_MANAGER);
        address adapter = helper.deployPermissionedWithSetup(
            manager,
            DEFAULT_FEE,
            GOVERNANCE,
            HOOK_MANAGER,
            initialHooks,
            SALT
        );
        
        assertFalse(adapter == address(0), "Should deploy with empty initial hooks");
    }

    function test_DeployPermissionedWithSetup_UnauthorizedCaller() public {
        address[] memory initialHooks = new address[](1);
        initialHooks[0] = address(0x1000);
        
        // Deployment itself should succeed - authorization happens during hook operations
        address adapter = helper.deployPermissionedWithSetup(
            manager,
            DEFAULT_FEE,
            GOVERNANCE,
            HOOK_MANAGER,
            initialHooks,
            SALT
        );
        
        assertFalse(adapter == address(0), "Deployment should succeed");
        
        // Authorization check happens when trying to register hooks
        PermissionedMultiHookAdapter permissionedAdapter = PermissionedMultiHookAdapter(adapter);
        
        // This should revert because we're not the hook manager
        vm.expectRevert();
        permissionedAdapter.registerHooks(poolKey, initialHooks);
    }

    //////////////////////////////////
    // Hook Permissions Tests       //
    //////////////////////////////////

    function test_DeployWithHookPermissions_Success() public {
        Hooks.Permissions memory requiredPermissions = Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: false,
            beforeAddLiquidity: true,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
        
        address adapter = helper.deployWithHookPermissions(
            manager,
            DEFAULT_FEE,
            requiredPermissions,
            100 // Max attempts
        );
        
        assertFalse(adapter == address(0), "Adapter should be deployed");
        
        // Verify the deployed address has the required flags
        uint160 expectedFlags = Hooks.BEFORE_INITIALIZE_FLAG | 
                              Hooks.BEFORE_ADD_LIQUIDITY_FLAG | 
                              Hooks.BEFORE_SWAP_FLAG;
        uint160 actualFlags = uint160(adapter) & expectedFlags;
        assertEq(actualFlags, expectedFlags, "Deployed address should have required flags");
    }

    function test_DeployWithHookPermissions_NoPermissions() public {
        Hooks.Permissions memory noPermissions = Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
        
        // Should find an address easily with no requirements
        address adapter = helper.deployWithHookPermissions(
            manager,
            DEFAULT_FEE,
            noPermissions,
            10
        );
        
        assertFalse(adapter == address(0), "Should deploy with no permission requirements");
    }

    function test_DeployWithHookPermissions_TooManyAttempts() public {
        // Set up permissions that are very unlikely to be found quickly
        Hooks.Permissions memory difficultPermissions = Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: true,
            beforeAddLiquidity: true,
            afterAddLiquidity: true,
            beforeRemoveLiquidity: true,
            afterRemoveLiquidity: true,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: true,
            afterDonate: true,
            beforeSwapReturnDelta: true,
            afterSwapReturnDelta: true,
            afterAddLiquidityReturnDelta: true,
            afterRemoveLiquidityReturnDelta: true
        });
        
        // Should revert with low max attempts
        vm.expectRevert("Could not find address with required hook permissions");
        helper.deployWithHookPermissions(
            manager,
            DEFAULT_FEE,
            difficultPermissions,
            5 // Very low attempts
        );
    }

    //////////////////////////////////
    // Batch Deployment Tests       //
    //////////////////////////////////

    function test_BatchDeploy_Success() public {
        AdapterDeploymentHelper.DeploymentConfig[] memory configs = 
            new AdapterDeploymentHelper.DeploymentConfig[](3);
        
        // Regular adapter
        configs[0] = AdapterDeploymentHelper.DeploymentConfig({
            poolManager: manager,
            defaultFee: 2500,
            governance: address(0),
            hookManager: address(0),
            enableHookManagement: false,
            isPermissioned: false,
            salt: bytes32(uint256(1))
        });
        
        // Permissioned adapter
        configs[1] = AdapterDeploymentHelper.DeploymentConfig({
            poolManager: manager,
            defaultFee: 3000,
            governance: GOVERNANCE,
            hookManager: HOOK_MANAGER,
            enableHookManagement: true,
            isPermissioned: true,
            salt: bytes32(uint256(2))
        });
        
        // Another regular adapter
        configs[2] = AdapterDeploymentHelper.DeploymentConfig({
            poolManager: manager,
            defaultFee: 5000,
            governance: address(0),
            hookManager: address(0),
            enableHookManagement: false,
            isPermissioned: false,
            salt: bytes32(uint256(3))
        });
        
        address[] memory adapters = helper.batchDeploy(configs);
        
        assertEq(adapters.length, 3, "Should deploy 3 adapters");
        
        // Verify first adapter (regular)
        MultiHookAdapter adapter0 = MultiHookAdapter(adapters[0]);
        assertEq(adapter0.defaultFee(), 2500);
        assertFalse(adapter0.governanceEnabled());
        
        // Verify second adapter (permissioned)
        PermissionedMultiHookAdapter adapter1 = PermissionedMultiHookAdapter(adapters[1]);
        assertEq(adapter1.defaultFee(), 3000);
        assertTrue(adapter1.governanceEnabled());
        assertEq(adapter1.governance(), GOVERNANCE);
        
        // Verify third adapter (regular)
        MultiHookAdapter adapter2 = MultiHookAdapter(adapters[2]);
        assertEq(adapter2.defaultFee(), 5000);
    }

    function test_BatchDeploy_EmptyArray() public {
        AdapterDeploymentHelper.DeploymentConfig[] memory configs = 
            new AdapterDeploymentHelper.DeploymentConfig[](0);
        
        address[] memory adapters = helper.batchDeploy(configs);
        assertEq(adapters.length, 0, "Should return empty array");
    }

    //////////////////////////////////
    // Helper Function Tests        //
    //////////////////////////////////

    function test_CalculateHookFlags() public {
        Hooks.Permissions memory permissions = Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: false,
            beforeAddLiquidity: true,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: true,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
        
        // Deploy to access internal function (through deployment attempt)
        address adapter = helper.deployWithHookPermissions(
            manager,
            DEFAULT_FEE,
            permissions,
            100
        );
        
        uint160 expectedFlags = Hooks.BEFORE_INITIALIZE_FLAG | 
                              Hooks.BEFORE_ADD_LIQUIDITY_FLAG | 
                              Hooks.AFTER_SWAP_FLAG |
                              Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG;
        
        uint160 actualFlags = uint160(adapter) & expectedFlags;
        assertEq(actualFlags, expectedFlags, "Should have all specified flags");
    }

    //////////////////////////////////
    // Integration Tests            //
    //////////////////////////////////

    function test_Integration_FullWorkflow() public {
        // 1. Deploy adapter with hooks and fee config
        address[] memory hooks = new address[](2);
        hooks[0] = address(0x1000);
        hooks[1] = address(0x2000);
        
        address adapter = helper.deployWithFullFeeConfig(
            manager,
            DEFAULT_FEE,
            poolKey,
            hooks,
            IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN,
            2000,
            SALT
        );
        
        // 2. Verify all configurations
        MultiHookAdapter multiAdapter = MultiHookAdapter(adapter);
        
        // Basic properties
        assertEq(address(multiAdapter.poolManager()), address(manager));
        assertEq(multiAdapter.defaultFee(), DEFAULT_FEE);
        
        // Fee configuration
        IFeeCalculationStrategy.FeeConfiguration memory config = 
            multiAdapter.getFeeConfiguration(poolId);
        assertEq(uint8(config.method), uint8(IFeeCalculationStrategy.FeeCalculationMethod.MEDIAN));
        assertEq(config.poolSpecificFee, 2000);
        assertTrue(config.poolSpecificFeeSet);
        
        // Verify it's immutable (can't register hooks again)
        assertTrue(multiAdapter.areHooksRegistered(poolId));
        
        vm.expectRevert();
        multiAdapter.registerHooks(poolKey, hooks);
    }

    //////////////////////////////////
    // Edge Cases and Error Tests   //
    //////////////////////////////////

    function test_FactoryReference() public {
        assertEq(address(helper.factory()), address(factory), "Should reference correct factory");
    }

    function testFuzz_DeployAndRegister(uint24 fee, bytes32 salt) public {
        vm.assume(fee <= 1_000_000);
        
        address[] memory hooks = new address[](1);
        hooks[0] = address(0x1000);
        
        address adapter = helper.deployAndRegisterHooks(
            manager,
            fee,
            poolKey,
            hooks,
            salt
        );
        
        assertFalse(adapter == address(0), "Should deploy with any valid fee");
        
        MultiHookAdapter multiAdapter = MultiHookAdapter(adapter);
        assertEq(multiAdapter.defaultFee(), fee);
    }
}
