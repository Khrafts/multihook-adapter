// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {MultiHookAdapter} from "../MultiHookAdapter.sol";
import {PermissionedMultiHookAdapter} from "../PermissionedMultiHookAdapter.sol";
import {IFeeCalculationStrategy} from "../interfaces/IFeeCalculationStrategy.sol";
import {MultiHookAdapterFactory} from "./MultiHookAdapterFactory.sol";

/// @title AdapterDeploymentHelper
/// @notice Helper contract for deploying adapters with hook registration and fee configuration
contract AdapterDeploymentHelper {
    
    /// @notice The factory contract used for deployments
    MultiHookAdapterFactory public immutable factory;
    
    constructor(MultiHookAdapterFactory _factory) {
        factory = _factory;
    }
    
    /// @notice Deploy MultiHookAdapter and register hooks in one transaction
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param poolKey The pool key for hook registration
    /// @param hookAddresses The hooks to register
    /// @param salt Salt for deterministic deployment
    /// @return adapter The deployed adapter address
    function deployAndRegisterHooks(
        IPoolManager poolManager,
        uint24 defaultFee,
        PoolKey calldata poolKey,
        address[] calldata hookAddresses,
        bytes32 salt
    ) external returns (address adapter) {
        // Deploy the adapter
        adapter = factory.deployMultiHookAdapter(poolManager, defaultFee, salt);
        
        // Register hooks
        MultiHookAdapter(adapter).registerHooks(poolKey, hookAddresses);
    }
    
    /// @notice Deploy MultiHookAdapter with full fee configuration
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param poolKey The pool key for hook registration
    /// @param hookAddresses The hooks to register
    /// @param feeMethod The fee calculation method
    /// @param poolSpecificFee Pool-specific fee override (0 = disabled)
    /// @param salt Salt for deterministic deployment
    /// @return adapter The deployed adapter address
    function deployWithFullFeeConfig(
        IPoolManager poolManager,
        uint24 defaultFee,
        PoolKey calldata poolKey,
        address[] calldata hookAddresses,
        IFeeCalculationStrategy.FeeCalculationMethod feeMethod,
        uint24 poolSpecificFee,
        bytes32 salt
    ) external returns (address adapter) {
        // Deploy the adapter
        adapter = factory.deployMultiHookAdapter(poolManager, defaultFee, salt);
        
        // Register hooks with full fee configuration
        MultiHookAdapter(adapter).registerHooksWithFullFeeConfig(
            poolKey,
            hookAddresses,
            feeMethod,
            poolSpecificFee
        );
    }
    
    /// @notice Deploy PermissionedMultiHookAdapter 
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param governance The governance address
    /// @param hookManager The hook manager address
    /// @param salt Salt for deterministic deployment
    /// @return adapter The deployed adapter address
    /// @dev Hook approval must be done separately by the hook manager after deployment
    function deployPermissionedWithSetup(
        IPoolManager poolManager,
        uint24 defaultFee,
        address governance,
        address hookManager,
        address[] calldata, /* initialApprovedHooks - unused, kept for interface compatibility */
        bytes32 salt
    ) external returns (address adapter) {
        // Deploy the permissioned adapter
        adapter = factory.deployPermissionedMultiHookAdapter(
            poolManager,
            defaultFee,
            governance,
            hookManager,
            true, // Enable hook management
            salt
        );
        
        // Note: Hook approval must be done separately by calling 
        // PermissionedMultiHookAdapter(adapter).batchApproveHooks(hooks) as the hook manager
    }
    
    /// @notice Deploy adapter with specific hook permissions
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param requiredPermissions The hook permissions required
    /// @param maxAttempts Maximum attempts to find suitable address
    /// @return adapter The deployed adapter address with correct permissions
    function deployWithHookPermissions(
        IPoolManager poolManager,
        uint24 defaultFee,
        Hooks.Permissions memory requiredPermissions,
        uint256 maxAttempts
    ) external returns (address adapter) {
        // Calculate the required hook address flags
        uint160 flags = _calculateHookFlags(requiredPermissions);
        
        // Try to find a salt that produces an address with the required flags
        for (uint256 i = 0; i < maxAttempts; i++) {
            bytes32 salt = keccak256(abi.encode(msg.sender, block.timestamp, i));
            
            address predicted = factory.predictMultiHookAdapterAddress(
                poolManager,
                defaultFee,
                salt
            );
            
            // Check if the predicted address has the required flags
            if ((uint160(predicted) & flags) == flags) {
                // Deploy with this salt
                adapter = factory.deployMultiHookAdapter(poolManager, defaultFee, salt);
                return adapter;
            }
        }
        
        revert("Could not find address with required hook permissions");
    }
    
    /// @notice Calculate hook flags from permissions struct
    /// @param permissions The permissions struct
    /// @return flags The calculated flags
    function _calculateHookFlags(Hooks.Permissions memory permissions) internal pure returns (uint160 flags) {
        if (permissions.beforeInitialize) flags |= Hooks.BEFORE_INITIALIZE_FLAG;
        if (permissions.afterInitialize) flags |= Hooks.AFTER_INITIALIZE_FLAG;
        if (permissions.beforeAddLiquidity) flags |= Hooks.BEFORE_ADD_LIQUIDITY_FLAG;
        if (permissions.afterAddLiquidity) flags |= Hooks.AFTER_ADD_LIQUIDITY_FLAG;
        if (permissions.beforeRemoveLiquidity) flags |= Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG;
        if (permissions.afterRemoveLiquidity) flags |= Hooks.AFTER_REMOVE_LIQUIDITY_FLAG;
        if (permissions.beforeSwap) flags |= Hooks.BEFORE_SWAP_FLAG;
        if (permissions.afterSwap) flags |= Hooks.AFTER_SWAP_FLAG;
        if (permissions.beforeDonate) flags |= Hooks.BEFORE_DONATE_FLAG;
        if (permissions.afterDonate) flags |= Hooks.AFTER_DONATE_FLAG;
        if (permissions.beforeSwapReturnDelta) flags |= Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG;
        if (permissions.afterSwapReturnDelta) flags |= Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG;
        if (permissions.afterAddLiquidityReturnDelta) flags |= Hooks.AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG;
        if (permissions.afterRemoveLiquidityReturnDelta) flags |= Hooks.AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG;
    }
    
    /// @notice Configuration for adapter deployment
    struct DeploymentConfig {
        IPoolManager poolManager;
        uint24 defaultFee;
        address governance;
        address hookManager;
        bool enableHookManagement;
        bool isPermissioned;
        bytes32 salt;
    }
    
    /// @notice Batch deploy multiple adapters with different configurations
    /// @param configs Array of deployment configurations
    /// @return adapters Array of deployed adapter addresses
    function batchDeploy(DeploymentConfig[] calldata configs) external returns (address[] memory adapters) {
        adapters = new address[](configs.length);
        
        for (uint256 i = 0; i < configs.length; i++) {
            DeploymentConfig memory config = configs[i];
            
            if (config.isPermissioned) {
                adapters[i] = factory.deployPermissionedMultiHookAdapter(
                    config.poolManager,
                    config.defaultFee,
                    config.governance,
                    config.hookManager,
                    config.enableHookManagement,
                    config.salt
                );
            } else {
                adapters[i] = factory.deployMultiHookAdapter(
                    config.poolManager,
                    config.defaultFee,
                    config.salt
                );
            }
        }
    }
}
