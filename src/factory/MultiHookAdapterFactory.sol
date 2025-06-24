// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {BasicAdapterFactory} from "./BasicAdapterFactory.sol";
import {PermissionedAdapterFactory} from "./PermissionedAdapterFactory.sol";

/// @title MultiHookAdapterFactory
/// @notice Main factory contract that coordinates deployment of MultiHookAdapter instances
/// @dev This factory delegates to specialized factories to reduce contract size
contract MultiHookAdapterFactory {
    
    /// @notice The basic adapter factory for immutable adapters
    BasicAdapterFactory public immutable basicFactory;
    
    /// @notice The permissioned adapter factory for governance-controlled adapters
    PermissionedAdapterFactory public immutable permissionedFactory;
    
    /// @notice Event emitted when factories are initialized
    /// @param basicFactory The basic adapter factory address
    /// @param permissionedFactory The permissioned adapter factory address
    event FactoriesInitialized(address basicFactory, address permissionedFactory);
    
    constructor() {
        basicFactory = new BasicAdapterFactory();
        permissionedFactory = new PermissionedAdapterFactory();
        
        emit FactoriesInitialized(address(basicFactory), address(permissionedFactory));
    }
    
    /// @notice Deploy a new immutable MultiHookAdapter
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points (e.g., 3000 = 0.3%)
    /// @param salt Optional salt for deterministic deployment
    /// @return adapter The deployed adapter address
    function deployMultiHookAdapter(
        IPoolManager poolManager,
        uint24 defaultFee,
        bytes32 salt
    ) external returns (address adapter) {
        return basicFactory.deployMultiHookAdapter(poolManager, defaultFee, salt);
    }
    
    /// @notice Deploy a new permissioned MultiHookAdapter with governance
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param governance The governance address for fee management
    /// @param hookManager The hook manager address for hook approvals
    /// @param enableHookManagement Whether to enable hook management features
    /// @param salt Optional salt for deterministic deployment
    /// @return adapter The deployed adapter address
    function deployPermissionedMultiHookAdapter(
        IPoolManager poolManager,
        uint24 defaultFee,
        address governance,
        address hookManager,
        bool enableHookManagement,
        bytes32 salt
    ) external returns (address adapter) {
        return permissionedFactory.deployPermissionedMultiHookAdapter(
            poolManager, defaultFee, governance, hookManager, enableHookManagement, salt
        );
    }
    
    /// @notice Predict the address of a MultiHookAdapter deployment
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param salt The salt used for deployment
    /// @return adapter The predicted adapter address
    function predictMultiHookAdapterAddress(
        IPoolManager poolManager,
        uint24 defaultFee,
        bytes32 salt
    ) external view returns (address adapter) {
        return basicFactory.predictMultiHookAdapterAddress(poolManager, defaultFee, salt);
    }
    
    /// @notice Predict the address of a PermissionedMultiHookAdapter deployment
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param governance The governance address
    /// @param hookManager The hook manager address
    /// @param enableHookManagement Whether hook management is enabled
    /// @param salt The salt used for deployment
    /// @return adapter The predicted adapter address
    function predictPermissionedMultiHookAdapterAddress(
        IPoolManager poolManager,
        uint24 defaultFee,
        address governance,
        address hookManager,
        bool enableHookManagement,
        bytes32 salt
    ) external view returns (address adapter) {
        return permissionedFactory.predictPermissionedMultiHookAdapterAddress(
            poolManager, defaultFee, governance, hookManager, enableHookManagement, salt
        );
    }
    
    /// @notice Deploy MultiHookAdapter to a specific hook-compatible address
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param targetHookAddress The target address that should have valid hook permissions
    /// @return adapter The deployed adapter address
    function deployToHookAddress(
        IPoolManager poolManager,
        uint24 defaultFee,
        address targetHookAddress
    ) external returns (address adapter) {
        return basicFactory.deployToHookAddress(poolManager, defaultFee, targetHookAddress);
    }
}
