// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {DeploymentLib} from "./libraries/DeploymentLib.sol";
import {PermissionedBytecodeLib} from "./libraries/PermissionedBytecodeLib.sol";

/// @title PermissionedAdapterFactory
/// @notice Factory contract for deploying PermissionedMultiHookAdapter instances
contract PermissionedAdapterFactory {
    
    /// @notice Event emitted when a new PermissionedMultiHookAdapter is deployed
    /// @param adapter The address of the deployed adapter
    /// @param poolManager The pool manager address
    /// @param defaultFee The default fee for the adapter
    /// @param governance The governance address
    /// @param hookManager The hook manager address
    /// @param deployer The address that deployed the adapter
    event PermissionedMultiHookAdapterDeployed(
        address indexed adapter,
        address indexed poolManager,
        uint24 defaultFee,
        address indexed governance,
        address hookManager,
        address deployer
    );
    
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
        DeploymentLib.validateBasicParams(address(poolManager), defaultFee);
        DeploymentLib.validateGovernanceParams(governance, hookManager, enableHookManagement);
        
        bytes memory bytecode = PermissionedBytecodeLib.generateBytecode(
            poolManager, defaultFee, governance, hookManager, enableHookManagement
        );
        
        adapter = DeploymentLib.deploy(bytecode, salt);
        
        emit PermissionedMultiHookAdapterDeployed(
            adapter, 
            address(poolManager), 
            defaultFee, 
            governance, 
            hookManager, 
            msg.sender
        );
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
        bytes memory bytecode = PermissionedBytecodeLib.generateBytecode(
            poolManager, defaultFee, governance, hookManager, enableHookManagement
        );
        
        adapter = DeploymentLib.predictAddress(address(this), bytecode, salt);
    }
}