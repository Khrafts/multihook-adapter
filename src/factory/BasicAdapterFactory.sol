// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {DeploymentLib} from "./libraries/DeploymentLib.sol";
import {BasicBytecodeLib} from "./libraries/BasicBytecodeLib.sol";

/// @title BasicAdapterFactory
/// @notice Factory contract for deploying basic MultiHookAdapter instances
contract BasicAdapterFactory {
    
    /// @notice Event emitted when a new MultiHookAdapter is deployed
    /// @param adapter The address of the deployed adapter
    /// @param poolManager The pool manager address
    /// @param defaultFee The default fee for the adapter
    /// @param deployer The address that deployed the adapter
    event MultiHookAdapterDeployed(
        address indexed adapter,
        address indexed poolManager, 
        uint24 defaultFee,
        address indexed deployer
    );
    
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
        DeploymentLib.validateBasicParams(address(poolManager), defaultFee);
        
        bytes memory bytecode = BasicBytecodeLib.generateBytecode(poolManager, defaultFee);
        
        adapter = DeploymentLib.deploy(bytecode, salt);
        
        emit MultiHookAdapterDeployed(adapter, address(poolManager), defaultFee, msg.sender);
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
        bytes memory bytecode = BasicBytecodeLib.generateBytecode(poolManager, defaultFee);
        
        adapter = DeploymentLib.predictAddress(address(this), bytecode, salt);
    }
    
    /// @notice Deploy MultiHookAdapter to a specific hook-compatible address
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param targetHookAddress The target address that should have valid hook permissions
    /// @return adapter The deployed adapter address
    /// @dev This function will try different salts to find one that produces the target address
    function deployToHookAddress(
        IPoolManager poolManager,
        uint24 defaultFee,
        address targetHookAddress
    ) external returns (address adapter) {
        DeploymentLib.validateBasicParams(address(poolManager), defaultFee);
        
        bytes memory bytecode = BasicBytecodeLib.generateBytecode(poolManager, defaultFee);
        
        // Try different salts until we find one that gives us the target address
        for (uint256 i = 0; i < 1000; i++) {
            bytes32 salt = bytes32(i);
            
            address predictedAddress = DeploymentLib.predictAddress(address(this), bytecode, salt);
            
            if (predictedAddress == targetHookAddress) {
                adapter = DeploymentLib.deploy(bytecode, salt);
                emit MultiHookAdapterDeployed(adapter, address(poolManager), defaultFee, msg.sender);
                return adapter;
            }
        }
        
        revert("Could not find salt for target address");
    }
}