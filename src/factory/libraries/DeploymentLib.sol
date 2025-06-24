// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DeploymentLib
/// @notice Library for common CREATE2 deployment functionality
library DeploymentLib {
    
    /// @notice Error thrown when CREATE2 deployment fails
    error DeploymentFailed();
    
    /// @notice Error thrown when deployment parameters are invalid
    error InvalidDeploymentParameters();
    
    /// @notice Deploy a contract using CREATE2
    /// @param bytecode The contract bytecode with constructor parameters
    /// @param salt The salt for deterministic deployment
    /// @return deployedAddress The address of the deployed contract
    function deploy(bytes memory bytecode, bytes32 salt) internal returns (address deployedAddress) {
        assembly {
            deployedAddress := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(deployedAddress) { revert(0, 0) }
        }
        
        if (deployedAddress == address(0)) {
            revert DeploymentFailed();
        }
    }
    
    /// @notice Predict the address of a CREATE2 deployment
    /// @param deployer The deployer contract address
    /// @param bytecode The contract bytecode with constructor parameters
    /// @param salt The salt for deployment
    /// @return predictedAddress The predicted address
    function predictAddress(
        address deployer,
        bytes memory bytecode,
        bytes32 salt
    ) internal pure returns (address predictedAddress) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                deployer,
                salt,
                keccak256(bytecode)
            )
        );
        
        predictedAddress = address(uint160(uint256(hash)));
    }
    
    /// @notice Validate basic deployment parameters
    /// @param poolManager The pool manager address
    /// @param defaultFee The default fee
    function validateBasicParams(address poolManager, uint24 defaultFee) internal pure {
        if (poolManager == address(0)) revert InvalidDeploymentParameters();
        if (defaultFee > 1_000_000) revert InvalidDeploymentParameters(); // Max 100%
    }
    
    /// @notice Validate governance parameters
    /// @param governance The governance address
    /// @param hookManager The hook manager address
    /// @param enableHookManagement Whether hook management is enabled
    function validateGovernanceParams(
        address governance,
        address hookManager,
        bool enableHookManagement
    ) internal pure {
        if (governance == address(0)) revert InvalidDeploymentParameters();
        if (enableHookManagement && hookManager == address(0)) revert InvalidDeploymentParameters();
    }
}