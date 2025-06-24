// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PermissionedMultiHookAdapter} from "../../PermissionedMultiHookAdapter.sol";

/// @title PermissionedBytecodeLib
/// @notice Library for generating PermissionedMultiHookAdapter bytecode
library PermissionedBytecodeLib {
    
    /// @notice Generate bytecode for PermissionedMultiHookAdapter deployment
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @param governance The governance address for fee management
    /// @param hookManager The hook manager address for hook approvals
    /// @param enableHookManagement Whether to enable hook management features
    /// @return bytecode The deployment bytecode with constructor parameters
    function generateBytecode(
        IPoolManager poolManager,
        uint24 defaultFee,
        address governance,
        address hookManager,
        bool enableHookManagement
    ) external pure returns (bytes memory bytecode) {
        bytecode = abi.encodePacked(
            type(PermissionedMultiHookAdapter).creationCode,
            abi.encode(poolManager, defaultFee, governance, hookManager, enableHookManagement)
        );
    }
}