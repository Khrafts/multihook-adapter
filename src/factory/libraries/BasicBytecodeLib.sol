// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {MultiHookAdapter} from "../../MultiHookAdapter.sol";

/// @title BasicBytecodeLib
/// @notice Library for generating MultiHookAdapter bytecode
library BasicBytecodeLib {
    
    /// @notice Generate bytecode for MultiHookAdapter deployment
    /// @param poolManager The Uniswap V4 pool manager
    /// @param defaultFee The default fee in basis points
    /// @return bytecode The deployment bytecode with constructor parameters
    function generateBytecode(
        IPoolManager poolManager,
        uint24 defaultFee
    ) external pure returns (bytes memory bytecode) {
        bytecode = abi.encodePacked(
            type(MultiHookAdapter).creationCode,
            abi.encode(poolManager, defaultFee)
        );
    }
}