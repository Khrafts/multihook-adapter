// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHooksAdapterBase} from "../../src/base/MultiHookAdapterBase.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IBaseHookExtension} from "../../src/interfaces/IBaseHookExtension.sol";

/// @title TestMultiHookAdapter
/// @notice Concrete implementation of MultiHooksAdapterBase for testing
contract TestMultiHookAdapter is MultiHooksAdapterBase {
    using PoolIdLibrary for PoolKey;

    constructor(IPoolManager _poolManager) MultiHooksAdapterBase(_poolManager) {}

    /// @notice Implement registerHooks to make this class concrete
    /// @param key The PoolKey identifying the pool for which to register hooks
    /// @param hookAddresses The ordered list of hook contract addresses to attach
    function registerHooks(PoolKey calldata key, address[] calldata hookAddresses) external override {
        _registerHooks(key, hookAddresses);
    }

    /// @notice Expose the internal mapping for testing purposes
    /// @param poolId The pool ID to get hooks for
    /// @return List of hooks registered for the pool
    function getHooksByPool(PoolId poolId) external view returns (IHooks[] memory) {
        return _hooksByPool[poolId];
    }

    // Must implement this method to make the contract concrete
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
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
    }
}
