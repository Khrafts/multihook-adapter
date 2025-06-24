// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseHookExtension} from "../../src/utils/BaseHookExtension.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IMultiHookAdapterBase} from "../../src/interfaces/IMultiHookAdapterBase.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";

contract MockSubHook is BaseHookExtension {
    // Events to track when hook functions are called
    event BeforeInitializeCalled(address sender, bytes32 poolId, uint160 sqrtPriceX96);
    event AfterInitializeCalled(address sender, bytes32 poolId, uint160 sqrtPriceX96, int24 tick);
    event BeforeSwapCalled(address sender, bytes32 poolId);
    event AfterSwapCalled(address sender, bytes32 poolId);
    event BeforeDonateCalled(address sender, bytes32 poolId);
    event AfterDonateCalled(address sender, bytes32 poolId);
    event BeforeAddLiquidityCalled(address sender, bytes32 poolId);
    event AfterAddLiquidityCalled(address sender, bytes32 poolId);
    event BeforeRemoveLiquidityCalled(address sender, bytes32 poolId);
    event AfterRemoveLiquidityCalled(address sender, bytes32 poolId);

    // Constructor can accept either IHooks or address type to maintain compatibility
    constructor(address _multiHookAdapter) BaseHookExtension(IHooks(_multiHookAdapter)) {}

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
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // Override validateHookAddress to allow testing
    function validateHookAddress(BaseHookExtension _this) internal pure override {
        // Skip validation for testing
    }

    // Override the internal hook methods to emit events

    function _beforeInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96)
        internal
        override
        returns (bytes4)
    {
        // Emit event to track that this function was called
        emit BeforeInitializeCalled(sender, keccak256(abi.encode(key)), sqrtPriceX96);

        // This return value will be used if not mocked
        return IHooks.beforeInitialize.selector;
    }

    function _afterInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96, int24 tick)
        internal
        override
        returns (bytes4)
    {
        // Emit event to track that this function was called
        emit AfterInitializeCalled(sender, keccak256(abi.encode(key)), sqrtPriceX96, tick);

        // This return value will be used if not mocked
        return IHooks.afterInitialize.selector;
    }

    // Additional override methods can be added for other hook functions
}
