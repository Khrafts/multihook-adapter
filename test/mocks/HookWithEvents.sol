// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {BeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";

/**
 * @title HookWithEvents
 * @notice A simple hook implementation that emits events when its functions are called
 * @dev Used for testing to verify which hooks are being called by the adapter
 */
contract HookWithEvents is IHooks {
    // Events emitted when hook functions are called
    event BeforeInitializeCalled(address sender, bytes32 poolId, uint160 sqrtPriceX96);
    event AfterInitializeCalled(address sender, bytes32 poolId, uint160 sqrtPriceX96, int24 tick);
    event BeforeSwapCalled(address sender, bytes32 poolId);
    event AfterSwapCalled(address sender, bytes32 poolId);
    event BeforeDonateCalled(address sender, bytes32 poolId);
    event AfterDonateCalled(address sender, bytes32 poolId);
    event BeforeAddLiquidityCalled(address sender, bytes32 poolId, bytes hookData);
    event AfterAddLiquidityCalled(address sender, bytes32 poolId);
    event BeforeRemoveLiquidityCalled(address sender, bytes32 poolId, bytes hookData);
    event AfterRemoveLiquidityCalled(address sender, bytes32 poolId);

    // Hook implementation functions
    function beforeInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96) external returns (bytes4) {
        emit BeforeInitializeCalled(sender, keccak256(abi.encode(key)), sqrtPriceX96);
        return IHooks.beforeInitialize.selector;
    }

    function afterInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96, int24 tick)
        external
        returns (bytes4)
    {
        emit AfterInitializeCalled(sender, keccak256(abi.encode(key)), sqrtPriceX96, tick);
        return IHooks.afterInitialize.selector;
    }

    function beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata,
        bytes calldata hookData
    ) external returns (bytes4) {
        emit BeforeAddLiquidityCalled(sender, keccak256(abi.encode(key)), hookData);
        return IHooks.beforeAddLiquidity.selector;
    }

    function afterAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external returns (bytes4, BalanceDelta) {
        emit AfterAddLiquidityCalled(sender, keccak256(abi.encode(key)));
        return (IHooks.afterAddLiquidity.selector, BalanceDelta.wrap(0));
    }

    function beforeRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata,
        bytes calldata hookData
    ) external returns (bytes4) {
        emit BeforeRemoveLiquidityCalled(sender, keccak256(abi.encode(key)), hookData);
        return IHooks.beforeRemoveLiquidity.selector;
    }

    function afterRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external returns (bytes4, BalanceDelta) {
        emit AfterRemoveLiquidityCalled(sender, keccak256(abi.encode(key)));
        return (IHooks.afterRemoveLiquidity.selector, BalanceDelta.wrap(0));
    }

    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata, bytes calldata)
        external
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        emit BeforeSwapCalled(sender, keccak256(abi.encode(key)));
        return (IHooks.beforeSwap.selector, BeforeSwapDelta.wrap(0), 0);
    }

    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata, BalanceDelta, bytes calldata)
        external
        returns (bytes4, int128)
    {
        emit AfterSwapCalled(sender, keccak256(abi.encode(key)));
        return (IHooks.afterSwap.selector, 0);
    }

    function beforeDonate(address sender, PoolKey calldata key, uint256, uint256, bytes calldata)
        external
        returns (bytes4)
    {
        emit BeforeDonateCalled(sender, keccak256(abi.encode(key)));
        return IHooks.beforeDonate.selector;
    }

    function afterDonate(address sender, PoolKey calldata key, uint256, uint256, bytes calldata)
        external
        returns (bytes4)
    {
        emit AfterDonateCalled(sender, keccak256(abi.encode(key)));
        return IHooks.afterDonate.selector;
    }
}
