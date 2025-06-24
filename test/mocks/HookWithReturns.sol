// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {BeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta, BalanceDeltaLibrary} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";

/**
 * @title HookWithReturns
 * @notice A configurable hook implementation that returns custom BalanceDelta values
 * @dev Used for testing functions that return and aggregate BalanceDelta values
 */
contract HookWithReturns is IHooks {
    // Custom return values for testing
    BalanceDelta private _customBalanceDelta;

    // Events for tracking hook calls
    event AfterAddLiquidityCalled(address sender, bytes32 poolId, BalanceDelta delta, BalanceDelta fees);
    event AfterRemoveLiquidityCalled(address sender, bytes32 poolId, BalanceDelta delta, BalanceDelta fees);

    // Set a custom BalanceDelta to return from hooks
    function setReturnValue(BalanceDelta delta) external {
        _customBalanceDelta = delta;
    }

    // Get the current custom BalanceDelta
    function getReturnValue() external view returns (BalanceDelta) {
        return _customBalanceDelta;
    }

    // Implementation of hook functions that return BalanceDelta
    function afterAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata,
        BalanceDelta delta,
        BalanceDelta fees,
        bytes calldata
    ) external returns (bytes4, BalanceDelta) {
        emit AfterAddLiquidityCalled(sender, keccak256(abi.encode(key)), delta, fees);
        return (IHooks.afterAddLiquidity.selector, _customBalanceDelta);
    }

    function afterRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata,
        BalanceDelta delta,
        BalanceDelta fees,
        bytes calldata
    ) external returns (bytes4, BalanceDelta) {
        emit AfterRemoveLiquidityCalled(sender, keccak256(abi.encode(key)), delta, fees);
        return (IHooks.afterRemoveLiquidity.selector, _customBalanceDelta);
    }

    // Basic implementations of other required functions that don't need to return values for our tests
    function beforeInitialize(address, PoolKey calldata, uint160) external pure returns (bytes4) {
        return IHooks.beforeInitialize.selector;
    }

    function afterInitialize(address, PoolKey calldata, uint160, int24) external pure returns (bytes4) {
        return IHooks.afterInitialize.selector;
    }

    function beforeAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IHooks.beforeAddLiquidity.selector;
    }

    function beforeRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IHooks.beforeRemoveLiquidity.selector;
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        pure
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        return (IHooks.beforeSwap.selector, BeforeSwapDelta.wrap(0), 0);
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, BalanceDelta, bytes calldata)
        external
        pure
        returns (bytes4, int128)
    {
        return (IHooks.afterSwap.selector, 0);
    }

    function beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return IHooks.beforeDonate.selector;
    }

    function afterDonate(address, PoolKey calldata, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return IHooks.afterDonate.selector;
    }
}
