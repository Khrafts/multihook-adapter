// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";

/**
 * @title DonateHook
 * @notice Mock Hook implementation for testing the donate callbacks
 */
contract DonateHook is IHooks {
    // Track whether the hook was called
    bool public wasCalled;
    bool public beforeDonateCalled;
    bool public afterDonateCalled;

    // Track the last received values
    address public lastSender;
    uint256 public lastAmount0;
    uint256 public lastAmount1;
    bytes public lastData;

    // Reset the call tracking
    function resetCalled() external {
        wasCalled = false;
        beforeDonateCalled = false;
        afterDonateCalled = false;
        lastSender = address(0);
        lastAmount0 = 0;
        lastAmount1 = 0;
        lastData = "";
    }

    // IHooks interface implementations

    function beforeInitialize(address, PoolKey calldata, uint160) external pure override returns (bytes4) {
        return IHooks.beforeInitialize.selector;
    }

    function afterInitialize(address, PoolKey calldata, uint160, int24) external pure override returns (bytes4) {
        return IHooks.afterInitialize.selector;
    }

    function beforeAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IHooks.beforeAddLiquidity.selector;
    }

    function afterAddLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure override returns (bytes4, BalanceDelta) {
        return (IHooks.afterAddLiquidity.selector, BalanceDelta.wrap(0));
    }

    function beforeRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IHooks.beforeRemoveLiquidity.selector;
    }

    function afterRemoveLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure override returns (bytes4, BalanceDelta) {
        return (IHooks.afterRemoveLiquidity.selector, BalanceDelta.wrap(0));
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        return (IHooks.beforeSwap.selector, BeforeSwapDelta.wrap(0), 0);
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, BalanceDelta, bytes calldata)
        external
        pure
        override
        returns (bytes4, int128)
    {
        return (IHooks.afterSwap.selector, 0);
    }

    function beforeDonate(address sender, PoolKey calldata, uint256 amount0, uint256 amount1, bytes calldata data)
        external
        override
        returns (bytes4)
    {
        wasCalled = true;
        beforeDonateCalled = true;
        lastSender = sender;
        lastAmount0 = amount0;
        lastAmount1 = amount1;
        lastData = data;
        return IHooks.beforeDonate.selector;
    }

    function afterDonate(address sender, PoolKey calldata, uint256 amount0, uint256 amount1, bytes calldata data)
        external
        override
        returns (bytes4)
    {
        wasCalled = true;
        afterDonateCalled = true;
        lastSender = sender;
        lastAmount0 = amount0;
        lastAmount1 = amount1;
        lastData = data;
        return IHooks.afterDonate.selector;
    }
}
