// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseHookExtension} from "../../src/utils/BaseHookExtension.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {BalanceDelta, toBalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, toBeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";

/// @title HookMock
/// @notice A hook implementation for testing with tracking capabilities
contract HookMock is BaseHookExtension {
    using PoolIdLibrary for PoolKey;

    string public name;

    // Counter to track order of hook calls (static across all instances)
    uint256 private static_callOrder;

    // Mappings to track call counts and parameters for each function
    mapping(string => uint256) private _callCounts;
    mapping(string => uint256) private _lastCallOrders;
    mapping(string => address) private _lastCallers;
    mapping(string => PoolId) private _lastPoolIds;
    mapping(string => bytes) private _lastDatas;
    mapping(string => int256) private _lastDelta0s;
    mapping(string => int256) private _lastDelta1s;

    constructor(IHooks adapter, string memory _name) BaseHookExtension(adapter) {
        name = _name;
    }

    // Access tracked information
    function callCount(string memory funcName) external view returns (uint256) {
        return _callCounts[funcName];
    }

    function lastCallOrder(string memory funcName) external view returns (uint256) {
        return _lastCallOrders[funcName];
    }

    function lastCaller(string memory funcName) external view returns (address) {
        return _lastCallers[funcName];
    }

    function lastPoolId(string memory funcName) external view returns (PoolId) {
        return _lastPoolIds[funcName];
    }

    function lastData(string memory funcName) external view returns (bytes memory) {
        return _lastDatas[funcName];
    }

    function lastDelta0(string memory funcName) external view returns (int256) {
        return _lastDelta0s[funcName];
    }

    function lastDelta1(string memory funcName) external view returns (int256) {
        return _lastDelta1s[funcName];
    }

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

    // Override validateHookAddress to allow testing
    function validateHookAddress(BaseHookExtension _this) internal pure override {
        // Skip validation for testing
    }

    // Track calls to beforeSwap
    function _beforeSwap(address sender, PoolKey calldata key, SwapParams calldata, bytes calldata hookData)
        internal
        virtual
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        string memory funcName = "beforeSwap";

        // Increment call order and record this call
        _callCounts[funcName] += 1;
        _lastCallOrders[funcName] = ++static_callOrder;
        _lastCallers[funcName] = sender;
        _lastPoolIds[funcName] = key.toId();
        _lastDatas[funcName] = hookData;

        return (IHooks.beforeSwap.selector, toBeforeSwapDelta(0, 0), 0);
    }

    // Track calls to afterSwap
    function _afterSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata,
        BalanceDelta delta,
        bytes calldata hookData
    ) internal virtual override returns (bytes4, int128) {
        string memory funcName = "afterSwap";

        // Increment call order and record this call
        _callCounts[funcName] += 1;
        _lastCallOrders[funcName] = ++static_callOrder;
        _lastCallers[funcName] = sender;
        _lastPoolIds[funcName] = key.toId();
        _lastDatas[funcName] = hookData;
        _lastDelta0s[funcName] = delta.amount0();
        _lastDelta1s[funcName] = delta.amount1();

        return (IHooks.afterSwap.selector, 0);
    }

    // Track calls to beforeAddLiquidity
    function _beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata,
        bytes calldata hookData
    ) internal virtual override returns (bytes4) {
        string memory funcName = "beforeAddLiquidity";

        // Increment call order and record this call
        _callCounts[funcName] += 1;
        _lastCallOrders[funcName] = ++static_callOrder;
        _lastCallers[funcName] = sender;
        _lastPoolIds[funcName] = key.toId();
        _lastDatas[funcName] = hookData;

        return IHooks.beforeAddLiquidity.selector;
    }

    // Track calls to afterAddLiquidity
    function _afterAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata,
        BalanceDelta delta,
        BalanceDelta,
        bytes calldata hookData
    ) internal virtual override returns (bytes4, BalanceDelta) {
        string memory funcName = "afterAddLiquidity";

        // Increment call order and record this call
        _callCounts[funcName] += 1;
        _lastCallOrders[funcName] = ++static_callOrder;
        _lastCallers[funcName] = sender;
        _lastPoolIds[funcName] = key.toId();
        _lastDatas[funcName] = hookData;
        _lastDelta0s[funcName] = delta.amount0();
        _lastDelta1s[funcName] = delta.amount1();

        return (IHooks.afterAddLiquidity.selector, toBalanceDelta(0, 0));
    }
}
