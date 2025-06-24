// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWeightedHook} from "../../src/interfaces/IWeightedHook.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";

/// @title WeightedHookMock//
/// @notice Mock implementation of IWeightedHook for testing weighted fee calculations
contract WeightedHookMock is IWeightedHook {
    
    // Configurable return values
    uint24 public mockFee;
    uint256 public mockWeight;
    BeforeSwapDelta public mockDelta;
    bool public mockHasFeeOverride;
    bool public mockSupportsWeighted;
    
    // Call tracking
    bool public beforeSwapWeightedCalled;
    bool public beforeSwapCalled;
    
    constructor() {
        mockFee = 3000; // 0.3% default
        mockWeight = 1;
        mockHasFeeOverride = true;
        mockSupportsWeighted = true;
    }
    
    /// @notice Set the return values for this mock hook
    function setMockValues(
        uint24 fee,
        uint256 weight,
        BeforeSwapDelta delta,
        bool hasFeeOverride,
        bool supportsWeighted
    ) external {
        mockFee = fee;
        mockWeight = weight;
        mockDelta = delta;
        mockHasFeeOverride = hasFeeOverride;
        mockSupportsWeighted = supportsWeighted;
    }
    
    /// @notice Reset call tracking
    function resetCallTracking() external {
        beforeSwapWeightedCalled = false;
        beforeSwapCalled = false;
    }
    
    /// @inheritdoc IWeightedHook
    function beforeSwapWeighted(
        address,
        PoolKey calldata,
        SwapParams calldata,
        bytes calldata
    ) external override returns (WeightedHookResult memory result) {
        beforeSwapWeightedCalled = true;
        
        result = WeightedHookResult({
            selector: IHooks.beforeSwap.selector,
            delta: mockDelta,
            fee: mockFee,
            weight: mockWeight,
            hasFeeOverride: mockHasFeeOverride
        });
    }
    
    /// @inheritdoc IWeightedHook
    function getHookWeight(
        PoolKey calldata,
        SwapParams calldata
    ) external view override returns (uint256 weight) {
        return mockWeight;
    }
    
    /// @inheritdoc IWeightedHook
    function supportsWeightedFees() external view override returns (bool supported) {
        return mockSupportsWeighted;
    }
    
    // Standard IHooks implementation
    function beforeSwap(
        address,
        PoolKey calldata,
        SwapParams calldata,
        bytes calldata
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        beforeSwapCalled = true;
        return (IHooks.beforeSwap.selector, mockDelta, mockFee);
    }
    
    // Empty implementations for other IHooks methods
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

    function afterAddLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure returns (bytes4, BalanceDelta) {
        return (IHooks.afterAddLiquidity.selector, BalanceDelta.wrap(0));
    }

    function beforeRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
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
    ) external pure returns (bytes4, BalanceDelta) {
        return (IHooks.afterRemoveLiquidity.selector, BalanceDelta.wrap(0));
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
