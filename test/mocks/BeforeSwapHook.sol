// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {
    BeforeSwapDelta, toBeforeSwapDelta, BeforeSwapDeltaLibrary
} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta, toBalanceDelta, BalanceDeltaLibrary, add} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {LPFeeLibrary} from "@uniswap/v4-core/src/libraries/LPFeeLibrary.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";

/**
 * @title BeforeSwapHook
 * @notice A configurable hook implementation that returns custom BeforeSwapDelta values and fee overrides
 * @dev Used for testing functions that return and aggregate BeforeSwapDelta values
 */
contract BeforeSwapHook is IHooks {
    BeforeSwapDelta private _customDelta;
    uint24 private _customFee;
    bool public wasCalled;
    bool private _hasDeltaFlag; // Whether this hook has the RETURNS_DELTA_FLAG

    constructor() {
        // Initialize with the flag indicating no override
        _customFee = LPFeeLibrary.OVERRIDE_FEE_FLAG;
        // Default to having delta flag
        _hasDeltaFlag = true;
    }

    function setReturnValues(BeforeSwapDelta delta, uint24 fee) external {
        _customDelta = delta;
        _customFee = fee;
    }

    function resetCalled() external {
        wasCalled = false;
    }

    function setHasDeltaFlag(bool hasDeltaFlag) external {
        _hasDeltaFlag = hasDeltaFlag;
    }

    // Dynamic beforeSwap implementation based on whether the hook has RETURNS_DELTA_FLAG
    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        wasCalled = true;

        if (_hasDeltaFlag) {
            // Standard return for hooks with RETURNS_DELTA_FLAG
            return (IHooks.beforeSwap.selector, _customDelta, _customFee);
        } else {
            // For hooks without RETURNS_DELTA_FLAG, special return logic is needed
            // The adapter expects either a bytes4 selector (if no fee override)
            // or a uint256 for fee override
            if (_customFee == LPFeeLibrary.OVERRIDE_FEE_FLAG) {
                // Just return selector with no fee override
                return (IHooks.beforeSwap.selector, BeforeSwapDelta.wrap(0), 0);
            } else {
                // For hooks without RETURNS_DELTA_FLAG that override fees,
                // we return the fee value as a uint256 raw value
                uint256 feeOverride = uint256(_customFee);
                assembly {
                    // Store the fee in memory at position 0
                    mstore(0, feeOverride)
                    // Return 32 bytes (size of uint256)
                    return(0, 32)
                }
            }
        }
    }

    // Empty implementations for other required methods
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
