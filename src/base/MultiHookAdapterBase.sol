// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Import necessary Uniswap v4 core types and interfaces
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {BalanceDelta, toBalanceDelta, BalanceDeltaLibrary, add} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {
    BeforeSwapDelta, toBeforeSwapDelta, BeforeSwapDeltaLibrary
} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {ModifyLiquidityParams, SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {IBaseHookExtension} from "../interfaces/IBaseHookExtension.sol";
import {IMultiHookAdapterBase} from "../interfaces/IMultiHookAdapterBase.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";

/// @title MultiHookAdapterBase
/// @notice Adapter contract that allows multiple hook contracts to be attached to a Uniswap V4 pool.
/// @dev It implements the IHooks interface and delegates each callback to a set of sub-hooks registered per pool, in order.
/// @dev Would be inherited by child contracts to place restrictions on hooks mutability

abstract contract MultiHookAdapterBase is BaseHook, IMultiHookAdapterBase {
    using Hooks for IHooks;

    /// @dev Mapping from PoolId to an ordered list of hook contracts that are invoked for that pool.
    mapping(PoolId => IHooks[]) internal _hooksByPool;

    /// @dev Temporary storage for beforeSwap returns of sub-hooks, keyed by PoolId.
    mapping(PoolId => BeforeSwapDelta[]) internal beforeSwapHookReturns;

    // Context struct to solve stack too deep issue
    struct BeforeSwapContext {
        address sender;
        PoolKey key;
        SwapParams params;
        bytes data;
        PoolId poolId;
    }

    // Context struct to solve stack too deep issue for afterSwap
    struct AfterSwapContext {
        address sender;
        PoolKey key;
        SwapParams params;
        BalanceDelta swapDelta;
        bytes data;
        PoolId poolId;
    }

    /// @dev Reentrancy lock state (1 = unlocked, 2 = locked).
    uint256 private locked = 1;

    modifier lock() {
        if (locked != 1) revert Reentrancy();
        locked = 2;
        _;
        locked = 1;
    }

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {}

    /// @notice Registers an array of sub-hooks to be used for a given pool.
    /// @param key The PoolKey identifying the pool for which to register hooks.
    /// @param hookAddresses The ordered list of hook contract addresses to attach.
    /// Each hook in the list will be invoked in sequence for each relevant callback.
    function registerHooks(PoolKey calldata key, address[] calldata hookAddresses) public virtual override {
        _registerHooks(key, hookAddresses);
    }

    /// @dev Internal implementation of registerHooks that can be called by inheriting contracts
    function _registerHooks(PoolKey calldata key, address[] calldata hookAddresses) internal {
        PoolId poolId = key.toId();
        // Clear any existing hooks for the pool
        delete _hooksByPool[poolId];
        // Set new hooks in the specified order
        uint256 count = hookAddresses.length;
        IHooks[] storage hookList = _hooksByPool[poolId];

        for (uint256 i = 0; i < count; i++) {
            IHooks hook = IHooks(hookAddresses[i]);
            if (hookAddresses[i] == address(0)) revert HookAddressZero();
            if (!hook.isValidHookAddress(key.fee)) revert InvalidHookAddress();
            hookList.push(hook);
        }

        // Emit event when hooks are registered
        emit HooksRegistered(poolId, hookAddresses);
    }

    /// @notice Returns the hook permissions for this adapter
    /// @return permissions The hook permissions
    function getHookPermissions() public pure virtual override returns (Hooks.Permissions memory permissions) {
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

    function _beforeInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96)
        internal
        override
        lock
        returns (bytes4)
    {
        PoolId poolId = key.toId();
        IHooks[] storage subHooks = _hooksByPool[poolId];
        // Invoke beforeInitialize on each sub-hook in order
        uint256 length = subHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            // Only call if the sub-hook is permissioned for beforeInitialize
            if (uint160(address(subHooks[i])) & Hooks.BEFORE_INITIALIZE_FLAG != 0) {
                // Call sub-hook; since beforeInitialize returns only a selector, we ignore returned data beyond selector check.
                (bool success, bytes memory result) = address(subHooks[i]).call(
                    abi.encodeWithSelector(IHooks.beforeInitialize.selector, sender, key, sqrtPriceX96)
                );
                require(success, "Sub-hook beforeInitialize failed");
                // Verify the returned selector for correctness
                require(
                    result.length >= 4 && bytes4(result) == IHooks.beforeInitialize.selector,
                    "Invalid beforeInitialize return"
                );
            }
        }
        // Return this function's own selector to PoolManager
        return IHooks.beforeInitialize.selector;
    }

    function _afterInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96, int24 tick)
        internal
        override
        lock
        returns (bytes4)
    {
        PoolId poolId = key.toId();
        IHooks[] storage subHooks = _hooksByPool[poolId];
        uint256 length = subHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            if (uint160(address(subHooks[i])) & Hooks.AFTER_INITIALIZE_FLAG != 0) {
                (bool success, bytes memory result) = address(subHooks[i]).call(
                    abi.encodeWithSelector(IHooks.afterInitialize.selector, sender, key, sqrtPriceX96, tick)
                );
                require(success, "Sub-hook afterInitialize failed");
                require(
                    result.length >= 4 && bytes4(result) == IHooks.afterInitialize.selector,
                    "Invalid afterInitialize return"
                );
            }
        }
        return IHooks.afterInitialize.selector;
    }

    function _beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        bytes calldata hookData
    ) internal override lock returns (bytes4) {
        return _beforeModifyPosition(sender, key, params, hookData);
    }

    function _beforeRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        bytes calldata hookData
    ) internal override lock returns (bytes4) {
        return _beforeModifyPosition(sender, key, params, hookData);
    }

    function _afterAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata hookData
    ) internal override lock returns (bytes4, BalanceDelta) {
        return _afterModifyPosition(sender, key, params, delta, feesAccrued, hookData);
    }

    function _afterRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata hookData
    ) internal override lock returns (bytes4, BalanceDelta) {
        return _afterModifyPosition(sender, key, params, delta, feesAccrued, hookData);
    }

    function _beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata data)
        internal
        override
        lock
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        PoolId poolId = key.toId();

        /// @dev mitigation against a stack too deep error
        BeforeSwapContext memory context =
            BeforeSwapContext({sender: sender, key: key, params: params, data: data, poolId: poolId});

        // Clear any previous hook returns for this pool
        delete beforeSwapHookReturns[poolId];

        // Get hook list
        IHooks[] storage subHooks = _hooksByPool[poolId];

        // Process hooks and aggregate results
        BeforeSwapDelta combinedDelta = BeforeSwapDeltaLibrary.ZERO_DELTA;
        uint24 lpFeeOverride = LPFeeLibrary.OVERRIDE_FEE_FLAG;

        uint256 length = subHooks.length;

        // Initialize the array with the correct length
        beforeSwapHookReturns[poolId] = new BeforeSwapDelta[](length);

        for (uint256 i = 0; i < length; ++i) {
            // Skip hooks without the BEFORE_SWAP_FLAG
            if (uint160(address(subHooks[i])) & Hooks.BEFORE_SWAP_FLAG == 0) continue;

            // Call the hook
            (bool success, bytes memory result) = address(subHooks[i]).call(
                abi.encodeWithSelector(
                    IHooks.beforeSwap.selector, context.sender, context.key, context.params, context.data
                )
            );
            require(success, "Sub-hook beforeSwap failed");

            // Process result based on hook permissions
            if (uint160(address(subHooks[i])) & Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG != 0) {
                // Process with delta returns
                (bytes4 sel, BeforeSwapDelta delta, uint24 fee) = abi.decode(result, (bytes4, BeforeSwapDelta, uint24));
                require(sel == IHooks.beforeSwap.selector, "Invalid beforeSwap return");

                // Save delta for later use
                beforeSwapHookReturns[poolId][i] = delta;

                // Add to combined delta
                combinedDelta = _addBeforeSwapDelta(combinedDelta, delta);

                // Handle fee override
                if (fee != LPFeeLibrary.OVERRIDE_FEE_FLAG) {
                    lpFeeOverride = fee;
                }
            } else {
                // Process without delta returns - just check for fee override
                bytes4 sel = result.length >= 4 ? bytes4(result) : bytes4(0);
                if (sel != IHooks.beforeSwap.selector) {
                    // Try to extract fee override
                    uint256 overrideVal = result.length == 32 ? abi.decode(result, (uint256)) : 0;
                    uint24 hookFee = uint24(overrideVal);

                    if (hookFee != LPFeeLibrary.OVERRIDE_FEE_FLAG) {
                        lpFeeOverride = hookFee;
                    }
                }
            }
        }

        return (IHooks.beforeSwap.selector, combinedDelta, lpFeeOverride);
    }

    function _afterSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        BalanceDelta swapDelta,
        bytes calldata data
    ) internal override lock returns (bytes4, int128) {
        /// @dev mitigation against a stack too deep error
        AfterSwapContext memory context = AfterSwapContext({
            sender: sender,
            key: key,
            params: params,
            swapDelta: swapDelta,
            data: data,
            poolId: key.toId()
        });

        // Get hooks
        IHooks[] storage subHooks = _hooksByPool[context.poolId];

        // Clear any stored beforeSwapHookReturns to avoid stale data
        delete beforeSwapHookReturns[context.poolId];

        // Combined result value
        int128 combinedDelta = 0;

        // Process each hook
        uint256 length = subHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            // Skip hooks without AFTER_SWAP_FLAG
            if (uint160(address(subHooks[i])) & Hooks.AFTER_SWAP_FLAG == 0) continue;

            // Get hook address and flags for clarity
            address hookAddr = address(subHooks[i]);
            bool hasReturnsDeltaFlag = uint160(hookAddr) & Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG != 0;

            // Call the hook with standard selector
            (bool success, bytes memory result) = address(subHooks[i]).call(
                abi.encodeWithSelector(
                    IHooks.afterSwap.selector,
                    context.sender,
                    context.key,
                    context.params,
                    context.swapDelta,
                    context.data
                )
            );

            require(success, "Sub-hook afterSwap failed");

            if (hasReturnsDeltaFlag) {
                // Extract the response
                (bytes4 sel, int128 hookAfterDelta) = abi.decode(result, (bytes4, int128));
                require(sel == IHooks.afterSwap.selector, "Invalid afterSwap return");

                // Add to the unspecified delta
                combinedDelta += hookAfterDelta;
            } else {
                require(result.length >= 4 && bytes4(result) == IHooks.afterSwap.selector, "Invalid afterSwap return");
            }
        }

        // Return the unspecified delta
        return (IHooks.afterSwap.selector, combinedDelta);
    }

    function _beforeDonate(address sender, PoolKey calldata key, uint256 amount0, uint256 amount1, bytes calldata data)
        internal
        override
        onlyPoolManager
        lock
        returns (bytes4)
    {
        PoolId poolId = key.toId();
        IHooks[] storage subHooks = _hooksByPool[poolId];
        uint256 length = subHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            if (uint160(address(subHooks[i])) & Hooks.BEFORE_DONATE_FLAG != 0) {
                (bool success, bytes memory result) = address(subHooks[i]).call(
                    abi.encodeWithSelector(IHooks.beforeDonate.selector, sender, key, amount0, amount1, data)
                );
                require(success, "Sub-hook beforeDonate failed");
                require(
                    result.length >= 4 && bytes4(result) == IHooks.beforeDonate.selector, "Invalid beforeDonate return"
                );
            }
        }
        return IHooks.beforeDonate.selector;
    }

    function _afterDonate(address sender, PoolKey calldata key, uint256 amount0, uint256 amount1, bytes calldata data)
        internal
        override
        lock
        returns (bytes4)
    {
        PoolId poolId = key.toId();
        IHooks[] storage subHooks = _hooksByPool[poolId];
        uint256 length = subHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            if (uint160(address(subHooks[i])) & Hooks.AFTER_DONATE_FLAG != 0) {
                (bool success, bytes memory result) = address(subHooks[i]).call(
                    abi.encodeWithSelector(IHooks.afterDonate.selector, sender, key, amount0, amount1, data)
                );
                require(success, "Sub-hook afterDonate failed");
                require(
                    result.length >= 4 && bytes4(result) == IHooks.afterDonate.selector, "Invalid afterDonate return"
                );
            }
        }
        return IHooks.afterDonate.selector;
    }

    function _addBeforeSwapDelta(BeforeSwapDelta a, BeforeSwapDelta b) internal pure returns (BeforeSwapDelta) {
        BalanceDelta res = add(
            toBalanceDelta(BeforeSwapDeltaLibrary.getSpecifiedDelta(a), BeforeSwapDeltaLibrary.getUnspecifiedDelta(a)),
            toBalanceDelta(BeforeSwapDeltaLibrary.getSpecifiedDelta(b), BeforeSwapDeltaLibrary.getUnspecifiedDelta(b))
        );
        return toBeforeSwapDelta(BalanceDeltaLibrary.amount0(res), BalanceDeltaLibrary.amount1(res));
    }

    function _beforeModifyPosition(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        bytes calldata data
    ) internal onlyPoolManager returns (bytes4) {
        PoolId poolId = key.toId();
        IHooks[] storage subHooks = _hooksByPool[poolId];
        bool addingLiquidity = params.liquidityDelta > 0;

        uint256 length = subHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            uint160 hookPerms = uint160(address(subHooks[i]));
            if (addingLiquidity) {
                // If adding liquidity, call sub-hook if it has beforeAddLiquidity permission
                if (hookPerms & Hooks.BEFORE_ADD_LIQUIDITY_FLAG != 0) {
                    (bool success, bytes memory result) = address(subHooks[i]).call(
                        abi.encodeWithSelector(IHooks.beforeAddLiquidity.selector, sender, key, params, data)
                    );
                    require(success, "Sub-hook beforeAddLiquidity failed");
                    require(
                        result.length >= 4 && bytes4(result) == IHooks.beforeAddLiquidity.selector,
                        "Invalid beforeAddLiquidity return"
                    );
                }
            } else {
                // If removing liquidity, call sub-hook if it has beforeRemoveLiquidity permission
                if (hookPerms & Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG != 0) {
                    (bool success, bytes memory result) = address(subHooks[i]).call(
                        abi.encodeWithSelector(IHooks.beforeRemoveLiquidity.selector, sender, key, params, data)
                    );
                    require(success, "Sub-hook beforeRemoveLiquidity failed");
                    require(
                        result.length >= 4 && bytes4(result) == IHooks.beforeRemoveLiquidity.selector,
                        "Invalid beforeRemoveLiquidity return"
                    );
                }
            }
        }

        // Return the appropriate selector based on the operation type
        return addingLiquidity ? IHooks.beforeAddLiquidity.selector : IHooks.beforeRemoveLiquidity.selector;
    }

    function _afterModifyPosition(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata data
    ) internal returns (bytes4, BalanceDelta) {
        PoolId poolId = key.toId();
        IHooks[] storage subHooks = _hooksByPool[poolId];
        bool addedLiquidity = params.liquidityDelta > 0;
        // Initialize combined balance delta to zero
        BalanceDelta combinedDelta = BalanceDeltaLibrary.ZERO_DELTA;

        if (addedLiquidity) {
            combinedDelta = _processAfterAddLiquidity(subHooks, sender, key, params, delta, feesAccrued, data);
            return (IHooks.afterAddLiquidity.selector, combinedDelta);
        } else {
            combinedDelta = _processAfterRemoveLiquidity(subHooks, sender, key, params, delta, feesAccrued, data);
            return (IHooks.afterRemoveLiquidity.selector, combinedDelta);
        }
    }

    // Helper function to process afterAddLiquidity callbacks
    function _processAfterAddLiquidity(
        IHooks[] storage subHooks,
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata data
    ) private returns (BalanceDelta) {
        BalanceDelta combinedDelta = BalanceDeltaLibrary.ZERO_DELTA;
        uint256 length = subHooks.length;

        for (uint256 i = 0; i < length; i++) {
            uint160 hookPerms = uint160(address(subHooks[i]));

            if (hookPerms & Hooks.AFTER_ADD_LIQUIDITY_FLAG != 0) {
                // If sub-hook has afterAddLiquidityReturnDelta, it returns a BalanceDelta
                if (hookPerms & Hooks.AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG != 0) {
                    (bool success, bytes memory result) = address(subHooks[i]).call(
                        abi.encodeWithSelector(
                            IHooks.afterAddLiquidity.selector, sender, key, params, delta, feesAccrued, data
                        )
                    );
                    require(success, "Sub-hook afterAddLiquidity failed");
                    (bytes4 sel, BalanceDelta hookDelta) = abi.decode(result, (bytes4, BalanceDelta));
                    require(sel == IHooks.afterAddLiquidity.selector, "Invalid afterAddLiquidity return");
                    combinedDelta = add(combinedDelta, hookDelta);
                } else {
                    (bool success, bytes memory result) = address(subHooks[i]).call(
                        abi.encodeWithSelector(
                            IHooks.afterAddLiquidity.selector, sender, key, params, delta, feesAccrued, data
                        )
                    );
                    require(success, "Sub-hook afterAddLiquidity failed");
                    require(
                        result.length >= 4 && bytes4(result) == IHooks.afterAddLiquidity.selector,
                        "Invalid afterAddLiquidity return"
                    );
                }
            }
        }

        return combinedDelta;
    }

    // Helper function to process afterRemoveLiquidity callbacks
    function _processAfterRemoveLiquidity(
        IHooks[] storage subHooks,
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata data
    ) private returns (BalanceDelta) {
        BalanceDelta combinedDelta = BalanceDeltaLibrary.ZERO_DELTA;
        uint256 length = subHooks.length;

        for (uint256 i = 0; i < length; i++) {
            uint160 hookPerms = uint160(address(subHooks[i]));

            if (hookPerms & Hooks.AFTER_REMOVE_LIQUIDITY_FLAG != 0) {
                if (hookPerms & Hooks.AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG != 0) {
                    (bool success, bytes memory result) = address(subHooks[i]).call(
                        abi.encodeWithSelector(
                            IHooks.afterRemoveLiquidity.selector, sender, key, params, delta, feesAccrued, data
                        )
                    );
                    require(success, "Sub-hook afterRemoveLiquidity failed");
                    (bytes4 sel, BalanceDelta hookDelta) = abi.decode(result, (bytes4, BalanceDelta));
                    require(sel == IHooks.afterRemoveLiquidity.selector, "Invalid afterRemoveLiquidity return");
                    combinedDelta = add(combinedDelta, hookDelta);
                } else {
                    (bool success, bytes memory result) = address(subHooks[i]).call(
                        abi.encodeWithSelector(
                            IHooks.afterRemoveLiquidity.selector, sender, key, params, delta, feesAccrued, data
                        )
                    );
                    require(success, "Sub-hook afterRemoveLiquidity failed");
                    require(
                        result.length >= 4 && bytes4(result) == IHooks.afterRemoveLiquidity.selector,
                        "Invalid afterRemoveLiquidity return"
                    );
                }
            }
        }

        return combinedDelta;
    }
}
