// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBase, PoolKey, IHooks, IPoolManager} from "./base/MultiHookAdapterBase.sol";

/// @title MultiHookAdapter
/// @author Poolshark Labs
/// @notice Extends MultiHookAdapterBase to provide a hook adapter that allows hook registration only once per pool.
/// @dev This contract ensures that once hooks are set for a specific pool, they cannot be changed or re-registered.
/// It relies on MultiHookAdapterBase for the core hook callback delegation logic.
contract MultiHookAdapter is MultiHookAdapterBase {

    /// @notice Tracks whether hooks have been registered for a specific pool.
    /// @dev The key is a hash of the PoolKey, and the value is true if hooks have been registered, false otherwise.
    mapping(bytes => bool) public isRegistered;
    /// @notice Constructs the MultiHookAdapter.
    /// @param _poolManager The address of the Uniswap V4 PoolManager.
    constructor(IPoolManager _poolManager) MultiHookAdapterBase(_poolManager) {}

    /// @notice Registers an array of sub-hooks for a given pool, if not already registered.
    /// @dev This function overrides the behavior in MultiHookAdapterBase to enforce that hooks can only be registered once per pool.
    /// It computes a hash of the PoolKey to track registration status. If already registered, the call will revert.
    /// Otherwise, it marks the pool as registered and calls the base contract's registerHooks logic.
    /// Emits a {HooksRegistered} event upon successful registration (event inherited from MultiHookAdapterBase).
    /// @param key The PoolKey identifying the pool for which to register hooks.
    /// @param hooks The ordered list of hook contract addresses to attach.
    function registerHooks(PoolKey calldata key, address[] calldata hooks) public override {
        bytes memory keyHash = _hashPoolKey(key);
        require(!isRegistered[keyHash], "Hooks already registered");
        isRegistered[keyHash] = true;
        super.registerHooks(key, hooks);
    }

    /**
     * @notice Hashes a pool key into a bytes value
     * @param key The pool key to hash
     * @return The bytes representation of the hashed pool key
     */
    function _hashPoolKey(PoolKey calldata key) internal pure returns (bytes memory) {
        return abi.encode(key.currency0, key.currency1, key.fee, key.tickSpacing, key.hooks);
    }
}