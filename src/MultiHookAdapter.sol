// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBase, PoolKey, IHooks, IPoolManager} from "./base/MultiHookAdapterBase.sol";

contract MultiHookAdapter is MultiHookAdapterBase {

    mapping(bytes => bool) public isRegistered;
    constructor(IPoolManager _poolManager) MultiHookAdapterBase(_poolManager) {}

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