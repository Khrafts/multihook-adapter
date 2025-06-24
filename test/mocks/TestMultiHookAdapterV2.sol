// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MultiHookAdapterBase} from "../../src/base/MultiHookAdapterBase.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";

/// @title TestMultiHookAdapter
/// @notice Test implementation of MultiHookAdapterBase for testing purposes
contract TestMultiHookAdapter is MultiHookAdapterBase {
    constructor(
        IPoolManager _poolManager,
        uint24 _defaultFee,
        address _governance,
        bool _governanceEnabled
    ) MultiHookAdapterBase(_poolManager, _defaultFee, _governance, _governanceEnabled) {}
}