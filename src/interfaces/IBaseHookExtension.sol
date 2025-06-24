// SPDX-License-identifiery: MIT
pragma solidity ^0.8.0;

import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";

interface IBaseHookExtension {
    function getHookPermissions() external pure returns (Hooks.Permissions memory);
}
