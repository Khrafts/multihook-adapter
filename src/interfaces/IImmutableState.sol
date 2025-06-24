// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IHooks} from "v4-core/interfaces/IHooks.sol";

/// @title IImmutableState
/// @notice An interface for the ImmutableState contract
/// @notice Copied and extended from the Uniswap v4 IImmutableState interface
/// @notice Original implementation: https://github.com/Uniswap/v4-periphery/blob/444c526b77d804590f0d7bc5a481af5a3277c952/src/interfaces/IImmutableState.sol
interface IImmutableState {
    /// @notice The MultiHookAdapter contract
    function multiHookAdapter() external view returns (IHooks);
}
