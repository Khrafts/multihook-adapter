// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MultiHookAdapterBase} from "../../src/base/MultiHookAdapterBase.sol";
import {TestMultiHookAdapter} from "../mocks/TestMultiHookAdapter.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {HookWithEvents} from "../mocks/HookWithEvents.sol";
import {Vm} from "forge-std/Vm.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import "forge-std/console.sol";

contract MultiHookAdapterBaseTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;

    TestMultiHookAdapter public adapter;

    // Named hooks for different hook functions
    HookWithEvents public beforeInitializeHook;
    HookWithEvents public afterInitializeHook;
    HookWithEvents public beforeSwapHook;
    HookWithEvents public afterSwapHook;
    HookWithEvents public beforeDonateHook;
    HookWithEvents public afterDonateHook;
    HookWithEvents public beforeAddLiquidityHook;
    HookWithEvents public afterAddLiquidityHook;
    HookWithEvents public beforeRemoveLiquidityHook;
    HookWithEvents public afterRemoveLiquidityHook;

    address public nonHookContract;
    address public zeroAddress = address(0);

    PoolKey public poolKey;
    PoolId public poolId;

    // Note: SQRT_PRICE_1_1 is already defined in Deployers

    event HooksRegistered(PoolId indexed poolId, address[] hooks);

    function setUp() public virtual {
        // Deploy a real PoolManager for testing
        deployFreshManagerAndRouters();

        // Define flags for all hooks
        uint160 adapterFlags = uint160(
            Hooks.AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG | Hooks.AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG
                | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG | Hooks.AFTER_DONATE_FLAG
                | Hooks.BEFORE_DONATE_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_SWAP_FLAG
                | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG | Hooks.AFTER_ADD_LIQUIDITY_FLAG
                | Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_INITIALIZE_FLAG
        );

        // Deploy adapter to a valid hook address using deployCodeTo
        address adapterAddress = address(uint160(adapterFlags));
        deployCodeTo("TestMultiHookAdapter.sol", abi.encode(manager, 3000, address(this), true), adapterAddress);
        adapter = TestMultiHookAdapter(adapterAddress);

        // Deploy each hook with its specific flag
        deployHookWithFlag("beforeInitializeHook", Hooks.BEFORE_INITIALIZE_FLAG);
        deployHookWithFlag("afterInitializeHook", Hooks.AFTER_INITIALIZE_FLAG);
        deployHookWithFlag("beforeSwapHook", Hooks.BEFORE_SWAP_FLAG);
        deployHookWithFlag("afterSwapHook", Hooks.AFTER_SWAP_FLAG);
        deployHookWithFlag("beforeDonateHook", Hooks.BEFORE_DONATE_FLAG);
        deployHookWithFlag("afterDonateHook", Hooks.AFTER_DONATE_FLAG);
        deployHookWithFlag("beforeAddLiquidityHook", Hooks.BEFORE_ADD_LIQUIDITY_FLAG);
        deployHookWithFlag("afterAddLiquidityHook", Hooks.AFTER_ADD_LIQUIDITY_FLAG);
        deployHookWithFlag("beforeRemoveLiquidityHook", Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG);
        deployHookWithFlag("afterRemoveLiquidityHook", Hooks.AFTER_REMOVE_LIQUIDITY_FLAG);

        // Create a non-hook contract for testing
        nonHookContract = address(new NonHookContract());

        // Setup pool information
        currency0 = Currency.wrap(address(0x1));
        currency1 = Currency.wrap(address(0x2));
        poolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(adapter))
        });
        poolId = poolKey.toId();
    }

    // Helper function to deploy a hook with a specific flag
    function deployHookWithFlag(string memory hookName, uint160 flag) internal {
        address hookAddress = address(uint160(flag));
        deployCodeTo("HookWithEvents.sol", "", hookAddress);

        if (keccak256(bytes(hookName)) == keccak256(bytes("beforeInitializeHook"))) {
            beforeInitializeHook = HookWithEvents(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("afterInitializeHook"))) {
            afterInitializeHook = HookWithEvents(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("beforeSwapHook"))) {
            beforeSwapHook = HookWithEvents(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("afterSwapHook"))) {
            afterSwapHook = HookWithEvents(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("beforeDonateHook"))) {
            beforeDonateHook = HookWithEvents(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("afterDonateHook"))) {
            afterDonateHook = HookWithEvents(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("beforeAddLiquidityHook"))) {
            beforeAddLiquidityHook = HookWithEvents(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("afterAddLiquidityHook"))) {
            afterAddLiquidityHook = HookWithEvents(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("beforeRemoveLiquidityHook"))) {
            beforeRemoveLiquidityHook = HookWithEvents(hookAddress);
        } else if (keccak256(bytes(hookName)) == keccak256(bytes("afterRemoveLiquidityHook"))) {
            afterRemoveLiquidityHook = HookWithEvents(hookAddress);
        }
    }

    // Helper function to create a standard test pool key
    function createTestPoolKey() internal view returns (PoolKey memory) {
        return PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(address(1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(adapter))
        });
    }

    // Helper function to impersonate the pool manager
    function impersonatePoolManager() internal returns (address) {
        address poolManagerAddress = address(adapter.poolManager());
        vm.prank(poolManagerAddress);
        return poolManagerAddress;
    }
}

// Non-hook contract for testing
contract NonHookContract {
    // This contract doesn't implement the IBaseHookExtension interface
    function foo() public pure returns (uint256) {
        return 42;
    }
}
