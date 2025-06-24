// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {BaseHookExtension} from "../src/utils/BaseHookExtension.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {ModifyLiquidityParams, SwapParams} from "v4-core/types/PoolOperation.sol";
import {BalanceDelta, toBalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {BeforeSwapDelta, toBeforeSwapDelta} from "v4-core/types/BeforeSwapDelta.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {MockMultiHookAdapter} from "./mocks/MockMultiHookAdapter.sol";
import {MockSubHook} from "./mocks/MockSubHook.sol";

contract BaseHookExtensionTest is Test {
    MockMultiHookAdapter public adapter;
    MockSubHook public hook;
    address public unauthorizedCaller;
    Currency public currency0;
    Currency public currency1;

    function setUp() public {
        adapter = new MockMultiHookAdapter();
        hook = new MockSubHook(address(adapter));
        unauthorizedCaller = address(0x123);
        currency0 = Currency.wrap(address(0x1));
        currency1 = Currency.wrap(address(0x2));
    }

    function test_ConstructorSetsAdapter() public {
        assertEq(address(hook.multiHookAdapter()), address(adapter));
    }

    function test_OnlyMultiHookAdapterCanCallBeforeInitialize() public {
        vm.prank(unauthorizedCaller);
        vm.expectRevert("Caller is not the MultiHookAdapter");
        hook.beforeInitialize(
            address(0),
            PoolKey({currency0: currency0, currency1: currency1, fee: 0, tickSpacing: 0, hooks: IHooks(address(0))}),
            0
        );
    }

    function test_OnlyMultiHookAdapterCanCallAfterInitialize() public {
        vm.prank(unauthorizedCaller);
        vm.expectRevert("Caller is not the MultiHookAdapter");
        hook.afterInitialize(
            address(0),
            PoolKey({currency0: currency0, currency1: currency1, fee: 0, tickSpacing: 0, hooks: IHooks(address(0))}),
            0,
            0
        );
    }

    function test_OnlyMultiHookAdapterCanCallBeforeSwap() public {
        vm.prank(unauthorizedCaller);
        vm.expectRevert("Caller is not the MultiHookAdapter");
        hook.beforeSwap(
            address(0),
            PoolKey({currency0: currency0, currency1: currency1, fee: 0, tickSpacing: 0, hooks: IHooks(address(0))}),
            SwapParams({zeroForOne: true, amountSpecified: 0, sqrtPriceLimitX96: 0}),
            ""
        );
    }

    function test_OnlyMultiHookAdapterCanCallAfterSwap() public {
        vm.prank(unauthorizedCaller);
        vm.expectRevert("Caller is not the MultiHookAdapter");
        hook.afterSwap(
            address(0),
            PoolKey({currency0: currency0, currency1: currency1, fee: 0, tickSpacing: 0, hooks: IHooks(address(0))}),
            SwapParams({zeroForOne: true, amountSpecified: 0, sqrtPriceLimitX96: 0}),
            toBalanceDelta(0, 0),
            ""
        );
    }

    function test_OnlyMultiHookAdapterCanCallBeforeAddLiquidity() public {
        vm.prank(unauthorizedCaller);
        vm.expectRevert("Caller is not the MultiHookAdapter");
        hook.beforeAddLiquidity(
            address(0),
            PoolKey({currency0: currency0, currency1: currency1, fee: 0, tickSpacing: 0, hooks: IHooks(address(0))}),
            ModifyLiquidityParams({tickLower: 0, tickUpper: 0, liquidityDelta: 0, salt: bytes32(0)}),
            ""
        );
    }

    function test_OnlyMultiHookAdapterCanCallAfterAddLiquidity() public {
        vm.prank(unauthorizedCaller);
        vm.expectRevert("Caller is not the MultiHookAdapter");
        hook.afterAddLiquidity(
            address(0),
            PoolKey({currency0: currency0, currency1: currency1, fee: 0, tickSpacing: 0, hooks: IHooks(address(0))}),
            ModifyLiquidityParams({tickLower: 0, tickUpper: 0, liquidityDelta: 0, salt: bytes32(0)}),
            toBalanceDelta(0, 0),
            toBalanceDelta(0, 0),
            ""
        );
    }
}
