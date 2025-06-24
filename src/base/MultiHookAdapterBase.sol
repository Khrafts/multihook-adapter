// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Import necessary Uniswap v4 core types and interfaces//
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
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";

// Import our interfaces and strategies
import {IMultiHookAdapterBase} from "../interfaces/IMultiHookAdapterBase.sol";
import {IFeeCalculationStrategy} from "../interfaces/IFeeCalculationStrategy.sol";
import {IWeightedHook} from "../interfaces/IWeightedHook.sol";
import {FeeCalculationStrategy} from "../strategies/FeeCalculationStrategy.sol";

/// @title MultiHookAdapterBase
/// @notice Unified adapter contract with complete hook aggregation logic and advanced fee calculation strategies
/// @dev Supports weighted fee calculations, multiple strategies, flexible governance, and all hook lifecycle callbacks
/// @dev Consolidates functionality from MultiHookAdapterBase and MultiHookAdapterBaseV2 into a single unified contract
abstract contract MultiHookAdapterBase is BaseHook, IMultiHookAdapterBase {
    using Hooks for IHooks;

    /// @dev Mapping from PoolId to an ordered list of hook contracts
    mapping(PoolId => IHooks[]) internal _hooksByPool;

    /// @dev Temporary storage for beforeSwap returns of sub-hooks, keyed by PoolId
    mapping(PoolId => BeforeSwapDelta[]) internal beforeSwapHookReturns;
    
    /// @dev Fee configuration per pool (protected for access by derived contracts)
    mapping(PoolId => IFeeCalculationStrategy.FeeConfiguration) internal _poolFeeConfigs;
    
    /// @dev Fee calculation strategy implementation
    IFeeCalculationStrategy public immutable feeCalculationStrategy;
    
    /// @dev Default fee set at deployment (immutable fallback)
    uint24 public immutable defaultFee;
    
    /// @dev Governance fee (can be updated if governance is enabled)
    uint24 public governanceFee;
    bool public governanceFeeSet;
    
    /// @dev Governance address (if governance is enabled)
    address public governance;
    
    /// @dev Whether governance is enabled for this adapter
    bool public immutable governanceEnabled;

    // Context structs to solve stack too deep issues
    struct BeforeSwapContext {
        address sender;
        PoolKey key;
        SwapParams params;
        bytes data;
        PoolId poolId;
    }

    struct AfterSwapContext {
        address sender;
        PoolKey key;
        SwapParams params;
        BalanceDelta swapDelta;
        bytes data;
        PoolId poolId;
    }

    /// @dev Reentrancy lock state
    uint256 private locked = 1;

    modifier lock() {
        if (locked != 1) revert Reentrancy();
        locked = 2;
        _;
        locked = 1;
    }
    
    modifier onlyGovernance() {
        if (governanceEnabled && msg.sender != governance) revert UnauthorizedGovernance();
        _;
    }

    constructor(
        IPoolManager _poolManager,
        uint24 _defaultFee,
        address _governance,
        bool _governanceEnabled
    ) BaseHook(_poolManager) {
        if (_defaultFee > 1_000_000) revert InvalidFee(_defaultFee); // Max 100%
        
        defaultFee = _defaultFee;
        governance = _governance;
        governanceEnabled = _governanceEnabled;
        
        // Deploy fee calculation strategy
        feeCalculationStrategy = new FeeCalculationStrategy();
    }
    
    /// @notice Override hook address validation to disable automatic validation during deployment
    /// @dev The adapter address will be validated during factory deployment with CREATE2
    function validateHookAddress(BaseHook) internal pure override {
        // Skip validation - factory handles this with CREATE2 salt selection
        return;
    }

    /// @inheritdoc IMultiHookAdapterBase
    function registerHooks(PoolKey calldata key, address[] calldata hookAddresses) external virtual override {
        _registerHooks(key, hookAddresses);
    }

    /// @dev Internal implementation of registerHooks
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
            // Skip hook address validation - allow any non-zero address
            // if (!hook.isValidHookAddress(key.fee)) revert InvalidHookAddress();
            hookList.push(hook);
        }

        // Initialize fee configuration if not set, preserving existing settings
        if (_poolFeeConfigs[poolId].defaultFee == 0) {
            // Save existing method if it was already set
            IFeeCalculationStrategy.FeeCalculationMethod existingMethod = _poolFeeConfigs[poolId].method;
            uint24 existingPoolFee = _poolFeeConfigs[poolId].poolSpecificFee;
            bool existingPoolFeeSet = _poolFeeConfigs[poolId].poolSpecificFeeSet;
            
            _poolFeeConfigs[poolId] = IFeeCalculationStrategy.FeeConfiguration({
                defaultFee: defaultFee,
                governanceFee: governanceFee,
                governanceFeeSet: governanceFeeSet,
                poolSpecificFee: existingPoolFee,
                poolSpecificFeeSet: existingPoolFeeSet,
                method: (uint8(existingMethod) == 0) ? IFeeCalculationStrategy.FeeCalculationMethod.WEIGHTED_AVERAGE : existingMethod
            });
        }

        emit HooksRegistered(poolId, hookAddresses);
    }
    
    /// @inheritdoc IMultiHookAdapterBase
    function setPoolFeeCalculationMethod(
        PoolId poolId, 
        IFeeCalculationStrategy.FeeCalculationMethod method
    ) external virtual override onlyGovernance {
        _poolFeeConfigs[poolId].method = method;
        emit PoolFeeConfigurationUpdated(poolId, method, _poolFeeConfigs[poolId].poolSpecificFee);
    }
    
    /// @inheritdoc IMultiHookAdapterBase
    function setPoolSpecificFee(PoolId poolId, uint24 fee) external virtual override onlyGovernance {
        if (fee > 1_000_000) revert InvalidFee(fee);
        
        _poolFeeConfigs[poolId].poolSpecificFee = fee;
        _poolFeeConfigs[poolId].poolSpecificFeeSet = (fee > 0);
        
        emit PoolFeeConfigurationUpdated(poolId, _poolFeeConfigs[poolId].method, fee);
    }
    
    /// @inheritdoc IMultiHookAdapterBase
    function setGovernanceFee(uint24 fee) external virtual override onlyGovernance {
        if (fee > 1_000_000) revert InvalidFee(fee);
        
        uint24 oldFee = governanceFee;
        governanceFee = fee;
        governanceFeeSet = (fee > 0);
        
        emit GovernanceFeeUpdated(oldFee, fee);
    }
    
    /// @inheritdoc IMultiHookAdapterBase
    function getFeeConfiguration(PoolId poolId) 
        external 
        view 
        override 
        returns (IFeeCalculationStrategy.FeeConfiguration memory config) 
    {
        return _getFeeConfiguration(poolId);
    }
    
    /// @dev Internal function to get fee configuration
    function _getFeeConfiguration(PoolId poolId) 
        internal 
        view 
        returns (IFeeCalculationStrategy.FeeConfiguration memory config) 
    {
        config = _poolFeeConfigs[poolId];
        // Ensure governance fee is current
        config.governanceFee = governanceFee;
        config.governanceFeeSet = governanceFeeSet;
        // Ensure default fee is current
        if (config.defaultFee == 0) {
            config.defaultFee = defaultFee;
        }
    }
    
    /// @inheritdoc IMultiHookAdapterBase
    function calculatePoolFee(
        PoolId poolId,
        uint24[] memory hookFees,
        uint256[] memory hookWeights
    ) external view override returns (uint24 finalFee) {
        require(hookFees.length == hookWeights.length, "Array length mismatch");
        
        IFeeCalculationStrategy.FeeConfiguration memory config = _getFeeConfiguration(poolId);
        
        // Convert to WeightedFee array
        IFeeCalculationStrategy.WeightedFee[] memory weightedFees = 
            new IFeeCalculationStrategy.WeightedFee[](hookFees.length);
            
        for (uint256 i = 0; i < hookFees.length; i++) {
            weightedFees[i] = IFeeCalculationStrategy.WeightedFee({
                fee: hookFees[i],
                weight: hookWeights[i],
                isValid: true
            });
        }
        
        return feeCalculationStrategy.calculateFee(poolId, weightedFees, config);
    }

    /// @notice Returns the hook permissions for this adapter
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
        uint256 length = subHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            if (uint160(address(subHooks[i])) & Hooks.BEFORE_INITIALIZE_FLAG != 0) {
                (bool success, bytes memory result) = address(subHooks[i]).call(
                    abi.encodeWithSelector(IHooks.beforeInitialize.selector, sender, key, sqrtPriceX96)
                );
                require(success, "Sub-hook beforeInitialize failed");
                require(
                    result.length >= 4 && bytes4(result) == IHooks.beforeInitialize.selector,
                    "Invalid beforeInitialize return"
                );
            }
        }
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
        BeforeSwapContext memory context =
            BeforeSwapContext({sender: sender, key: key, params: params, data: data, poolId: poolId});

        // Clear any previous hook returns for this pool
        delete beforeSwapHookReturns[poolId];

        // Get hook list and fee configuration
        IHooks[] storage subHooks = _hooksByPool[poolId];
        IFeeCalculationStrategy.FeeConfiguration memory feeConfig = _getFeeConfiguration(poolId);

        // Process hooks and collect weighted fees
        BeforeSwapDelta combinedDelta = BeforeSwapDeltaLibrary.ZERO_DELTA;
        uint256 length = subHooks.length;
        
        IFeeCalculationStrategy.WeightedFee[] memory weightedFees = 
            new IFeeCalculationStrategy.WeightedFee[](length);
        
        // Initialize the array with the correct length
        beforeSwapHookReturns[poolId] = new BeforeSwapDelta[](length);

        for (uint256 i = 0; i < length; ++i) {
            // Skip hooks without the BEFORE_SWAP_FLAG
            if (uint160(address(subHooks[i])) & Hooks.BEFORE_SWAP_FLAG == 0) {
                weightedFees[i] = IFeeCalculationStrategy.WeightedFee({
                    fee: 0,
                    weight: 0,
                    isValid: false
                });
                continue;
            }

            // Try weighted hook interface first
            weightedFees[i] = _callHookForWeightedFee(subHooks[i], context, i);
            
            // Add to combined delta if hook has delta returns flag
            if (uint160(address(subHooks[i])) & Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG != 0) {
                combinedDelta = _addBeforeSwapDelta(combinedDelta, beforeSwapHookReturns[poolId][i]);
            }
        }

        // Calculate final fee using strategy
        uint24 finalFee = feeCalculationStrategy.calculateFee(poolId, weightedFees, feeConfig);

        return (IHooks.beforeSwap.selector, combinedDelta, finalFee);
    }
    
    /// @dev Call hook and extract weighted fee information
    function _callHookForWeightedFee(
        IHooks hook, 
        BeforeSwapContext memory context, 
        uint256 index
    ) internal returns (IFeeCalculationStrategy.WeightedFee memory weightedFee) {
        address hookAddr = address(hook);
        
        // Check if hook supports weighted fees
        try IWeightedHook(hookAddr).supportsWeightedFees() returns (bool supportsWeighted) {
            if (supportsWeighted) {
                return _callWeightedHook(IWeightedHook(hookAddr), context, index);
            }
        } catch {
            // Fall back to standard hook call
        }
        
        // Standard hook call
        return _callStandardHook(hook, context, index);
    }
    
    /// @dev Call weighted hook interface
    function _callWeightedHook(
        IWeightedHook weightedHook, 
        BeforeSwapContext memory context, 
        uint256 index
    ) internal returns (IFeeCalculationStrategy.WeightedFee memory weightedFee) {
        try weightedHook.beforeSwapWeighted(context.sender, context.key, context.params, context.data) 
            returns (IWeightedHook.WeightedHookResult memory result) {
            
            require(result.selector == IHooks.beforeSwap.selector, "Invalid weighted hook return");
            
            // Store delta if applicable
            if (uint160(address(weightedHook)) & Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG != 0) {
                beforeSwapHookReturns[context.poolId][index] = result.delta;
            }
            
            return IFeeCalculationStrategy.WeightedFee({
                fee: result.hasFeeOverride ? result.fee : 0,
                weight: result.weight,
                isValid: result.hasFeeOverride && result.weight > 0
            });
            
        } catch {
            // If weighted call fails, fall back to standard
            return _callStandardHook(IHooks(address(weightedHook)), context, index);
        }
    }
    
    /// @dev Call standard hook interface and infer weight
    function _callStandardHook(
        IHooks hook, 
        BeforeSwapContext memory context, 
        uint256 index
    ) internal returns (IFeeCalculationStrategy.WeightedFee memory weightedFee) {
        (bool success, bytes memory result) = address(hook).call(
            abi.encodeWithSelector(
                IHooks.beforeSwap.selector, context.sender, context.key, context.params, context.data
            )
        );
        require(success, "Sub-hook beforeSwap failed");

        // Process result based on hook permissions
        if (uint160(address(hook)) & Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG != 0) {
            // Process with delta returns
            (bytes4 sel, BeforeSwapDelta delta, uint24 fee) = abi.decode(result, (bytes4, BeforeSwapDelta, uint24));
            require(sel == IHooks.beforeSwap.selector, "Invalid beforeSwap return");

            // Save delta for later use
            beforeSwapHookReturns[context.poolId][index] = delta;

            return IFeeCalculationStrategy.WeightedFee({
                fee: fee,
                weight: (fee != LPFeeLibrary.OVERRIDE_FEE_FLAG) ? 1 : 0, // Default weight 1 for fee overrides
                isValid: fee != LPFeeLibrary.OVERRIDE_FEE_FLAG
            });
        } else {
            // Process without delta returns - check for fee override
            bytes4 sel = result.length >= 4 ? bytes4(result) : bytes4(0);
            if (sel == IHooks.beforeSwap.selector) {
                return IFeeCalculationStrategy.WeightedFee({
                    fee: 0,
                    weight: 0,
                    isValid: false
                });
            } else {
                // Try to extract fee override
                uint256 overrideVal = result.length == 32 ? abi.decode(result, (uint256)) : 0;
                uint24 hookFee = uint24(overrideVal);

                return IFeeCalculationStrategy.WeightedFee({
                    fee: hookFee,
                    weight: (hookFee != LPFeeLibrary.OVERRIDE_FEE_FLAG) ? 1 : 0,
                    isValid: hookFee != LPFeeLibrary.OVERRIDE_FEE_FLAG
                });
            }
        }
    }

    function _afterSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        BalanceDelta swapDelta,
        bytes calldata data
    ) internal override lock returns (bytes4, int128) {
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
        BalanceDelta combinedDelta = BalanceDeltaLibrary.ZERO_DELTA;

        if (addedLiquidity) {
            combinedDelta = _processAfterAddLiquidity(subHooks, sender, key, params, delta, feesAccrued, data);
            return (IHooks.afterAddLiquidity.selector, combinedDelta);
        } else {
            combinedDelta = _processAfterRemoveLiquidity(subHooks, sender, key, params, delta, feesAccrued, data);
            return (IHooks.afterRemoveLiquidity.selector, combinedDelta);
        }
    }

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