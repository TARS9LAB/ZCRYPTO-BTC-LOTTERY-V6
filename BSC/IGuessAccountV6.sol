// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice GuessV6 对 GuessAccount 的指令接口（唯一实现方：GuessAccountV6）。
/// @dev 与 GuessV6.sol 内联声明逐字一致；实现侧必须 onlyRules（仅 GuessV6 可调用）。
interface IGuessAccountV6 {
    /// @notice 押注登记时扣 1 张票（user 余额 → betEscrow）；余额不足必须 revert。
    function debitBet(address user, uint256 amount, bytes32 leaf) external;
    /// @notice 结算落地：betEscrow -= t；claimReserve += totalPayout；
    ///         rakeAcc += rake-dividend；dividendAcc += dividend；feeAcc += fee；pool: poolBefore → poolAfter。
    function settleRound(
        uint256 rid, uint256 t, uint256 totalPayout, uint256 rake, uint256 dividend,
        uint256 fee, uint256 poolBefore, uint256 poolAfter
    ) external;
    /// @notice 流局落地：本轮 betEscrow 转为可按叶退款状态；pool/rake 不动。
    function voidRound(uint256 rid) external;
    /// @notice 从 claimReserve 向用户发放奖金。
    function payWin(address user, uint256 amount) external;
    /// @notice 流局/退注：从 betEscrow 全额返还用户（含 10% 运营费部分，流局不收费）。
    function refundEscrow(address user, uint256 amount) external;
    /// @notice 冲突回滚：从用户余额扣回已入账奖金到 claimReserve（提现闸门保证此时资金未离场）。
    function rollbackToReserve(address user, uint256 amount) external;
}

/// @notice GuessAccount 查询 GuessV6 提现闸门的只读接口。
interface IGuessV6Gate {
    function withdrawalBlocked(address user) external view returns (bool);
}

/// @notice GuessAccount 验证会话密钥活跃度的只读接口（ZCryptoSessionManagerV6）。
interface ISessionManagerV6 {
    function isActive(address user, address key) external view returns (bool);
}

/// @notice 旧 WITHDRAW 合约的 FancyBTC 式白名单回款接口（游戏出场用）。
/// @dev 旧合约零改动：本接口与旧 WITHDRAW.receiveSellProceeds 签名一致；
///      调用方（GuessAccount）须在旧 WITHDRAW 的 allowedFancyBtc 白名单内。
interface ILegacyWithdraw {
    /// @notice 业务合约回款：USDT 从调用方拉入旧 WITHDRAW，记到用户统一账户。
    function receiveSellProceeds(address user, uint256 amount) external;
}
