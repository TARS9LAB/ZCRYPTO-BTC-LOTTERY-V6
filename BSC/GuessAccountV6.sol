// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./SafeToken.sol";
import "./IGuessAccountV6.sol";

/// @title GuessAccountV6 — 游戏资金池 + 台账（不接主钱包签名）
/// @notice V6 的 USDT 自持资金池。实现 IGuessAccountV6（仅 GuessV6 规则合约可调），
///         出入金骑在**旧 WITHDRAW 合约**的 FancyBTC 式白名单通道上（旧合约零改动）。
///
///   通道对接（用户拍板：游戏出入金仍走旧 WITHDRAW，无其他出入口）：
///     - 进场：后端调旧 WITHDRAW.fundBuyQueue / smartFundBuyQueue(本合约, user, amount, orderId)
///       → 旧 WITHDRAW 扣用户统一账户，并回调本合约 depositAndQueueFor /
///       smartDepositAndQueueFor 推送 USDT（与 FancyBTC 完全同款流程，msg.sender == 旧 WITHDRAW）。
///       orderId 幂等防后端重试重复入账。本合约只在被旧 WITHDRAW 调用的函数内拉款，
///       自身永远无法主动发起 transferFrom。
///     - 出场：用户会话密钥 EIP-712 签名 withdrawGameBySig（relay 代发，无需主钱包），
///       先查 GuessV6 提现闸门，再放款并调旧 WITHDRAW.receiveSellProceeds 记回用户统一账户，
///       最终按现有后端签名流程提现。本合约须在旧 WITHDRAW 的 allowedFancyBtc 白名单内。
///
///   分桶台账（全部只进有源、出有据）：
///     balances（用户游戏余额）/ betEscrow（在押注金）/ claimReserve（派奖储备）
///     poolLedger（滚存奖池镜像）/ rakeAcc（运营费）/ feeAcc（决胜剩余）/ dividendAcc（ZC 质押分红）
///     守恒断言：settleRound 要求 totalPayout + rake + fee + poolAfter == t + poolBefore；
///     solvent() 要求 USDT 实余 >= 全部桶合计（owner 无 USDT 转出资，仅桶清扫）。
contract GuessAccountV6 is IGuessAccountV6 {
    using SafeToken for IERC20;

    // ==================== 自定义错误 ====================
    error ZeroAddrErr();
    error ZeroAmountErr();
    error NotOwnerErr();
    error NotRulesErr();
    error PausedErr();
    error ReentrantErr();
    error InsufficientBalanceErr();
    error EscrowShortErr();
    error ReserveShortErr();
    error PoolMismatchErr();
    error ConservationErr();
    error DividendExceedsRakeErr();
    error WithdrawBlockedErr();
    error DeadlinePassedErr();
    error InvalidNonceErr();
    error InvalidSignatureErr();
    error UsdtRescueErr();
    error BucketShortErr();
    error OnlyWithdrawErr();
    error OrderProcessedErr();

    // ==================== EIP-712 ====================
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant NAME_HASH = keccak256("ZCryptoGuessAccountV6");
    bytes32 public constant VERSION_HASH = keccak256("1");
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256(
        "WithdrawGame(address user,uint256 amount,uint256 nonce,uint64 deadline)");
    uint256 private constant SECP256K1_HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    // ==================== 依赖 ====================
    address public owner;
    IERC20 public immutable usdt;                 // BSC USDT（18 位）
    IGuessV6Gate public guessV6;                  // 规则合约（提现闸门 + onlyRules 调用源）
    ILegacyWithdraw public withdrawContract;        // 旧 WITHDRAW（allowedFancyBtc 通道）
    ISessionManagerV6 public sessionManager;      // 会话密钥注册表
    bool public paused;
    bool private _locked;

    // ==================== 台账 ====================
    mapping(address => uint256) public balances;  // 用户游戏余额
    uint256 public totalUserBalances;
    uint256 public betEscrow;                     // 在押注金（已扣未结算）
    uint256 public claimReserve;                  // 派奖储备（待领取奖金）
    uint256 public poolLedger;                    // 滚存奖池（与 GuessV6.poolMirror / MegaETH pool 咬合）
    uint256 public rakeAcc;                       // 运营费（已扣分红）
    uint256 public feeAcc;                        // 决胜轮剩余
    uint256 public dividendAcc;                   // ZC 质押分红桶（1.5% 下注额，自运营费切出）

    mapping(address => uint256) public actionNonces;  // 会话签名顺序 nonce（出场共用）
    mapping(bytes32 => bool) public processedOrders;    // 进场 orderId 幂等（防后端重试重复入账）

    // ==================== 事件 ====================
    event EnteredGame(address indexed user, uint256 amount, bytes32 indexed orderId);
    event WithdrawnToChannel(address indexed user, uint256 amount);
    event BetDebited(address indexed user, uint256 amount, bytes32 indexed leaf);
    event RoundSettled(uint256 indexed rid, uint256 t, uint256 totalPayout, uint256 rake,
                       uint256 dividend, uint256 fee, uint256 poolBefore, uint256 poolAfter);
    event VoidApplied(uint256 indexed rid);
    event WinPaid(address indexed user, uint256 amount);
    event EscrowRefunded(address indexed user, uint256 amount);
    event RolledBack(address indexed user, uint256 amount);
    event PoolSeeded(address indexed from, uint256 amount, uint256 poolAfter);
    event BucketSwept(uint8 indexed bucket, address indexed to, uint256 amount); // 0=rake 1=fee 2=dividend
    event Paused();
    event Unpaused();
    event OwnerTransferred(address indexed oldOwner, address indexed newOwner);
    event WithdrawContractUpdated(address indexed oldC, address indexed newC);
    event SessionManagerUpdated(address indexed oldS, address indexed newS);
    event TokenRescued(address indexed token, address indexed to, uint256 amount);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwnerErr(); _; }
    modifier onlyRules() { if (msg.sender != address(guessV6)) revert NotRulesErr(); _; }
    modifier whenNotPaused() { if (paused) revert PausedErr(); _; }
    modifier nonReentrant() { if (_locked) revert ReentrantErr(); _locked = true; _; _locked = false; }

    constructor(
        address _usdt,
        address _guessV6,
        address _withdrawContract,
        address _sessionManager,
        address _owner
    ) {
        if (_usdt == address(0) || _guessV6 == address(0) || _withdrawContract == address(0)
            || _sessionManager == address(0) || _owner == address(0)) revert ZeroAddrErr();
        usdt = IERC20(_usdt);
        guessV6 = IGuessV6Gate(_guessV6);
        withdrawContract = ILegacyWithdraw(_withdrawContract);
        sessionManager = ISessionManagerV6(_sessionManager);
        owner = _owner;
        // 出场回款 receiveSellProceeds 采用 transferFrom 拉取：一次性授权旧 WITHDRAW
        usdt.safeApprove(_withdrawContract, type(uint256).max);
    }

    // ==================== 管理 ====================
    function transferOwnership(address n) external onlyOwner {
        if (n == address(0)) revert ZeroAddrErr();
        emit OwnerTransferred(owner, n);
        owner = n;
    }

    function pause() external onlyOwner { paused = true; emit Paused(); }
    function unpause() external onlyOwner { paused = false; emit Unpaused(); }

    /// @notice 更换通道合约（灾难升级路径，如迁移到 ZCryptoWithdrawV6）；重新授权后旧通道应被弃用。
    function setWithdrawContract(address c) external onlyOwner {
        if (c == address(0)) revert ZeroAddrErr();
        emit WithdrawContractUpdated(address(withdrawContract), c);
        withdrawContract = ILegacyWithdraw(c);
        usdt.safeApprove(c, type(uint256).max);
    }

    function setSessionManager(address s) external onlyOwner {
        if (s == address(0)) revert ZeroAddrErr();
        emit SessionManagerUpdated(address(sessionManager), s);
        sessionManager = ISessionManagerV6(s);
    }

    /// @notice 抢救误转的非 USDT 代币；USDT 任何时候不得被转走（偿付能力红线）。
    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert ZeroAddrErr();
        if (token == address(usdt)) revert UsdtRescueErr();
        IERC20(token).safeTransfer(to, amount);
        emit TokenRescued(token, to, amount);
    }

    /// @notice 奖池注资（与 MegaETH schedulePoolBonus 同步）：owner 转入 USDT 注入 poolLedger。
    /// @dev 序列：先 seedPool(BSC) 与 schedulePoolBonus(MegaETH) 同额，再等新周期首轮结算消息
    ///      携带 poolBonus 完成两侧镜像咬合。
    function seedPool(uint256 amount) external onlyOwner nonReentrant {
        if (amount == 0) revert ZeroAmountErr();
        usdt.safeTransferFrom(msg.sender, address(this), amount);
        poolLedger += amount;
        emit PoolSeeded(msg.sender, amount, poolLedger);
    }

    // ==================== 桶清扫（owner；USDT 仅有的三个出口，全部有据） ====================
    function sweepRake(address to, uint256 amount) external onlyOwner nonReentrant {
        _sweep(0, rakeAcc, to, amount);
        rakeAcc -= amount;
    }
    function sweepFee(address to, uint256 amount) external onlyOwner nonReentrant {
        _sweep(1, feeAcc, to, amount);
        feeAcc -= amount;
    }
    function sweepDividend(address to, uint256 amount) external onlyOwner nonReentrant {
        _sweep(2, dividendAcc, to, amount);
        dividendAcc -= amount;
    }
    function _sweep(uint8 bucket, uint256 bucketValue, address to, uint256 amount) internal {
        if (to == address(0)) revert ZeroAddrErr();
        if (amount == 0 || amount > bucketValue) revert BucketShortErr();
        usdt.safeTransfer(to, amount);
        emit BucketSwept(bucket, to, amount);
    }

    // ==================== 进场（旧 WITHDRAW 推送，FancyBTC 式） ====================
    /// @notice 旧 WITHDRAW.fundBuyQueue 回调：统一账户 → 游戏余额。
    /// @dev msg.sender 必须是旧 WITHDRAW（其后端 owner/sttOwner 发起 fundBuyQueue 后回调此处），
    ///      USDT 从旧 WITHDRAW 拉入（白名单时旧合约已 max 授权本合约），资金只记到 user 名下。
    ///      orderId 幂等：后端重试/重放不会重复入账。
    function depositAndQueueFor(address user, uint256 amount, bytes32 orderId)
        external nonReentrant whenNotPaused
    {
        if (msg.sender != address(withdrawContract)) revert OnlyWithdrawErr();
        _enterGame(user, amount, orderId);
    }

    /// @notice 旧 WITHDRAW.smartFundBuyQueue 回调（差额语义对游戏不适用：游戏没有内部账可抵扣，
    ///         全额从旧 WITHDRAW 拉取，actualPulled 恒等于 amount，与旧合约扣账一致）。
    function smartDepositAndQueueFor(address user, uint256 amount, bytes32 orderId)
        external nonReentrant whenNotPaused
    {
        if (msg.sender != address(withdrawContract)) revert OnlyWithdrawErr();
        _enterGame(user, amount, orderId);
    }

    function _enterGame(address user, uint256 amount, bytes32 orderId) internal {
        if (user == address(0)) revert ZeroAddrErr();
        if (user == msg.sender) revert ZeroAddrErr();          // 同旧合约"不能给自己买"语义
        if (amount == 0) revert ZeroAmountErr();
        if (processedOrders[orderId]) revert OrderProcessedErr();
        processedOrders[orderId] = true;
        usdt.safeTransferFrom(msg.sender, address(this), amount);   // 旧 WITHDRAW → 本合约
        balances[user] += amount;
        totalUserBalances += amount;
        emit EnteredGame(user, amount, orderId);
    }

    // ==================== 用户：提游戏内余额（游戏余额 → 旧 WITHDRAW 统一账户） ====================
    /// @notice 主钱包直接提（便利路径）。
    function withdrawGame(uint256 amount) external nonReentrant whenNotPaused {
        _withdrawGame(msg.sender, amount);
    }

    /// @notice 会话密钥签名提游戏内余额（relay 代发；典型路径）。
    /// @dev 执行前必查 GuessV6 提现闸门：有未终局活动（押注/领奖）或全局冻结 → 拒绝。
    function withdrawGameBySig(
        address user, uint256 amount, uint256 nonce, uint64 deadline, bytes calldata signature
    ) external nonReentrant whenNotPaused {
        _verifySessionSig(user, WITHDRAW_TYPEHASH, amount, nonce, deadline, signature);
        _withdrawGame(user, amount);
    }

    function _withdrawGame(address user, uint256 amount) internal {
        if (user == address(0)) revert ZeroAddrErr();
        if (amount == 0) revert ZeroAmountErr();
        if (guessV6.withdrawalBlocked(user)) revert WithdrawBlockedErr();
        if (balances[user] < amount) revert InsufficientBalanceErr();
        balances[user] -= amount;
        totalUserBalances -= amount;
        // 旧 WITHDRAW 从本合约拉款（构造函数已 max 授权），记到用户统一账户
        withdrawContract.receiveSellProceeds(user, amount);
        emit WithdrawnToChannel(user, amount);
    }

    // ==================== 规则合约指令（仅 GuessV6） ====================
    /// @inheritdoc IGuessAccountV6
    function debitBet(address user, uint256 amount, bytes32 leaf) external onlyRules {
        if (balances[user] < amount) revert InsufficientBalanceErr();
        balances[user] -= amount;
        totalUserBalances -= amount;
        betEscrow += amount;
        emit BetDebited(user, amount, leaf);
    }

    /// @inheritdoc IGuessAccountV6
    function settleRound(
        uint256 rid, uint256 t, uint256 totalPayout, uint256 rake, uint256 dividend,
        uint256 fee, uint256 poolBefore, uint256 poolAfter
    ) external onlyRules {
        if (dividend > rake) revert DividendExceedsRakeErr();
        if (betEscrow < t) revert EscrowShortErr();
        if (poolLedger != poolBefore) revert PoolMismatchErr();
        // 守恒断言（GuessV6 已按分支复算，此处纵深防御）：
        if (totalPayout + rake + fee + poolAfter != t + poolBefore) revert ConservationErr();

        betEscrow -= t;
        poolLedger = poolAfter;
        claimReserve += totalPayout;
        rakeAcc += rake - dividend;
        dividendAcc += dividend;
        feeAcc += fee;
        emit RoundSettled(rid, t, totalPayout, rake, dividend, fee, poolBefore, poolAfter);
    }

    /// @inheritdoc IGuessAccountV6
    function voidRound(uint256 rid) external onlyRules {
        emit VoidApplied(rid);   // 退款按叶从 betEscrow 支出（refundEscrow），此处无批量账务
    }

    /// @inheritdoc IGuessAccountV6
    function payWin(address user, uint256 amount) external onlyRules {
        if (claimReserve < amount) revert ReserveShortErr();
        claimReserve -= amount;
        balances[user] += amount;
        totalUserBalances += amount;
        emit WinPaid(user, amount);
    }

    /// @inheritdoc IGuessAccountV6
    function refundEscrow(address user, uint256 amount) external onlyRules {
        if (betEscrow < amount) revert EscrowShortErr();
        betEscrow -= amount;
        balances[user] += amount;
        totalUserBalances += amount;
        emit EscrowRefunded(user, amount);
    }

    /// @inheritdoc IGuessAccountV6
    function rollbackToReserve(address user, uint256 amount) external onlyRules {
        if (balances[user] < amount) revert InsufficientBalanceErr();  // GuessV6 try/catch 转告警
        balances[user] -= amount;
        totalUserBalances -= amount;
        claimReserve += amount;
        emit RolledBack(user, amount);
    }

    // ==================== 对账 ====================
    /// @notice 全部负债桶合计。
    function totalObligations() public view returns (uint256) {
        return totalUserBalances + betEscrow + claimReserve + poolLedger + rakeAcc + feeAcc + dividendAcc;
    }

    /// @notice 合约 USDT 实余应恒 >= 全部桶合计。
    function solvent() external view returns (bool) {
        return usdt.balanceOf(address(this)) >= totalObligations();
    }

    // ==================== EIP-712（会话密钥签名） ====================
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _verifySessionSig(
        address user, bytes32 typehash, uint256 amount, uint256 nonce, uint64 deadline, bytes calldata signature
    ) internal {
        if (user == address(0)) revert ZeroAddrErr();
        if (block.timestamp > deadline) revert DeadlinePassedErr();
        if (nonce != actionNonces[user]) revert InvalidNonceErr();
        bytes32 structHash = keccak256(abi.encode(typehash, user, amount, nonce, deadline));
        address signer = _recover(keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash)), signature);
        // 签名者必须是该用户当前有效的会话密钥（BSC SessionManager 为唯一权威注册表）
        if (!sessionManager.isActive(user, signer)) revert InvalidSignatureErr();
        actionNonces[user] = nonce + 1;
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v != 27 && v != 28) return address(0);
        if (uint256(s) > SECP256K1_HALF_N || r == bytes32(0) || s == bytes32(0)) return address(0);
        signer = ecrecover(digest, v, r, s);
    }
}
