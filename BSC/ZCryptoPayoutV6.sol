// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20, SafeToken} from "./SafeToken.sol";

/// @dev 旧 WITHDRAW 出口接口（与 GuessAccountV6 同款对接）：receiveSellProceeds 会从
///      本合约 transferFrom 拉走 USDT，并把金额记入用户在旧 WITHDRAW 的统一账户余额。
interface ILegacyWithdraw {
    function receiveSellProceeds(address user, uint256 amount) external;
}

/// @dev 会话密钥注册表只读接口（ZCryptoSessionManagerV6，BSC 唯一权威）。
interface ISessionManagerV6 {
    function isActive(address user, address key) external view returns (bool);
}

/// @title ZCryptoPayoutV6 —— 质押分红 + 佣金 统一领取合约（BSC，USDT）
/// @notice 账务真相源在 PHP+MySQL；本合约只做三件事：
///         owner 预存 USDT → operator（PHP 后台密钥）按批次挂账 → 用户自提。
/// @dev    铁律：
///         1) 先打钱后挂账：creditBatch 强制偿付能力检查，余额不够直接 revert；
///         2) batchId 幂等：PHP 重试/重放同一批不会重复挂账；
///         3) claim 不裸转 USDT：走旧 WITHDRAW.receiveSellProceeds，金额进用户统一账户余额
///            （WITHDRAW 是唯一出入口纪律，与游戏出场同路）。
///         出入管制：平时 sweep 只能扫"未分配余额"（已挂账未领取部分扫不走）；
///         紧急状态下（paused）owner 可 emergencyRescue 全额转移，含已挂账部分。
contract ZCryptoPayoutV6 {
    using SafeToken for IERC20;

    // ==================== 自定义错误 ====================
    error ZeroAddrErr();
    error ZeroAmountErr();
    error NotOwnerErr();
    error NotOperatorErr();
    error PausedErr();
    error ReentrantErr();
    error BatchProcessedErr();        // batchId 已处理（幂等拦截）
    error LengthMismatchErr();
    error BadKindErr();
    error InsufficientFundsErr();     // 池内余额不足以覆盖本次挂账
    error NothingToClaimErr();
    error SweepExceedsErr();          // 试图扫走已挂账的钱
    error NotPausedErr();             // emergencyRescue 须先 pause
    error DeadlinePassedErr();
    error InvalidNonceErr();
    error InvalidSignatureErr();

    // ==================== EIP-712（会话密钥签名领取） ====================
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant NAME_HASH = keccak256("ZCryptoPayoutV6");
    bytes32 public constant VERSION_HASH = keccak256("1");
    /// @dev 领取是"全额自提到本人 WITHDRAW 账户"，签名不含金额：
    ///      语义 = 把我在本合约的全部可领余额划入我的统一账户（金额无盗用向量，省去余额竞态）。
    bytes32 public constant CLAIM_TYPEHASH = keccak256(
        "ClaimPayout(address user,uint256 nonce,uint64 deadline)");
    uint256 private constant SECP256K1_HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    // ==================== 常量与角色 ====================
    IERC20 public immutable usdt;
    ILegacyWithdraw public immutable withdrawContract;  // 旧 WITHDRAW（唯一出入口）
    ISessionManagerV6 public immutable sessionManager;  // 会话密钥注册表
    address public owner;
    address public operator;          // PHP 后台密钥（只能挂账，碰不了钱）
    bool public paused;

    // ==================== 台账 ====================
    uint256 public totalCredited;     // 累计挂账
    uint256 public totalClaimed;      // 累计领取
    mapping(address => uint256) public claimable;        // 用户可提余额（分红+佣金合并）
    mapping(bytes32 => bool) public processedBatch;      // batchId 幂等
    mapping(address => uint256) public actionNonces;     // 会话签名顺序 nonce（与游戏出场同款）

    uint256 private _lock;            // 防重入

    // ==================== 事件 ====================
    /// @notice kind: 1=质押分红 2=佣金（仅审计标签，链上合并为一个余额）
    event Credited(bytes32 indexed batchId, uint8 indexed kind, address indexed user, uint256 amount);
    event Claimed(address indexed user, uint256 amount);
    event Funded(address indexed from, uint256 amount);
    event Swept(address indexed to, uint256 amount);
    event EmergencyRescue(address indexed to, uint256 amount);
    event OperatorSet(address indexed oldOp, address indexed newOp);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event PausedSet(bool paused);

    // ==================== 修饰器 ====================
    modifier onlyOwner() { if (msg.sender != owner) revert NotOwnerErr(); _; }
    modifier onlyOperator() { if (msg.sender != operator) revert NotOperatorErr(); _; }
    modifier whenNotPaused() { if (paused) revert PausedErr(); _; }
    modifier nonReentrant() {
        if (_lock != 0) revert ReentrantErr();
        _lock = 1; _; _lock = 0;
    }

    constructor(address usdt_, address withdrawContract_, address sessionManager_,
                address owner_, address operator_) {
        if (usdt_ == address(0) || withdrawContract_ == address(0) ||
            sessionManager_ == address(0) || owner_ == address(0)) revert ZeroAddrErr();
        usdt = IERC20(usdt_);
        withdrawContract = ILegacyWithdraw(withdrawContract_);
        sessionManager = ISessionManagerV6(sessionManager_);
        owner = owner_;
        operator = operator_;         // 允许零地址 = 暂不开通挂账
        // receiveSellProceeds 会从本合约拉款：max 授权（与 GuessAccountV6 对接方式一致）
        SafeToken.safeApprove(IERC20(usdt_), withdrawContract_, type(uint256).max);
    }

    // ==================== 视图 ====================
    /// @notice 已挂账未领取总额（= 用户可提余额总和，owner 扫不走这部分）
    function unclaimed() public view returns (uint256) {
        return totalCredited - totalClaimed;
    }

    /// @notice 池内还可分配的余额（owner 可扫 / operator 可挂账的上限）
    function allocatable() public view returns (uint256) {
        return usdt.balanceOf(address(this)) - unclaimed();
    }

    // ==================== OWNER：入金 ====================
    /// @notice 预存 USDT（需先 approve）。也可以直接向合约地址普通转账，效果相同，
    ///         只是少了 Funded 事件；偿付能力检查按 balanceOf 实余计算，两种入金都认。
    function fund(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmountErr();
        usdt.safeTransferFrom(msg.sender, address(this), amount);
        emit Funded(msg.sender, amount);
    }

    // ==================== OPERATOR：挂账 ====================
    /// @notice 批量挂账（分红或佣金）。PHP 每天算好后调用；同一 batchId 只能成功一次。
    /// @param batchId 批次号（建议 keccak256(日期+kind+流水号)），PHP 重试幂等
    /// @param kind    1=质押分红 2=佣金
    /// @dev 强制"先打钱后挂账"：合约实余必须覆盖 未领取余额 + 本批总额，否则整批 revert。
    ///      单批建议 ≤ 400 用户（BSC 单笔 gas 上限内）。
    function creditBatch(bytes32 batchId, uint8 kind, address[] calldata users, uint256[] calldata amounts)
        external nonReentrant onlyOperator whenNotPaused
    {
        if (kind != 1 && kind != 2) revert BadKindErr();
        if (processedBatch[batchId]) revert BatchProcessedErr();
        uint256 n = users.length;
        if (n == 0 || n != amounts.length) revert LengthMismatchErr();

        uint256 sum;
        for (uint256 i = 0; i < n; i++) {
            if (users[i] == address(0)) revert ZeroAddrErr();
            if (amounts[i] == 0) revert ZeroAmountErr();
            sum += amounts[i];
        }
        if (usdt.balanceOf(address(this)) < unclaimed() + sum) revert InsufficientFundsErr();

        processedBatch[batchId] = true;
        totalCredited += sum;
        for (uint256 i = 0; i < n; i++) {
            claimable[users[i]] += amounts[i];
            emit Credited(batchId, kind, users[i], amounts[i]);
        }
    }

    // ==================== 用户：自提 ====================
    /// @notice 本人直接提取全部可领余额（分红+佣金合并一笔）。
    function claim() external nonReentrant whenNotPaused {
        _claim(msg.sender);
    }

    /// @notice 会话密钥签名领取（relay 代发，无需主钱包；与游戏出场同款 EIP-712 流程）。
    /// @dev 签名者为该用户在 SessionManager 注册的活跃会话密钥；nonce 顺序防重放。
    function claimBySig(address user, uint256 nonce, uint64 deadline, bytes calldata signature)
        external nonReentrant whenNotPaused
    {
        _verifyClaimSig(user, nonce, deadline, signature);
        _claim(user);
    }

    /// @dev 不裸转 USDT：旧 WITHDRAW 从本合约拉款并记入用户统一账户余额，
    ///      用户在旧 WITHDRAW 体系内再自行提币（WITHDRAW 唯一出入口纪律）。
    function _claim(address user) internal {
        uint256 amount = claimable[user];
        if (amount == 0) revert NothingToClaimErr();
        claimable[user] = 0;
        totalClaimed += amount;
        withdrawContract.receiveSellProceeds(user, amount);
        emit Claimed(user, amount);
    }

    // ==================== EIP-712 验签（与 GuessAccountV6 同款） ====================
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _verifyClaimSig(address user, uint256 nonce, uint64 deadline, bytes calldata signature)
        internal
    {
        if (user == address(0)) revert ZeroAddrErr();
        if (block.timestamp > deadline) revert DeadlinePassedErr();
        if (nonce != actionNonces[user]) revert InvalidNonceErr();
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, user, nonce, deadline));
        address signer = _recover(
            keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash)), signature);
        // 签名者必须是该用户当前有效的会话密钥（SessionManager 为唯一权威注册表）
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

    // ==================== OWNER：治理 ====================
    /// @notice 清扫未分配余额。已挂账未领取的部分（unclaimed）平时扫不走。
    function sweep(address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert ZeroAddrErr();
        if (amount == 0 || amount > allocatable()) revert SweepExceedsErr();
        usdt.safeTransfer(to, amount);
        emit Swept(to, amount);
    }

    /// @notice 紧急救援：暂停后 owner 可将任意金额转至安全地址（含已挂账部分）。
    /// @dev 仅在合约漏洞/USDT 异常等紧急场景使用；正常运营用 sweep。
    function emergencyRescue(address to, uint256 amount) external onlyOwner nonReentrant {
        if (!paused) revert NotPausedErr();
        if (to == address(0)) revert ZeroAddrErr();
        if (amount == 0 || amount > usdt.balanceOf(address(this))) revert InsufficientFundsErr();
        usdt.safeTransfer(to, amount);
        emit EmergencyRescue(to, amount);
    }

    function setOperator(address op) external onlyOwner {
        emit OperatorSet(operator, op);
        operator = op;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddrErr();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setPaused(bool p) external onlyOwner {
        paused = p;
        emit PausedSet(p);
    }
}

