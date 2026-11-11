// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./SafeToken.sol";

/// @title ZCryptoWithdrawV6 — 出入金唯一通道（重写版）
/// @notice 重写自旧 Withdraw 合约。核心变化：**项目方签名者（projectSigner）角色彻底删除**——
///         旧合约"后端签名即可放币"的单点（且 BNB/ZC 不查链上余额）不复存在。
///
///   资金模型：
///     - 充值：用户主钱包 `deposit`（approve + transferFrom），记入 balances[user]；
///     - 提现：用户主钱包 `withdraw`，合约放币——主钱包签名只出现在这里，
///       也是全系统唯一需要主钱包动作的地方；
///     - 游戏通道：balances 与白名单业务合约（如 GuessAccount）之间的双向搬运，
///       仅 owner 认证的白名单合约可调（onlyWhitelisted），且 USDT 随调用原子转移：
///         releaseToGame   WITHDRAW 扣用户账 → USDT 转给调用合约（用户进场）
///         creditFromGame  调用合约放 USDT → WITHDRAW 记用户账（用户出场待提）
///
///   白名单模型（替代旧合约 allowedFancyBtc 的单点写法）：
///     - owner（建议多签）通过 setAllowedContract 增删业务合约；
///     - **白名单是最高信任位**：成员合约既能 creditFromGame 给用户记账，
///       也能 releaseToGame 划走任意用户余额——因此业务合约自身的授权逻辑
///       （如 GuessAccount 的主钱包/会话密钥签名校验、withdrawalBlocked 闸）
///       是用户资金的真正防线，加入白名单前必须完成审计；
///     - 移除白名单不影响存量记账，只切断后续搬运。
///
///   与旧合约的关系：旧合约保持原样只出不进（存量客户资金用后端签名原路提走），
///   本合约从零开始承接新资金；owner 无任意转币权限（rescue 禁止动 USDT）。
contract ZCryptoWithdrawV6 {
    using SafeToken for IERC20;

    // ==================== 自定义错误 ====================
    error ZeroAddrErr();
    error ZeroAmountErr();
    error NotOwnerErr();
    error NotWhitelistedErr();
    error PausedErr();
    error InsufficientBalanceErr();
    error ReentrantErr();
    error UsdtRescueErr();

    // ==================== 存储 ====================
    address public owner;
    IERC20 public immutable usdt;             // BSC USDT（18 位）
    bool public paused;
    bool private _locked;

    /// @notice 认证的业务合约白名单（如 GuessAccountV6）。
    ///         成员可调用 releaseToGame / creditFromGame 在用户余额与自身之间搬运 USDT。
    mapping(address => bool) public allowedContracts;

    mapping(address => uint256) public balances;   // 用户在本通道的 USDT 余额
    uint256 public totalBalances;                  // 全部用户余额合计（对账用）

    // ==================== 事件 ====================
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event ReleasedToGame(address indexed contract_, address indexed user, uint256 amount);
    event CreditedFromGame(address indexed contract_, address indexed user, uint256 amount);
    event ContractAllowed(address indexed contract_, bool allowed);
    event Paused();
    event Unpaused();
    event OwnerTransferred(address indexed oldOwner, address indexed newOwner);
    event TokenRescued(address indexed token, address indexed to, uint256 amount);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwnerErr(); _; }
    modifier onlyWhitelisted() { if (!allowedContracts[msg.sender]) revert NotWhitelistedErr(); _; }
    modifier whenNotPaused() { if (paused) revert PausedErr(); _; }
    modifier nonReentrant() { if (_locked) revert ReentrantErr(); _locked = true; _; _locked = false; }

    constructor(address _usdt, address _owner) {
        if (_usdt == address(0) || _owner == address(0)) revert ZeroAddrErr();
        usdt = IERC20(_usdt);
        owner = _owner;
    }

    // ==================== 管理 ====================
    function transferOwnership(address n) external onlyOwner {
        if (n == address(0)) revert ZeroAddrErr();
        emit OwnerTransferred(owner, n);
        owner = n;
    }

    /// @notice 增删白名单业务合约。
    /// @dev 高信任操作：白名单成员可划动用户余额（见合约头注释），加入前必须审计。
    ///      建议 owner 为多签；移除时传 false 即可，不影响存量记账。
    function setAllowedContract(address c, bool allowed) external onlyOwner {
        if (c == address(0)) revert ZeroAddrErr();
        allowedContracts[c] = allowed;
        emit ContractAllowed(c, allowed);
    }

    function pause() external onlyOwner { paused = true; emit Paused(); }
    function unpause() external onlyOwner { paused = false; emit Unpaused(); }

    /// @notice 抢救误转的非 USDT 代币；USDT 任何时候不得被 owner 转走（偿付能力红线）。
    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert ZeroAddrErr();
        if (token == address(usdt)) revert UsdtRescueErr();
        IERC20(token).safeTransfer(to, amount);
        emit TokenRescued(token, to, amount);
    }

    // ==================== 用户：充值 / 提现（主钱包） ====================
    /// @notice 充值 USDT 进通道（主钱包交易；先 approve 本合约）。
    function deposit(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmountErr();
        usdt.safeTransferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        totalBalances += amount;
        emit Deposited(msg.sender, amount);
    }

    /// @notice 提现 USDT 到主钱包。全系统唯一需要主钱包动作的出口。
    function withdraw(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmountErr();
        if (balances[msg.sender] < amount) revert InsufficientBalanceErr();
        balances[msg.sender] -= amount;
        totalBalances -= amount;
        usdt.safeTransfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    // ==================== 游戏通道（仅白名单合约） ====================
    /// @notice 用户进场：扣通道余额，USDT 原子转给调用的业务合约。
    /// @dev 授权发生在业务合约层（如 GuessAccount 的主钱包 msg.sender 或会话密钥签名），
    ///      本合约只认"调用方在白名单内"，USDT 转给调用方（msg.sender）与其记账配套。
    function releaseToGame(address user, uint256 amount) external nonReentrant whenNotPaused onlyWhitelisted {
        if (amount == 0) revert ZeroAmountErr();
        if (balances[user] < amount) revert InsufficientBalanceErr();
        balances[user] -= amount;
        totalBalances -= amount;
        usdt.safeTransfer(msg.sender, amount);
        emit ReleasedToGame(msg.sender, user, amount);
    }

    /// @notice 用户出场：业务合约放 USDT 进来，记到用户通道余额（等待用户主钱包提现）。
    /// @dev 业务合约须预先 approve 本合约；transferFrom 与记账同一交易，原子完成。
    function creditFromGame(address user, uint256 amount) external nonReentrant whenNotPaused onlyWhitelisted {
        if (amount == 0) revert ZeroAmountErr();
        usdt.safeTransferFrom(msg.sender, address(this), amount);
        balances[user] += amount;
        totalBalances += amount;
        emit CreditedFromGame(msg.sender, user, amount);
    }

    // ==================== 对账 ====================
    /// @notice 合约 USDT 余额应恒 >= totalBalances（owner 不可动 USDT，正常恒等）。
    function solvent() external view returns (bool) {
        return usdt.balanceOf(address(this)) >= totalBalances;
    }
}
