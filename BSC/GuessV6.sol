// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev CCIP 接收端最小 Client 结构（Chainlink 官方 Any2EVMMessage 布局）
library Client {
    struct EVMTokenAmount { address token; uint256 amount; }
    struct Any2EVMMessage {
        bytes32 messageId;
        uint64 sourceChainSelector;
        bytes sender;
        bytes data;
        EVMTokenAmount[] destTokenAmounts;
    }
}

/// @notice GuessV6 对 GuessAccount（USDT 资金池 + 台账）的全部指令接口。
/// @dev GuessAccount 实现侧必须 onlyRules（仅本合约可调用），并维护如下资金桶：
///      balances（用户余额）/ betEscrow（在押注金）/ claimReserve（派奖储备）
///      / pool（滚存奖池账簿）/ rakeAcc / feeAcc / dividendAcc（ZC 质押分红桶）。
///      守恒要求：settleRound 必须满足 totalPayout + rake + fee + poolAfter == t + poolBefore。
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

/// @title GuessV6 — BSC 规则合约（接 RELAY / CCIP / Operator 三方输入）
/// @notice V6 双链架构的 BSC 侧规则中枢。本合约不持有 USDT，资金指令全部下发 GuessAccount。
///
///   输入三方：
///     1) RELAY（白名单 ×3）：下注窗口内押注登记 registerBets —— 每注扣 1 票进 betEscrow，
///        登记是 MegaETH 锚定的前置闸门（先 BSC 扣款、后 MegaETH 上链），3 Relay 并发幂等去重。
///     2) CCIP（唯一 Router + 固定源链/源合约）：MegaETH GuessSettleV6 的结算/流局/空局
///        【FTF 快消息 + 全终局慢消息】双消息。快消息记账（可继续玩），慢消息终审（解锁提现）。
///     3) OPERATOR：submitOperatorRoot 仅作链上数据的健康巡检，绝不作为记账依据；
///        与终局 Root 不一致 → 冻结；与 FTF 期 Root 不一致 → 仅告警（可能是源链重组瞬态）。
///
///   镜像纪律（防伪造的核心）：
///     - pool 连续性：poolBefore == poolMirror + poolBonus，逐轮链式咬合，任何一环伪造即断链。
///     - 公式一致性：t == betCount × ticketForPool(poolBefore)；rake == t×10%；
///       三分支（决胜 / <minSmallBets 小局 / 普通奖局）账务用与 MegaETH 完全相同的整数公式复算。
///     - 周期参数：周期内不变，跨周期沿 V5.8 快照纪律从 NEXT_* 升级，并与消息逐字比对。
///     - 注数对账：msg.betCount > 押注标记数 = 有未扣款注单上链（资金缺口）→ 立即冻结；
///       msg.betCount < 押注标记数 = Relay 丢注（资金在押无缺口）→ 告警后继续，多签事后退注。
///     - 双消息幂等：同轮重复投递必须逐字节一致；不一致 = 最高级事故 → 全局冻结 + 在账回滚。
///
///   提现闸门（供 GuessAccount 查询 withdrawalBlocked）：
///     lastActiveRid[user] 为用户最近押注轮；lastFinalRid 为全终局水位线（连续推进）。
///     有未终局活动的用户禁止提现 —— 这同时保证 FTF 记账的奖金在慢消息冲突时一定还在账上可回滚。
contract GuessV6 {
    // ==================== 自定义错误 ====================
    error ZeroAddrErr();
    error NotOwnerErr();
    error NotRelayErr();
    error NotOperatorErr();
    error NotMultisigErr();
    error ReentrantErr();
    error FrozenErr();
    error NotFrozenErr();
    error OutOfBoundsErr();
    error BadSlotErr();
    error WindowClosedErr();
    error SlotMismatchErr();
    error OldRoundErr();
    error AlreadyProcessedErr();
    error NotRouterErr();
    error BadSourceChainErr();
    error BadSenderErr();
    error BadMessageErr();
    error BadCycleErr();
    error ParamMismatchErr();
    error MirrorBreakErr();
    error FormulaErr();
    error WrongStateErr();
    error NotMarkedErr();
    error AlreadyClaimedErr();
    error BadProofErr();
    error ZeroErr();

    // ==================== 常量（与 MegaETH / V5.8 逐字一致） ====================
    uint64 public constant ROUND_DURATION = 10 minutes;
    uint64 public constant BET_WINDOW = 5 minutes;          // 第 0–5 分钟接单，之后拒单
    uint256 public constant RAKE_BPS = 1000;                // 10% 运营费
    uint256 public constant LADDER_LINE = 100_000;          // 升档线：pool >= 10万 × 票价
    uint256 public constant DIVIDEND_BPS = 150;             // 下注额 1.5% → ZC 质押分红（自 10% 运营费切出）
    uint256 public constant MAX_BATCH = 300;                // registerBets 单批上限

    // ==================== 普通奖参数（本周期 / 下周期，V5.8 快照纪律） ====================
    uint256 public SMALL_BPS = 4500;
    uint256 public MIN_SMALL_BETS = 10;
    uint256 public WIN_CAP_BPS = 3000;
    uint256 public NEXT_SMALL_BPS = 4500;
    uint256 public NEXT_MIN_SMALL_BETS = 10;
    uint256 public NEXT_WIN_CAP_BPS = 3000;

    // ==================== 轮状态 ====================
    // 0=None 1=SettleFast 2=SettleFinal 3=VoidFast 4=VoidFinal 5=EmptyFast 6=EmptyFinal
    struct RRound {
        uint8 status;
        bytes32 payloadHash;     // 首条消息 keccak256(data)：第二终局层级/重放必须逐字节一致
        bytes32 betRoot;
        bytes32 settlementRoot;
        uint64 settlePrice;
        uint64 bestDiff;
        bool burst;
        uint256 ticket;          // 押注登记时快照 ticketForPool(poolMirror)；消息侧复算必须相等
        uint256 t;
        uint256 totalPayout;
        uint256 betCount;
        uint256 markCount;       // 已押注扣款注数（3 Relay 去重后）
        uint256 claimPaid;       // 已领奖合计（<= totalPayout）
        uint256 refundPaid;      // 流局已退款合计
    }

    struct BetEntry {
        address player;
        uint64 guess;
        uint64 nonce;
    }

    // ==================== 角色与依赖 ====================
    address public owner;
    address public multisig;              // 72h 应急多签：解冻 / 冲突回滚 / 退未锚注 / 紧急水位
    address public operator;              // 链上数据巡检员（健康检查，无记账权）
    mapping(address => bool) public relays;
    IGuessAccountV6 public account;
    address public ccipRouter;            // BSC 唯一 CCIP Router
    uint64 public megaChainSelector;      // MegaETH 源链 selector
    address public megaSender;            // MegaETH GuessSettleV6 地址

    // ==================== 镜像账务状态 ====================
    uint256 public poolMirror;            // 与 MegaETH pool 逐轮咬合的镜像值
    uint256 public cycleId;               // 镜像周期号（构造时延续旧合约，如 45）
    bool public expectNewCycle;           // 决胜轮已落地，等待下一周期首轮（构造时 = true，对齐 MegaETH needNewCycle）
    bool public frozen;
    uint256 public freezeReason;          // 1=同轮载荷冲突 2=有未扣款注单上链 3=OperatorRoot 与终局 Root 不一致

    mapping(uint256 => RRound) public rounds;
    mapping(uint256 => uint64) public ridSlot;                 // rid → 格点（押注登记时锁定）
    mapping(bytes32 => uint8) public markState;                // betLeaf → 0 无 / 1 已押注扣款
    mapping(bytes32 => bool) public claimed;                   // settleLeaf 防重
    mapping(bytes32 => bool) public refunded;                  // betLeaf 流局退款防重
    mapping(uint256 => mapping(address => uint256)) public claimedAmount;  // 冲突回滚台账
    mapping(uint256 => bytes) public pendingPayload;           // 因事故冻结时暂存的消息体，解冻后 resume
    mapping(uint256 => bytes32) public opBetRoot;              // Operator 巡检 Root
    mapping(uint256 => bytes32) public opSettleRoot;
    mapping(uint256 => bool) public opRootSeen;

    // ==================== 提现闸门 ====================
    uint256 public lastFinalRid;                          // 全终局水位线（连续推进，可 poke）
    mapping(address => uint256) public lastActiveRid;     // 用户最近押注轮

    bool private _locked;

    // ==================== 事件 ====================
    event BetRegistered(uint256 indexed rid, bytes32 indexed leaf, address indexed player, uint64 guess, uint64 nonce);
    event BetRejected(uint256 indexed rid, address indexed player, uint64 guess, uint64 nonce); // 扣款失败：Relay 不得再提交 MegaETH
    event SettlementReceived(uint256 indexed rid, uint8 fin, uint256 t, uint256 totalPayout, uint256 poolAfter);
    event VoidReceived(uint256 indexed rid, uint8 fin, uint256 betCount, uint256 t);
    event EmptyReceived(uint256 indexed rid, uint8 fin);
    event RoundFinalized(uint256 indexed rid, uint8 newStatus);
    event CycleAdopted(uint256 indexed cycleId, uint256 smallBps, uint256 minSmallBets, uint256 winCapBps);
    event MarksExcessAlarm(uint256 indexed rid, uint256 markCount, uint256 betCount);   // Relay 丢注：多签事后退注
    event UnmarkedVoidAlarm(uint256 indexed rid, uint256 markCount, uint256 betCount);
    event MarksOnEmptyAlarm(uint256 indexed rid, uint256 markCount);
    event RootMismatchAlarm(uint256 indexed rid, bytes32 ccipBetRoot, bytes32 opBetRoot);
    event Frozen(uint256 indexed rid, uint256 reason);
    event Unfrozen();
    event WinClaimed(uint256 indexed rid, address indexed player, uint256 payout);
    event VoidRefunded(uint256 indexed rid, address indexed player, uint256 amount);
    event ClaimRolledBack(uint256 indexed rid, address indexed player, uint256 amount);
    event RollbackFailed(uint256 indexed rid, address indexed player, uint256 amount);
    event OperatorRootSubmitted(uint256 indexed rid, bytes32 betRoot, bytes32 settlementRoot);
    event AdminMarked(uint256 indexed rid, bytes32 leaf, address indexed player);
    event UnanchoredRefunded(uint256 indexed rid, address indexed player, uint256 amount);
    event RelayUpdated(address indexed relay, bool enabled);
    event OperatorUpdated(address indexed oldOp, address indexed newOp);
    event AccountUpdated(address indexed account);
    event CcipConfigUpdated(address router, uint64 selector, address sender);
    event MultisigUpdated(address indexed oldMs, address indexed newMs);
    event WatermarkForced(uint256 rid);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwnerErr(); _; }
    modifier onlyRelay() { if (!relays[msg.sender]) revert NotRelayErr(); _; }
    modifier onlyOperator() { if (msg.sender != operator) revert NotOperatorErr(); _; }
    modifier onlyMultisig() { if (msg.sender != multisig) revert NotMultisigErr(); _; }
    modifier nonReentrant() { if (_locked) revert ReentrantErr(); _locked = true; _; _locked = false; }

    constructor(
        address _ccipRouter,
        uint64 _megaChainSelector,
        address _megaSender,
        address _multisig,
        uint256 _ridWatermark,     // 首个 MegaETH 轮次号 - 1（续接旧合约编号体系）
        uint256 _cycleId           // 延续旧合约周期号（如 45）
    ) {
        if (_ccipRouter == address(0) || _megaSender == address(0) || _multisig == address(0)) revert ZeroAddrErr();
        owner = msg.sender;
        ccipRouter = _ccipRouter;
        megaChainSelector = _megaChainSelector;
        megaSender = _megaSender;
        multisig = _multisig;
        lastFinalRid = _ridWatermark;
        cycleId = _cycleId;
        expectNewCycle = true;     // 对齐 MegaETH needNewCycle 初始值
    }

    // ==================== 管理 ====================
    function transferOwnership(address n) external onlyOwner {
        if (n == address(0)) revert ZeroAddrErr();
        owner = n;
    }

    function setRelay(address r, bool enabled) external onlyOwner {
        if (r == address(0)) revert ZeroAddrErr();
        relays[r] = enabled;
        emit RelayUpdated(r, enabled);
    }

    function setOperator(address n) external onlyOwner {
        if (n == address(0)) revert ZeroAddrErr();
        emit OperatorUpdated(operator, n);
        operator = n;
    }

    function setMultisig(address n) external onlyOwner {
        if (n == address(0)) revert ZeroAddrErr();
        emit MultisigUpdated(multisig, n);
        multisig = n;
    }

    function setAccount(address a) external onlyOwner {
        if (a == address(0)) revert ZeroAddrErr();
        account = IGuessAccountV6(a);
        emit AccountUpdated(a);
    }

    function setCcipConfig(address router, uint64 selector, address sender) external onlyOwner {
        if (router == address(0) || sender == address(0)) revert ZeroAddrErr();
        ccipRouter = router;
        megaChainSelector = selector;
        megaSender = sender;
        emit CcipConfigUpdated(router, selector, sender);
    }

    /// @notice 下一周期普通奖参数（与 V5.8 setSmallPrizeConfig 相同边界；MegaETH 侧需同值设置）
    function setSmallPrizeConfig(uint256 minSmallBets, uint256 smallBps, uint256 winCapBps) external onlyOwner {
        if (minSmallBets < 10) revert OutOfBoundsErr();
        if (smallBps < 2000 || smallBps > 8000) revert OutOfBoundsErr();
        if (winCapBps < 300 || winCapBps > 6000) revert OutOfBoundsErr();
        if (smallBps * 10 < winCapBps * 13) revert OutOfBoundsErr();
        NEXT_MIN_SMALL_BETS = minSmallBets;
        NEXT_SMALL_BPS = smallBps;
        NEXT_WIN_CAP_BPS = winCapBps;
    }

    // ==================== RELAY：押注登记（BSC 扣款闸门，先于 MegaETH 锚定） ====================
    /// @notice 下注窗口内批量登记押注：每注扣 1 票进 betEscrow，并关闭用户提现闸门。
    /// @dev Relay 流水线纪律：先调用本函数，确认 BetRegistered 后再向 MegaETH 提交锚定；
    ///      BetRejected（余额不足等）的注单绝不得上链 —— 否则结算时 betCount > markCount 触发全局冻结。
    ///      3 Relay 并发重复提交同一注：按 betLeaf 幂等跳过，不 revert。
    function registerBets(uint256 rid, uint64 slotStart, BetEntry[] calldata entries)
        external nonReentrant onlyRelay
    {
        if (frozen) revert FrozenErr();
        if (entries.length == 0 || entries.length > MAX_BATCH) revert OutOfBoundsErr();
        if (slotStart % ROUND_DURATION != 0) revert BadSlotErr();
        if (block.timestamp < slotStart || block.timestamp >= uint256(slotStart) + BET_WINDOW) revert WindowClosedErr();
        RRound storage r = rounds[rid];
        if (r.status != 0) revert AlreadyProcessedErr();
        if (rid <= lastFinalRid) revert OldRoundErr();
        uint64 prevSlot = ridSlot[rid];
        if (prevSlot == 0) ridSlot[rid] = slotStart;
        else if (prevSlot != slotStart) revert SlotMismatchErr();

        uint256 ticket = r.ticket;
        if (ticket == 0) {
            // 窗口内 pool 不变（上一轮结算早已落地），此刻定价 == MegaETH 关窗定价
            ticket = ticketForPool(poolMirror);
            r.ticket = ticket;
        }

        uint256 marks = r.markCount;
        for (uint256 i = 0; i < entries.length; i++) {
            BetEntry calldata e = entries[i];
            bytes32 leaf = _betLeaf(rid, e.player, e.guess, e.nonce);
            if (markState[leaf] != 0) continue;                 // 3 Relay 并发去重：幂等跳过
            try account.debitBet(e.player, ticket, leaf) {
                markState[leaf] = 1;
                marks++;
                if (lastActiveRid[e.player] < rid) lastActiveRid[e.player] = rid;
                emit BetRegistered(rid, leaf, e.player, e.guess, e.nonce);
            } catch {
                emit BetRejected(rid, e.player, e.guess, e.nonce);
            }
        }
        r.markCount = marks;
    }

    // ==================== OPERATOR：Root 健康巡检（绝不作为记账依据） ====================
    /// @notice Operator 从 MegaETH 链上数据（BetPlaced 事件/getBet 顺序）复算的 Root，仅作早期预警。
    /// @dev 与 CCIP 终局 Root 不一致 → 全局冻结；与 FTF 期 Root 不一致 → 仅告警（源链可能重组）。
    function submitOperatorRoot(uint256 rid, bytes32 betRoot_, bytes32 settlementRoot_)
        external nonReentrant onlyOperator
    {
        if (frozen) revert FrozenErr();
        opRootSeen[rid] = true;
        opBetRoot[rid] = betRoot_;
        opSettleRoot[rid] = settlementRoot_;
        emit OperatorRootSubmitted(rid, betRoot_, settlementRoot_);

        RRound storage r = rounds[rid];
        if (r.status == 0) return;                              // CCIP 消息未到：先存档，事后人工比对
        if (betRoot_ == r.betRoot && settlementRoot_ == r.settlementRoot) return;
        if (r.status == 2 || r.status == 4 || r.status == 6) {
            _freeze(rid, 3);                                    // 与终局 Root 冲突：最高级事故
        } else {
            emit RootMismatchAlarm(rid, r.betRoot, betRoot_);   // FTF 期内：告警观察
        }
    }

    // ==================== CCIP：接收 MegaETH 结算 / 流局 / 空局 双消息 ====================
    function ccipReceive(Client.Any2EVMMessage calldata m) external nonReentrant {
        if (msg.sender != ccipRouter) revert NotRouterErr();
        if (m.sourceChainSelector != megaChainSelector) revert BadSourceChainErr();
        if (abi.decode(m.sender, (address)) != megaSender) revert BadSenderErr();
        if (frozen) revert FrozenErr();                         // 冻结期间拒收：消息留在 CCIP 待人工恢复
        _process(m.data);
    }

    function _process(bytes memory data) internal {
        (
            uint8 msgType, uint8 fin, uint256 rid, uint256 msgCycleId,
            bytes32 betRoot_, bytes32 settlementRoot_, uint64 settlePrice_, uint64 bestDiff_, bool burst_,
            uint256 betCount_, uint256 t_, uint256 totalPayout_, uint256 rake_,
            uint256 poolBefore_, uint256 poolAfter_, uint256 fee_,
            uint256 minSmallBets_, uint256 smallBps_, uint256 winCapBps_, uint256 poolBonus_
        ) = abi.decode(data, (
            uint8, uint8, uint256, uint256,
            bytes32, bytes32, uint64, uint64, bool,
            uint256, uint256, uint256, uint256,
            uint256, uint256, uint256,
            uint256, uint256, uint256, uint256
        ));
        if (msgType > 2 || fin > 1) revert BadMessageErr();

        RRound storage r = rounds[rid];
        bytes32 ph = keccak256(data);

        if (r.status != 0) {
            // 重复投递 / 第二终局层级：必须逐字节一致，否则同轮两个"权威结果"= 最高级事故
            if (r.payloadHash != ph) { _freeze(rid, 1); return; }
            if (fin == 1 && (r.status == 1 || r.status == 3 || r.status == 5)) {
                r.status += 1;
                _advanceWatermark();
                emit RoundFinalized(rid, r.status);
            }
            return;
        }

        r.payloadHash = ph;
        if (msgType == 0) {
            _verifySettlement(data, rid, r, msgCycleId, betRoot_, settlementRoot_, settlePrice_, bestDiff_, burst_,
                betCount_, t_, totalPayout_, rake_, poolBefore_, poolAfter_, fee_,
                minSmallBets_, smallBps_, winCapBps_, poolBonus_);
            r.status = fin == 0 ? 1 : 2;
            emit SettlementReceived(rid, fin, t_, totalPayout_, poolAfter_);
        } else if (msgType == 1) {
            _verifyVoid(rid, r, msgCycleId, betRoot_, settlementRoot_, burst_,
                betCount_, t_, totalPayout_, rake_, poolBefore_, poolAfter_, fee_,
                minSmallBets_, smallBps_, winCapBps_, poolBonus_);
            r.status = fin == 0 ? 3 : 4;
            emit VoidReceived(rid, fin, betCount_, t_);
        } else {
            _verifyEmpty(rid, r, msgCycleId, betCount_, t_, totalPayout_, rake_,
                poolBefore_, poolAfter_, fee_, burst_, poolBonus_);
            r.status = fin == 0 ? 5 : 6;
            emit EmptyReceived(rid, fin);
        }
        if (fin == 1) _advanceWatermark();
    }

    /// @dev 结算消息镜像校验 + 账务落地。
    function _verifySettlement(
        bytes memory data, uint256 rid, RRound storage r, uint256 msgCycleId,
        bytes32 betRoot_, bytes32 settlementRoot_, uint64 settlePrice_, uint64 bestDiff_, bool burst_,
        uint256 betCount_, uint256 t_, uint256 totalPayout_, uint256 rake_,
        uint256 poolBefore_, uint256 poolAfter_, uint256 fee_,
        uint256 minSmallBets_, uint256 smallBps_, uint256 winCapBps_, uint256 poolBonus_
    ) internal {
        _adoptCycle(msgCycleId, minSmallBets_, smallBps_, winCapBps_);

        // —— pool 链式连续性（含周期首轮赞助注入） ——
        if (poolBefore_ != poolMirror + poolBonus_) revert MirrorBreakErr();

        // —— 票价与总额（与 MegaETH 同一整数公式） ——
        uint256 ticket = ticketForPool(poolBefore_);
        if (t_ != betCount_ * ticket) revert FormulaErr();
        if (r.ticket != 0 && r.ticket != ticket) revert FormulaErr();
        if (rake_ != t_ * RAKE_BPS / 10000) revert FormulaErr();

        // —— 注数对账：有未扣款注单上链 = 资金缺口，立即冻结（消息暂存，和解后 resume 重放） ——
        if (betCount_ > r.markCount) { pendingPayload[rid] = data; _freeze(rid, 2); return; }
        if (betCount_ < r.markCount) emit MarksExcessAlarm(rid, r.markCount, betCount_);

        // —— 三分支账务复算 ——
        if (burst_) {
            // 决胜：总池（历史池 + 本局 90%）= 派奖 + 剩余 fee；pool 归零，周期终结
            if (poolAfter_ != 0) revert FormulaErr();
            if (fee_ + totalPayout_ != poolBefore_ + t_ - rake_) revert FormulaErr();
        } else if (betCount_ < minSmallBets_) {
            // 小局：无普通奖，90% 滚存 / 10% 运营费
            if (totalPayout_ != 0 || fee_ != 0) revert FormulaErr();
            if (poolAfter_ != poolBefore_ + t_ - rake_) revert FormulaErr();
        } else {
            // 普通奖局：smallFund = t×SMALL_BPS；未派完滚存
            uint256 small = t_ * smallBps_ / 10000;
            if (totalPayout_ > small) revert FormulaErr();
            if (fee_ != 0) revert FormulaErr();
            if (poolAfter_ != poolBefore_ + t_ - rake_ - totalPayout_) revert FormulaErr();
            uint256 cap = betCount_ * winCapBps_ / 10000;
            uint256 base = ticket * 101 / 100;
            if (small < base * cap) revert FormulaErr();        // SmallFund 不变式
        }

        // —— 落地：镜像推进 + 指令 GuessAccount 分桶 ——
        poolMirror = poolAfter_;
        r.ticket = ticket;
        r.betRoot = betRoot_;
        r.settlementRoot = settlementRoot_;
        r.settlePrice = settlePrice_;
        r.bestDiff = bestDiff_;
        r.burst = burst_;
        r.t = t_;
        r.totalPayout = totalPayout_;
        r.betCount = betCount_;
        if (burst_) expectNewCycle = true;

        uint256 dividend = t_ * DIVIDEND_BPS / 10000;           // 1.5% 下注额，自 10% 运营费切出
        account.settleRound(rid, t_, totalPayout_, rake_, dividend, fee_, poolBefore_, poolAfter_);
    }

    /// @dev 流局消息镜像校验：pool 不动、费用为零；退款凭 BetRoot proof 逐叶办理。
    function _verifyVoid(
        uint256 rid, RRound storage r, uint256 msgCycleId,
        bytes32 betRoot_, bytes32 settlementRoot_, bool burst_,
        uint256 betCount_, uint256 t_, uint256 totalPayout_, uint256 rake_,
        uint256 poolBefore_, uint256 poolAfter_, uint256 fee_,
        uint256 minSmallBets_, uint256 smallBps_, uint256 winCapBps_, uint256 poolBonus_
    ) internal {
        _adoptCycle(msgCycleId, minSmallBets_, smallBps_, winCapBps_);
        if (poolBefore_ != poolMirror + poolBonus_) revert MirrorBreakErr();
        if (poolAfter_ != poolBefore_) revert FormulaErr();     // 流局 pool 不变
        if (totalPayout_ != 0 || rake_ != 0 || fee_ != 0) revert FormulaErr();
        if (settlementRoot_ != bytes32(0) || burst_) revert FormulaErr();

        uint256 ticket = ticketForPool(poolBefore_);
        if (t_ != betCount_ * ticket) revert FormulaErr();
        if (r.ticket != 0 && r.ticket != ticket) revert FormulaErr();

        // 未押注扣款的上链注单在流局下无任何领取路径，不构成资金缺口：仅告警
        if (betCount_ > r.markCount) emit UnmarkedVoidAlarm(rid, r.markCount, betCount_);

        r.ticket = ticket;                                      // 退款定价依据
        r.betRoot = betRoot_;
        r.t = t_;
        r.betCount = betCount_;
        account.voidRound(rid);
    }

    /// @dev 空局心跳：只推进终局水位线；不得携带任何账务。
    function _verifyEmpty(
        uint256 rid, RRound storage r, uint256 msgCycleId,
        uint256 betCount_, uint256 t_, uint256 totalPayout_, uint256 rake_,
        uint256 poolBefore_, uint256 poolAfter_, uint256 fee_, bool burst_, uint256 poolBonus_
    ) internal {
        if (msgCycleId != cycleId) revert BadCycleErr();        // 空局不启动新周期
        if (poolBefore_ != poolMirror || poolAfter_ != poolMirror || poolBonus_ != 0) revert MirrorBreakErr();
        if (betCount_ != 0 || t_ != 0 || totalPayout_ != 0 || rake_ != 0 || fee_ != 0 || burst_) revert FormulaErr();
        if (r.markCount > 0) emit MarksOnEmptyAlarm(rid, r.markCount);  // 押注了却空局：多签事后退注
    }

    /// @dev 周期镜像：同周期参数必须逐字相等；跨周期（+1）要求前一轮为决胜，并按 NEXT_* 快照。
    function _adoptCycle(uint256 msgCycleId, uint256 minSmallBets_, uint256 smallBps_, uint256 winCapBps_) internal {
        if (msgCycleId == cycleId) {
            if (minSmallBets_ != MIN_SMALL_BETS || smallBps_ != SMALL_BPS || winCapBps_ != WIN_CAP_BPS)
                revert ParamMismatchErr();
        } else if (msgCycleId == cycleId + 1) {
            if (!expectNewCycle) revert BadCycleErr();
            MIN_SMALL_BETS = NEXT_MIN_SMALL_BETS;
            SMALL_BPS = NEXT_SMALL_BPS;
            WIN_CAP_BPS = NEXT_WIN_CAP_BPS;
            cycleId = msgCycleId;
            expectNewCycle = false;
            if (minSmallBets_ != MIN_SMALL_BETS || smallBps_ != SMALL_BPS || winCapBps_ != WIN_CAP_BPS)
                revert ParamMismatchErr();
            emit CycleAdopted(msgCycleId, SMALL_BPS, MIN_SMALL_BETS, WIN_CAP_BPS);
        } else {
            revert BadCycleErr();
        }
        // 防御性边界（对齐 V5.8 owner 侧校验；防对端被错误配置污染）
        if (minSmallBets_ < 10) revert OutOfBoundsErr();
        if (smallBps_ < 2000 || smallBps_ > 8000) revert OutOfBoundsErr();
        if (winCapBps_ < 300 || winCapBps_ > 6000) revert OutOfBoundsErr();
        if (smallBps_ * 10 < winCapBps_ * 13) revert OutOfBoundsErr();
    }

    /// @dev 终局水位线连续推进：空洞（消息迟到）时停下，由 pokeWatermark 后续补推。
    function _advanceWatermark() internal {
        while (true) {
            uint8 st = rounds[lastFinalRid + 1].status;
            if (st == 2 || st == 4 || st == 6) lastFinalRid += 1;
            else break;
        }
    }

    /// @notice 水位线空洞补推（permissionless）：当慢消息乱序到达导致空洞时，任何人可触发推进。
    function pokeWatermark() external {
        _advanceWatermark();
    }

    // ==================== 用户：领奖 / 流局退款 ====================
    /// @notice 凭结算叶 proof 领奖。FTF 快消息落地即可领（可继续玩）；提现须等慢消息终审。
    /// @dev 叶 = keccak256(rid, player, nonce, payout)，与 MegaETH 造叶逐字节一致。
    ///      要求该注已在 BSC 押注扣款：未扣款的"幽灵中奖注"（事故场景）无权领取。
    function claimWin(uint256 rid, address player, uint64 guess, uint64 nonce, uint256 payout, bytes32[] calldata proof)
        external nonReentrant
    {
        if (frozen) revert FrozenErr();
        RRound storage r = rounds[rid];
        if (r.status != 1 && r.status != 2) revert WrongStateErr();
        if (payout == 0) revert ZeroErr();
        bytes32 betLeaf = _betLeaf(rid, player, guess, nonce);
        if (markState[betLeaf] != 1) revert NotMarkedErr();
        bytes32 leaf = keccak256(abi.encodePacked(rid, player, nonce, payout));
        if (claimed[leaf]) revert AlreadyClaimedErr();
        if (!_verifyProof(proof, r.settlementRoot, leaf)) revert BadProofErr();

        claimed[leaf] = true;
        claimedAmount[rid][player] += payout;                   // 冲突回滚台账
        uint256 paid = r.claimPaid + payout;
        if (paid > r.totalPayout) revert FormulaErr();          // 防御：派奖储备不超支
        r.claimPaid = paid;
        account.payWin(player, payout);
        emit WinClaimed(rid, player, payout);
    }

    /// @notice 流局退款：凭 BetRoot proof 全额返还 1 票（含 10% 运营费部分，流局不收费）。
    function claimVoidRefund(uint256 rid, address player, uint64 guess, uint64 nonce, bytes32[] calldata proof)
        external nonReentrant
    {
        if (frozen) revert FrozenErr();
        RRound storage r = rounds[rid];
        if (r.status != 3 && r.status != 4) revert WrongStateErr();
        bytes32 leaf = _betLeaf(rid, player, guess, nonce);
        if (markState[leaf] != 1) revert NotMarkedErr();
        if (refunded[leaf]) revert AlreadyClaimedErr();
        if (!_verifyProof(proof, r.betRoot, leaf)) revert BadProofErr();

        refunded[leaf] = true;
        r.refundPaid += r.ticket;
        account.refundEscrow(player, r.ticket);
        emit VoidRefunded(rid, player, r.ticket);
    }

    // ==================== 提现闸门（GuessAccount 调用） ====================
    /// @notice 二进制闸门：有未终局活动（押注/领奖）的用户禁止提现；全局冻结时全员禁止。
    function withdrawalBlocked(address user) external view returns (bool) {
        if (frozen) return true;
        return lastActiveRid[user] > lastFinalRid;
    }

    // ==================== 事故处理（72h 应急多签） ====================
    function _freeze(uint256 rid, uint256 reason) internal {
        frozen = true;
        freezeReason = reason;
        emit Frozen(rid, reason);
    }

    function unfreeze() external onlyMultisig {
        if (!frozen) revert NotFrozenErr();
        frozen = false;
        emit Unfrozen();
    }

    /// @notice "有未扣款注单上链"事故的和解：多签核实后补登记（扣款进 betEscrow），再解冻 resume。
    /// @dev ticket 由多签从事故消息（t / betCount）读出传入；与登记快照不一致时拒绝。
    function adminMark(uint256 rid, address player, uint64 guess, uint64 nonce, uint256 ticket) external onlyMultisig {
        RRound storage r = rounds[rid];
        if (r.ticket != 0 && r.ticket != ticket) revert FormulaErr();
        bytes32 leaf = _betLeaf(rid, player, guess, nonce);
        if (markState[leaf] != 0) revert AlreadyClaimedErr();
        account.debitBet(player, ticket, leaf);                 // 余额不足则 revert，需先运营处置
        if (r.ticket == 0) r.ticket = ticket;
        markState[leaf] = 1;
        r.markCount += 1;
        if (lastActiveRid[player] < rid) lastActiveRid[player] = rid;
        emit AdminMarked(rid, leaf, player);
    }

    /// @notice 解冻后重放被冻结暂存的消息（权限放开，载荷已由链上暂存保证未篡改）。
    function resume(uint256 rid) external nonReentrant {
        if (frozen) revert FrozenErr();
        bytes memory data = pendingPayload[rid];
        if (data.length == 0) revert BadMessageErr();
        delete pendingPayload[rid];
        _process(data);
    }

    /// @notice 冲突事故的回滚：把指定玩家在问题轮已领取的奖金扣回派奖储备。
    /// @dev 提现闸门保证这些奖金未离场；若玩家已把奖金输回系统（余额不足），该笔跳过并告警，
    ///      缺口由后续冻结轮次的在押资金/运营费覆盖，属人工清算范畴。
    function rollbackClaims(uint256 rid, address[] calldata players) external onlyMultisig nonReentrant {
        if (!frozen) revert NotFrozenErr();
        RRound storage r = rounds[rid];
        for (uint256 i = 0; i < players.length; i++) {
            address p = players[i];
            uint256 amt = claimedAmount[rid][p];
            if (amt == 0) continue;
            try account.rollbackToReserve(p, amt) {
                claimedAmount[rid][p] = 0;
                r.claimPaid -= amt;
                emit ClaimRolledBack(rid, p, amt);
            } catch {
                emit RollbackFailed(rid, p, amt);
            }
        }
    }

    /// @notice Relay 丢注退注：已押注扣款但从未锚定上链（不在 BetRoot）的注单，多签核实后退 1 票。
    /// @dev 仅用于 MarksExcess / MarksOnEmpty 告警场景；多签须在链下核实该叶确不在 BetRoot。
    function refundUnanchored(uint256 rid, address player, uint64 guess, uint64 nonce)
        external onlyMultisig nonReentrant
    {
        RRound storage r = rounds[rid];
        if (r.status == 0) revert WrongStateErr();              // 轮次须有处理结果
        bytes32 leaf = _betLeaf(rid, player, guess, nonce);
        if (markState[leaf] != 1) revert NotMarkedErr();
        if (refunded[leaf]) revert AlreadyClaimedErr();
        refunded[leaf] = true;
        r.refundPaid += r.ticket;
        account.refundEscrow(player, r.ticket);
        emit UnanchoredRefunded(rid, player, r.ticket);
    }

    /// @notice MegaETH 卡死（消息永不到达）灾难的逃生：多签强制推进终局水位线。
    /// @dev 仅在确认源链对应轮次永远不会有消息时使用；推进后相关用户提现闸门解锁。
    function forceWatermark(uint256 rid) external onlyMultisig {
        if (rid <= lastFinalRid) revert OldRoundErr();
        lastFinalRid = rid;
        emit WatermarkForced(rid);
    }

    // ==================== 查询 / 公开复算 ====================
    /// @notice 票价阶梯（与 MegaETH / V5.8 ticketForPool 逐字一致）：1→2→5→10→20→50…
    function ticketForPool(uint256 p) public pure returns (uint256) {
        uint256 mantissa = 1;
        uint256 exp = 0;
        while (p >= LADDER_LINE * mantissa * (10 ** exp) * 1e18) {
            if (mantissa == 1) mantissa = 2;
            else if (mantissa == 2) mantissa = 5;
            else { mantissa = 1; exp += 1; }
        }
        return mantissa * (10 ** exp) * 1e18;
    }

    /// @notice BetRoot 叶子（与 MegaETH GuessBetV6._betLeaf 逐字节一致）
    function betLeafOf(uint256 rid, address player, uint64 guess, uint64 nonce) external pure returns (bytes32) {
        return _betLeaf(rid, player, guess, nonce);
    }

    /// @notice 结算叶（与 MegaETH 造叶逐字节一致）
    function settleLeafOf(uint256 rid, address player, uint64 nonce, uint256 payout) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(rid, player, nonce, payout));
    }

    function getRoundCore(uint256 rid) external view returns (
        uint8 status, bytes32 betRoot, bytes32 settlementRoot, bool burst,
        uint256 ticket, uint256 t, uint256 totalPayout, uint256 betCount, uint256 markCount
    ) {
        RRound storage r = rounds[rid];
        return (r.status, r.betRoot, r.settlementRoot, r.burst, r.ticket, r.t, r.totalPayout, r.betCount, r.markCount);
    }

    // ==================== 内部 ====================
    function _betLeaf(uint256 rid, address player, uint64 guess, uint64 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(rid, player, guess, nonce));
    }

    /// @dev sorted-pair Merkle proof（与 MegaETH MerkleBuilder 同一协议）
    function _verifyProof(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            h = h < p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
        }
        return h == root;
    }
}
