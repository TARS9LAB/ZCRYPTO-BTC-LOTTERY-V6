// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MerkleBuilder.sol";

interface IAggregatorV3 {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function getRoundData(uint80) external view returns (uint80, int256, uint256, uint256, uint80);
    function decimals() external view returns (uint8);
}

interface IGuessBetV6 {
    function getRoundCore(uint256 rid) external view returns (
        uint64 bettingClose, uint64 priceTime, uint8 state, uint256 betCount, bytes32 betRoot
    );
    function getBet(uint256 rid, uint256 index) external view
        returns (address player, uint64 guess, uint64 nonce);
}

interface IVRFCoordinator {
    struct RandomWordsRequest {
        bytes32 keyHash;
        uint256 subId;
        uint16 requestConfirmations;
        uint32 callbackGasLimit;
        uint32 numWords;
        bytes extraArgs;
    }
    function requestRandomWords(RandomWordsRequest calldata req) external returns (uint256);
}

/// @dev CCIP Router 最小接口（Chainlink 官方 Client 结构）
library Client {
    struct EVMTokenAmount { address token; uint256 amount; }
    struct EVM2AnyMessage {
        bytes receiver;
        bytes data;
        EVMTokenAmount[] tokenAmounts;
        address feeToken;   // address(0)=原生币
        bytes extraArgs;
    }
}

interface IRouterClient {
    function ccipSend(uint64 destinationChainSelector, Client.EVM2AnyMessage calldata message)
        external payable returns (bytes32 messageId);
    function getFee(uint64 destinationChainSelector, Client.EVM2AnyMessage calldata message)
        external view returns (uint256 fee);
}

/// @title GuessSettleV6 — MegaETH 链上结算镜像合约
/// @notice V6 核心变化：结算由【链上分步计算】产生，取代 V5 的“Operator 申报 + 挑战举证”。
///
///   流程（全部 permissionless，Keeper/任何人均可触发）：
///     beginRound        读取 GuessBetV6 已关窗轮次，建立结算上下文
///     anchorPrice       锚定 Chainlink “priceTime 前最后一跳”（沿用 V5 的下一 Tick 夹逼验证）
///     requestVrf        达门槛且非强制决胜位时请求 VRF（沿用 V5 三路决胜）
///     computeDiffs      游标分批计算全部注单 diff，聚合 bestDiff/冠军/圈/diff 分布
///     finalizeDiffs     决胜判定 + 拆账口径确定（10% 运营费 / 普通奖基金 / 滚存）
///     sortDiffs         链上插入排序 diff 列表（游标分步）
///     buildGroups       沿升序 diff 分组：普通奖档位与每注派奖 / 决胜圈档与冠军份额
///     buildLeaves       为每笔注单生成结算叶 (rid, player, nonce, payout)
///     buildSettlementRoot  分步构建 SettlementRoot
///     publish           经 CCIP 向 BSC GuessV6 发送【FTF 快消息 + 全终局慢消息】双消息
///
///   统一票面制（沿用 V5.8）：每注 1 张票，stake = 当轮 ticket，注单不带金额。
///   BSC 侧凭结算叶 proof 逐笔记账：扣 stake(=ticket)、入 payout，资金完全闭合。
///
///   安全约定：
///     - 本合约不持有资金；Root 与账务摘要是唯一输出。
///     - BSC 侧必须用【完全相同的整数公式】复算账务，否则守恒校验失败（镜像纪律）。
///     - 流局（Oracle 死亡 / VRF 超时 / 各阶段卡死超 FINAL_GRACE）→ voidInit → CCIP 流局消息。
contract GuessSettleV6 is MerkleBuilder {
    // ==================== 自定义错误 ====================
    error ZeroAddrErr();
    error NotOwnerErr();
    error WrongStateErr();
    error TooEarlyErr();
    error NoBetsErr();
    error AlreadyRequestedErr();
    error WaitVRFErr();
    error BadWordsErr();
    error NotCoordinatorErr();
    error UnknownRequestErr();
    error AlreadyFulfilledErr();
    error FinalRoundNoVRFErr();
    error PoolBelowVRFThresholdErr();
    error NoDataAtRoundErr();
    error BadAnswerErr();
    error PriceAfterTargetErr();
    error StalePriceErr();
    error NextRoundNotAfterTargetErr();
    error FeedDecimalsNotEqual8Err();
    error SmallFundInvariantErr();
    error StakeMismatchErr();
    error VoidConditionsNotMetErr();
    error CcipNotConfiguredErr();
    error CcipFeeErr();
    error VRFRequestFailedErr();
    error FinalizedErr();
    error OutOfBoundsErr();

    // ==================== 常量（沿用 V5.8 口径） ====================
    uint64 public constant CIRCLE_TOLERANCE = 100000;      // 决胜圈：diff <= 10.0000 U
    uint256 public constant RAKE_BPS = 1000;               // 10% 运营费
    uint256 public constant CHAMP_BPS = 6000;              // 决胜且圈内有人：总池 60% 冠军
    uint256 public constant CIRCLE_BPS = 4000;             // 决胜圈奖 40%
    uint256 public constant LADDER_LINE = 100_000;         // 升档线：pool >= 10万 × 票价
    uint256 public constant BASE_TICKET = 1 ether;         // 票面 1 U（18 位，与 BSC USDT 口径一致）
    uint256 public constant MIN_CYCLE_ROUNDS = 1;
    uint256 public constant MAX_CYCLE_ROUNDS = 100_000;
    uint64 public constant ORACLE_STALE = 6 hours;
    uint64 public constant FINAL_GRACE = 24 hours;         // 卡死逃生阈值
    uint64 public constant VRF_GRACE = 2 hours;
    uint8  public constant SMALL_TIER_NONE = 255;

    // 普通奖档界与权重（与 V5.8 完全一致）
    uint16[6] public TIER_CUM = [1, 4, 14, 44, 144, 344];
    uint16[7] public TIER_W = [1500, 600, 250, 70, 12, 2, 0];
    uint16[7] public BTIER_W = [1500, 600, 250, 70, 12, 2, 1];

    // ==================== 普通奖参数（本周期 / 下周期，沿用 V5.8 快照纪律） ====================
    uint256 public SMALL_BPS = 4500;
    uint256 public MIN_SMALL_BETS = 10;
    uint256 public WIN_CAP_BPS = 3000;
    uint256 public NEXT_SMALL_BPS = 4500;
    uint256 public NEXT_MIN_SMALL_BETS = 10;
    uint256 public NEXT_WIN_CAP_BPS = 3000;

    // ==================== 结算轮状态 ====================
    // 0=None 1=AwaitPrice 2=Diffs 3=Sort 4=Groups 5=GroupsAssign(决胜第二遍)
    // 6=Leaves 7=Root 8=Ready 9=Published 10=Voiding 11=Voided 12=Empty 13=EmptyPublished
    struct SRound {
        uint8 state;
        uint64 priceTime;
        uint64 settlePrice;
        uint64 bestDiff;
        uint64 stateEnteredAt;
        uint256 ticket;
        uint256 betCount;     // 注数 = 票数（统一票面）
        uint256 t;            // 总投注额 = betCount × ticket
        uint256 poolBefore;
        uint256 poolBonus;    // 本论结算时新周期快照注入的赞助（BSC 镜像连续性校验用）
        uint256 rake;
        uint256 smallFund;
        uint256 smallPaid;
        uint256 totalPayout;
        uint256 fee;          // 决胜轮剩余（归运营）
        uint256 champCount;   // 冠军注数
        uint256 circleCount;  // 圈内注数
        uint256 groupCount;
        uint256 winnerGroupCount;
        uint64 smallCutoff;
        uint8 smallCutoffMode; // 0=未封口 1=COLLISION 2=EXACT
        bool burst;
        bool vrfReady;
        uint256 vrfWord;
        uint256 vrfRequestId;
        bytes32 betRoot;
        bytes32 settlementRoot;
        // —— 游标 ——
        uint256 diffCursor;
        uint256 sortI;
        uint256 sortJ;
        uint64 sortKey;
        uint256 groupCursor;
        uint256 assignCursor;
        uint256 leafCursor;
        uint256 prefixCount;  // 普通奖：已入选注数
        uint256 winnerIdx;
        uint256 circleSeq;
        uint256 stakeSum;
    }

    // ==================== 全局账务（BSC GuessV6 镜像复算对象） ====================
    uint256 public pool;
    uint256 public totalRake;
    uint256 public cycleId = 45;                    // 延续旧合约
    uint256 public cycleRoundCount;
    uint256 public cycleMaxRounds;
    uint256 public nextCycleRounds = 6;
    uint256 public nextMinVrfJackpot;
    uint256 public currentMinVrfJackpot;
    uint256 public nextCyclePoolBonus;
    bool public needNewCycle = true;

    // ==================== 依赖 ====================
    address public owner;
    IGuessBetV6 public betContract;
    IAggregatorV3 public feed;
    IVRFCoordinator public vrfCoordinator;           // 可为 0：VRF 不可用时随机决胜路径关闭
    bytes32 public vrfKeyHash;
    uint256 public vrfSubId;
    uint32 public vrfCallbackGasLimit = 200000;
    bool public vrfNativePayment = true;
    uint16 public vrfRequestConfirmations = 3;

    // CCIP
    IRouterClient public ccipRouter;
    uint64 public bscChainSelector;
    address public bscReceiver;                      // BSC GuessV6 地址
    bytes public fastExtraArgs;                      // FTF 配置（按 CCIP 2.0 文档设定确认深度）
    bytes public finalExtraArgs;                     // 全终局配置

    mapping(uint256 => SRound) public srounds;
    mapping(uint256 => uint64[]) internal _diffs;    // 本轮 distinct diff 列表
    mapping(uint256 => mapping(uint64 => bool)) internal _diffSeen;
    mapping(uint256 => mapping(uint64 => uint256)) internal _diffBets;      // 每 diff 注数
    mapping(uint256 => mapping(uint64 => uint256)) public payoutPerBet;     // 每注派奖（0=未中奖）
    mapping(uint256 => mapping(uint64 => uint8)) internal _circleTier;      // 决胜圈档位+1（0=非圈组）
    mapping(uint256 => mapping(uint8 => uint256)) internal _tierBets;       // 决胜各档注数
    mapping(uint256 => uint256[7]) internal _circleSharePerBet;
    mapping(uint256 => uint256) public champPerBet;                         // 决胜冠军每注派奖
    mapping(uint256 => uint256) public roundOfRequest;

    // ==================== 事件 ====================
    event RoundBound(uint256 indexed rid, uint256 betCount, bytes32 betRoot);
    event PriceAnchored(uint256 indexed rid, uint64 settlePrice);
    event VrfRequested(uint256 indexed roundId, uint256 requestId);
    event VrfFulfilled(uint256 indexed roundId, uint256 word);
    event DiffsComputed(uint256 indexed rid, uint64 bestDiff, uint256 champCount, uint256 circleCount, uint256 groupCount);
    event AccountingFixed(uint256 indexed rid, bool burst, uint256 t, uint256 ticket, uint256 rake, uint256 smallFund, uint256 poolBefore);
    event GroupsBuilt(uint256 indexed rid, uint256 winnerGroupCount, uint64 cutoff, uint8 cutoffMode);
    event LeavesBuilt(uint256 indexed rid, uint256 totalPayout, uint256 stakeSum);
    event SettlementRootBuilt(uint256 indexed rid, bytes32 root);
    event Published(uint256 indexed rid, bytes32 fastMessageId, bytes32 finalMessageId, uint256 poolAfter);
    event RakeAccrued(uint256 indexed rid, uint256 rakeDelta, uint256 totalRake);
    event VoidStarted(uint256 indexed rid, string reason);
    event VoidPublished(uint256 indexed rid, bytes32 fastMessageId, bytes32 finalMessageId);
    event EmptyPublished(uint256 indexed rid, bytes32 fastMessageId, bytes32 finalMessageId);
    event PoolBonusApplied(uint256 indexed cycleId, uint256 indexed roundId, uint256 amount, uint256 poolAfter);
    event CycleStarted(uint256 indexed cycleId, uint256 maxRounds, uint256 minVrfJackpot);
    event CcipConfigUpdated(address router, uint64 selector, address receiver);
    event OwnerTransferred(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwnerErr(); _; }

    constructor(
        address _betContract,
        address _feed,
        address _vrfCoordinator,   // 允许 address(0)：VRF 未上线时仅保留自然/强制决胜
        bytes32 _vrfKeyHash,
        uint256 _vrfSubId
    ) {
        if (_betContract == address(0) || _feed == address(0)) revert ZeroAddrErr();
        owner = msg.sender;
        betContract = IGuessBetV6(_betContract);
        feed = IAggregatorV3(_feed);
        if (feed.decimals() != 8) revert FeedDecimalsNotEqual8Err();
        vrfCoordinator = IVRFCoordinator(_vrfCoordinator);
        vrfKeyHash = _vrfKeyHash;
        vrfSubId = _vrfSubId;
    }

    receive() external payable {}

    // ==================== 管理 ====================
    function transferOwnership(address n) external onlyOwner {
        if (n == address(0)) revert ZeroAddrErr();
        emit OwnerTransferred(owner, n);
        owner = n;
    }

    function setVrfConfig(address coordinator, bytes32 keyHash, uint256 subId, bool nativePayment, uint16 confirmations)
        external onlyOwner
    {
        if (confirmations < 3 || confirmations > 200) revert BadWordsErr();
        vrfCoordinator = IVRFCoordinator(coordinator);
        vrfKeyHash = keyHash;
        vrfSubId = subId;
        vrfNativePayment = nativePayment;
        vrfRequestConfirmations = confirmations;
    }

    function setCcipConfig(address router, uint64 selector, address receiver, bytes calldata fastArgs, bytes calldata finalArgs)
        external onlyOwner
    {
        if (router == address(0) || receiver == address(0)) revert ZeroAddrErr();
        ccipRouter = IRouterClient(router);
        bscChainSelector = selector;
        bscReceiver = receiver;
        fastExtraArgs = fastArgs;
        finalExtraArgs = finalArgs;
        emit CcipConfigUpdated(router, selector, receiver);
    }

    /// @notice 下一周期生效的周期参数（沿用 V5.8：周期中途修改绝不影响本期）
    function setCycleConfig(uint256 rounds, uint256 minVrfJackpot) external onlyOwner {
        if (rounds < MIN_CYCLE_ROUNDS || rounds > MAX_CYCLE_ROUNDS) revert BadWordsErr();
        nextCycleRounds = rounds;
        nextMinVrfJackpot = minVrfJackpot;
    }

    /// @notice 下一周期普通奖参数（与 V5.8 setSmallPrizeConfig 相同边界校验；BSC 镜像侧同值同校验）
    function setSmallPrizeConfig(uint256 smallBps, uint256 minSmallBets, uint256 winCapBps) external onlyOwner {
        if (minSmallBets < 10) revert OutOfBoundsErr();
        if (smallBps < 2000 || smallBps > 8000) revert OutOfBoundsErr();
        if (winCapBps < 300 || winCapBps > 6000) revert OutOfBoundsErr();
        if (smallBps * 10 < winCapBps * 13) revert SmallFundInvariantErr();
        NEXT_SMALL_BPS = smallBps;
        NEXT_MIN_SMALL_BETS = minSmallBets;
        NEXT_WIN_CAP_BPS = winCapBps;
    }

    /// @notice 预约赞助冲池：下一周期首个有注轮结算时生效（BSC 侧需同步注资）
    function schedulePoolBonus(uint256 amount) external onlyOwner {
        nextCyclePoolBonus += amount;
    }

    /// @notice 提取合约内原生币余额（CCIP 费用余额管理）
    function withdrawNative(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddrErr();
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert CcipFeeErr();
    }

    // ==================== 阶段 0：绑定已关窗轮次 ====================
    /// @notice 读取 GuessBetV6 已 Closed 的轮次，建立结算上下文。
    function beginRound(uint256 rid) external {
        SRound storage s = srounds[rid];
        if (s.state != 0) revert WrongStateErr();
        ( , uint64 priceTime, uint8 betState, uint256 betCount, bytes32 betRoot) =
            betContract.getRoundCore(rid);
        if (betState != 4) revert WrongStateErr();         // Bet 合约必须已 Closed
        s.priceTime = priceTime;
        s.betCount = betCount;
        s.betRoot = betRoot;
        s.stateEnteredAt = uint64(block.timestamp);
        if (betCount == 0) {
            s.state = 12;                                   // 空局：不占周期、不账务、不发消息
        } else {
            s.state = 1;
            emit RoundBound(rid, betCount, betRoot);
        }
    }

    // ==================== 阶段 1：锚定结算价（沿用 V5 夹逼验证） ====================
    /// @notice 提交 Chainlink roundId，验证其为 priceTime 前最后一跳；permissionless。
    function anchorPrice(uint256 rid, uint80 oracleRoundId) external {
        SRound storage s = srounds[rid];
        if (s.state != 1) revert WrongStateErr();
        if (block.timestamp < s.priceTime) revert TooEarlyErr();
        s.settlePrice = _priceAt(oracleRoundId, s.priceTime);
        s.state = 2;
        s.stateEnteredAt = uint64(block.timestamp);
        emit PriceAnchored(rid, s.settlePrice);
    }

    // ==================== VRF（沿用 V5.8 三路决胜） ====================
    /// @notice 为本轮请求 VRF；仅当达门槛且不在强制决胜位。coordinator 为 0 时路径关闭。
    function requestVrf(uint256 rid) external {
        SRound storage s = srounds[rid];
        if (s.state < 1 || s.state >= 9) revert WrongStateErr();
        if (s.vrfRequestId != 0) revert AlreadyRequestedErr();
        if (s.betCount == 0) revert NoBetsErr();
        if (address(vrfCoordinator) == address(0)) revert VRFRequestFailedErr();
        if (!(pool >= currentMinVrfJackpot)) revert PoolBelowVRFThresholdErr();
        if (!(cycleRoundCount + 1 < cycleMaxRounds)) revert FinalRoundNoVRFErr();
        bytes memory extraArgs = abi.encodeWithSelector(bytes4(0x92fd1338), vrfNativePayment);
        try vrfCoordinator.requestRandomWords(IVRFCoordinator.RandomWordsRequest({
            keyHash: vrfKeyHash,
            subId: vrfSubId,
            requestConfirmations: vrfRequestConfirmations,
            callbackGasLimit: vrfCallbackGasLimit,
            numWords: 1,
            extraArgs: extraArgs
        })) returns (uint256 reqId) {
            s.vrfRequestId = reqId;
            roundOfRequest[reqId] = rid;
            emit VrfRequested(rid, reqId);
        } catch {
            revert VRFRequestFailedErr();
        }
    }

    function rawFulfillRandomWords(uint256 requestId, uint256[] memory randomWords) external {
        if (msg.sender != address(vrfCoordinator)) revert NotCoordinatorErr();
        if (randomWords.length != 1) revert BadWordsErr();
        uint256 rid = roundOfRequest[requestId];
        if (rid == 0) revert UnknownRequestErr();
        SRound storage s = srounds[rid];
        if (s.vrfReady) revert AlreadyFulfilledErr();
        s.vrfWord = randomWords[0];
        s.vrfReady = true;
        emit VrfFulfilled(rid, randomWords[0]);
    }

    // ==================== 阶段 2：分批计算 diff ====================
    /// @notice 每次最多处理 maxBets 笔注单：聚合 diff 分布、bestDiff、冠军/圈注数。
    function computeDiffs(uint256 rid, uint256 maxBets) external {
        SRound storage s = srounds[rid];
        if (s.state != 2) revert WrongStateErr();
        uint64 price = s.settlePrice;
        uint256 rows = s.betCount;
        uint256 i = s.diffCursor;
        uint256 steps = 0;
        uint64 best = s.diffCursor == 0 ? type(uint64).max : s.bestDiff;
        uint256 champ = s.champCount;
        uint256 circle = s.circleCount;

        while (i < rows && steps < maxBets) {
            ( , uint64 guess, ) = betContract.getBet(rid, i);
            uint64 d = guess > price ? guess - price : price - guess;
            if (!_diffSeen[rid][d]) {
                _diffSeen[rid][d] = true;
                _diffs[rid].push(d);
            }
            _diffBets[rid][d] += 1;
            if (d < best) {
                best = d;
                champ = 1;
            } else if (d == best) {
                champ += 1;
            }
            if (d <= CIRCLE_TOLERANCE) circle += 1;
            i++;
            steps++;
        }

        s.diffCursor = i;
        s.bestDiff = best;
        s.champCount = champ;
        s.circleCount = circle;
        s.groupCount = _diffs[rid].length;

        if (i >= rows) {
            emit DiffsComputed(rid, best, champ, circle, s.groupCount);
            _finalizeDiffs(rid);
        }
    }

    /// @dev 决胜判定 + 拆账口径；随后按分支进入 Sort / Leaves。
    function _finalizeDiffs(uint256 rid) internal {
        SRound storage s = srounds[rid];

        // —— 新周期快照（首个有注结算轮）：沿用 V5.8 纪律 ——
        if (needNewCycle) {
            cycleId += 1;
            cycleRoundCount = 0;
            cycleMaxRounds = nextCycleRounds;
            currentMinVrfJackpot = nextMinVrfJackpot;
            SMALL_BPS = NEXT_SMALL_BPS;
            MIN_SMALL_BETS = NEXT_MIN_SMALL_BETS;
            WIN_CAP_BPS = NEXT_WIN_CAP_BPS;
            if (nextCyclePoolBonus > 0) {
                pool += nextCyclePoolBonus;
                s.poolBonus = nextCyclePoolBonus;
                emit PoolBonusApplied(cycleId, rid, nextCyclePoolBonus, pool);
                nextCyclePoolBonus = 0;
            }
            needNewCycle = false;
            emit CycleStarted(cycleId, cycleMaxRounds, currentMinVrfJackpot);
        }

        // —— 票价与总额 ——
        uint256 ticket = ticketForPool(pool);
        uint256 t = s.betCount * ticket;
        s.ticket = ticket;
        s.t = t;
        s.poolBefore = pool;
        s.rake = t * RAKE_BPS / 10000;

        // —— 决胜三路判定 ——
        bool finalRound = cycleRoundCount + 1 >= cycleMaxRounds;
        bool burst = s.bestDiff == 0 || finalRound;
        if (!burst && pool >= currentMinVrfJackpot) {
            if (!s.vrfReady) revert WaitVRFErr();           // Keeper 等待后重试本阶段
            burst = s.vrfWord % cycleMaxRounds < 2;
        }
        s.burst = burst;

        if (burst) {
            s.smallFund = 0;
            _enterSort(rid, s);
        } else if (s.betCount < MIN_SMALL_BETS) {
            // 小局：无普通奖，直接造叶（payout 全 0）
            s.smallFund = 0;
            s.state = 6;
        } else {
            s.smallFund = t * SMALL_BPS / 10000;
            _enterSort(rid, s);
        }
        s.stateEnteredAt = uint64(block.timestamp);
        emit AccountingFixed(rid, burst, t, ticket, s.rake, s.smallFund, pool);
    }

    function _enterSort(uint256 rid, SRound storage s) internal {
        uint256 d = _diffs[rid].length;
        if (d <= 1) {
            s.state = 4;                                     // 无需排序
            s.sortI = 0;
        } else {
            s.state = 3;
            s.sortI = 1;
            s.sortJ = 1;
            s.sortKey = _diffs[rid][1];
        }
    }

    /// @notice 链上插入排序（游标分步，每次最多 maxSteps 个比较移动）。
    function sortDiffs(uint256 rid, uint256 maxSteps) external {
        SRound storage s = srounds[rid];
        if (s.state != 3) revert WrongStateErr();
        uint64[] storage arr = _diffs[rid];
        uint256 dlen = arr.length;
        uint256 i = s.sortI;
        uint256 j = s.sortJ;
        uint64 key = s.sortKey;
        uint256 steps = 0;
        while (steps < maxSteps) {
            if (i >= dlen) {
                s.state = 4;
                s.sortI = 0;
                s.sortJ = 0;
                s.sortKey = 0;
                s.groupCursor = 0;
                s.prefixCount = 0;
                s.winnerIdx = 0;
                s.circleSeq = 0;
                s.stateEnteredAt = uint64(block.timestamp);
                return;
            }
            if (j > 0 && arr[j - 1] > key) {
                arr[j] = arr[j - 1];
                j--;
                steps++;
            } else {
                arr[j] = key;
                i++;
                if (i < dlen) {
                    j = i;
                    key = arr[i];
                }
                steps++;
            }
        }
        s.sortI = i;
        s.sortJ = j;
        s.sortKey = key;
    }

    // ==================== 阶段 4：分组与派奖（普通奖单遍 / 决胜两遍） ====================
    /// @notice 沿升序 diff 分批建组；每次最多处理 maxGroups 个组。
    function buildGroups(uint256 rid, uint256 maxGroups) external {
        SRound storage s = srounds[rid];
        if (s.burst) {
            if (s.state == 4) _burstGroupPass1(rid, s, maxGroups);
            else if (s.state == 5) _burstGroupPass2(rid, s, maxGroups);
            else revert WrongStateErr();
        } else {
            if (s.state != 4) revert WrongStateErr();
            _smallGroupPass(rid, s, maxGroups);
        }
    }

    /// @dev 普通奖：cap 封口（EXACT 恰满 / COLLISION 整组剔除），派奖 = 票面 1.01× + 档权 bonus。
    ///      公式与 V5.8 _smallGroupMatchesRules 逐字一致（统一票面，count=注数）。
    function _smallGroupPass(uint256 rid, SRound storage s, uint256 maxGroups) internal {
        uint64[] storage arr = _diffs[rid];
        uint256 cap = s.betCount * WIN_CAP_BPS / 10000;      // smallSlots
        uint256 base = s.ticket * 101 / 100;
        if (s.smallFund < base * cap) revert SmallFundInvariantErr();
        uint256 bonusPool = s.smallFund - base * cap;
        uint256 wsum = _weightSum(cap);

        uint256 g = s.groupCursor;
        uint256 steps = 0;
        while (g < arr.length && steps < maxGroups) {
            uint64 d = arr[g];
            uint256 count = _diffBets[rid][d];
            if (s.smallCutoffMode == 0 && s.prefixCount + count <= cap) {
                // 赢家组：档位按入选组序号
                (, uint16 w) = _tierOf(s.winnerIdx);
                uint256 bonusEach = w == 0 ? 0 : bonusPool * uint256(w) / wsum / count;
                payoutPerBet[rid][d] = base + bonusEach;
                s.winnerIdx++;
                s.prefixCount += count;
                if (s.prefixCount == cap) {
                    s.smallCutoffMode = 2;                    // EXACT：恰满封口
                    s.smallCutoff = d;
                }
            } else {
                // 输家组；首个越界组记录 COLLISION 封口
                if (s.smallCutoffMode == 0) {
                    s.smallCutoffMode = 1;
                    s.smallCutoff = d;
                }
            }
            g++;
            steps++;
        }
        s.groupCursor = g;
        s.winnerGroupCount = s.winnerIdx;

        if (g >= arr.length) {
            s.state = 6;
            s.stateEnteredAt = uint64(block.timestamp);
            emit GroupsBuilt(rid, s.winnerGroupCount, s.smallCutoff, s.smallCutoffMode);
        }
    }

    /// @dev 决胜第一遍：累计 ±10U 圈内各 diff 组的档位与注数；完成后折算冠军/圈档每注派奖。
    function _burstGroupPass1(uint256 rid, SRound storage s, uint256 maxGroups) internal {
        uint64[] storage arr = _diffs[rid];
        uint256 g = s.groupCursor;
        uint256 steps = 0;
        while (g < arr.length && steps < maxGroups) {
            uint64 d = arr[g];
            if (d <= CIRCLE_TOLERANCE) {
                (uint8 tier, ) = _tierOf(s.circleSeq);
                _circleTier[rid][d] = tier + 1;
                _tierBets[rid][tier] += _diffBets[rid][d];
                s.circleSeq++;
            }
            g++;
            steps++;
        }
        s.groupCursor = g;
        if (g < arr.length) return;

        // —— 折算（poolAfter 为决胜局总池口径：历史池 + 本局 90%）——
        uint256 poolAfter = pool + s.t - s.rake;
        uint256 champBudget = poolAfter * (s.circleCount == 0 ? 10000 : CHAMP_BPS) / 10000;
        champPerBet[rid] = champBudget / s.champCount;

        if (s.circleCount > 0) {
            uint256 circleBudget = poolAfter * CIRCLE_BPS / 10000;
            uint256 dsum = 0;
            for (uint8 k = 0; k < 7; k++) dsum += uint256(BTIER_W[k]) * _tierBets[rid][k];
            for (uint8 k = 0; k < 7; k++) {
                uint256 n = _tierBets[rid][k];
                _circleSharePerBet[rid][k] = n == 0 ? 0 : circleBudget * uint256(BTIER_W[k]) / dsum;
            }
        }
        s.state = 5;
        s.assignCursor = 0;
    }

    /// @dev 决胜第二遍：为圈组写入每注派奖，冠军组叠加冠军份额。
    function _burstGroupPass2(uint256 rid, SRound storage s, uint256 maxGroups) internal {
        uint64[] storage arr = _diffs[rid];
        uint256 g = s.assignCursor;
        uint256 steps = 0;
        while (g < arr.length && steps < maxGroups) {
            uint64 d = arr[g];
            uint8 t1 = _circleTier[rid][d];
            if (t1 > 0) payoutPerBet[rid][d] = _circleSharePerBet[rid][t1 - 1];
            if (d == s.bestDiff) payoutPerBet[rid][d] += champPerBet[rid];
            g++;
            steps++;
        }
        s.assignCursor = g;
        if (g >= arr.length) {
            s.state = 6;
            s.stateEnteredAt = uint64(block.timestamp);
            emit GroupsBuilt(rid, s.circleSeq, 0, 0);
        }
    }

    // ==================== 阶段 5：结算叶（覆盖全部注单，含输家 payout=0） ====================
    /// @notice 为每笔注单生成结算叶并累计守恒校验数据；每次最多 maxBets 笔。
    /// @dev 叶 = keccak256(rid, player, nonce, payout)；统一票面制下 stake = 当轮 ticket，
    ///      BSC 凭 proof 逐笔记账：扣 ticket、入 payout，资金完全闭合。
    function buildLeaves(uint256 rid, uint256 maxBets) external {
        SRound storage s = srounds[rid];
        if (s.state != 6) revert WrongStateErr();
        uint64 price = s.settlePrice;
        uint256 rows = s.betCount;
        uint256 i = s.leafCursor;
        uint256 steps = 0;
        uint256 stakeSum = s.stakeSum;
        uint256 paid = s.totalPayout;
        uint256 ticket = s.ticket;

        while (i < rows && steps < maxBets) {
            (address player, uint64 guess, uint64 nonce) = betContract.getBet(rid, i);
            uint64 d = guess > price ? guess - price : price - guess;
            uint256 payout = payoutPerBet[rid][d];
            _pushLeaf(rid, keccak256(abi.encodePacked(rid, player, nonce, payout)));
            stakeSum += ticket;
            paid += payout;
            i++;
            steps++;
        }
        s.leafCursor = i;
        s.stakeSum = stakeSum;
        s.totalPayout = paid;

        if (i >= rows) {
            // —— 守恒校验与账务落地（单点） ——
            if (stakeSum != s.t) revert StakeMismatchErr();
            if (s.burst) {
                uint256 poolAfter = pool + s.t - s.rake;
                if (paid > poolAfter) revert SmallFundInvariantErr();
                s.fee = poolAfter - paid;
                pool = 0;                                    // 决胜爆池，周期终结
            } else {
                if (s.betCount >= MIN_SMALL_BETS) {
                    s.smallPaid = paid;
                    if (paid > s.smallFund) revert SmallFundInvariantErr();
                }
                pool = pool + s.t - s.rake - paid;           // 未派完部分自然滚存
            }
            totalRake += s.rake;
            emit RakeAccrued(rid, s.rake, totalRake);
            s.state = 7;
            s.stateEnteredAt = uint64(block.timestamp);
            emit LeavesBuilt(rid, paid, stakeSum);
        }
    }

    // ==================== 阶段 6：SettlementRoot ====================
    function buildSettlementRoot(uint256 rid, uint256 maxSteps) external {
        SRound storage s = srounds[rid];
        if (s.state != 7) revert WrongStateErr();
        (bool done, bytes32 root) = _buildStep(rid, maxSteps);
        if (done) {
            s.settlementRoot = root;
            s.state = 8;
            s.stateEnteredAt = uint64(block.timestamp);
            emit SettlementRootBuilt(rid, root);
        }
    }

    // ==================== 阶段 7：CCIP 双消息发布 ====================
    /// @notice 向 BSC GuessV6 发送 FTF 快消息 + 全终局慢消息；消息体含全部镜像账务字段。
    /// @dev 消息布局（settlement / void / empty 三种 msgType 统一 21 字段）：
    ///      (uint8 msgType, uint8 fin, uint256 rid, uint256 cycleId,
    ///       bytes32 betRoot, bytes32 settlementRoot, uint64 settlePrice, uint64 bestDiff, bool burst,
    ///       uint256 betCount, uint256 t, uint256 totalPayout, uint256 rake,
    ///       uint256 poolBefore, uint256 poolAfter, uint256 fee,
    ///       uint256 minSmallBets, uint256 smallBps, uint256 winCapBps, uint256 poolBonus)
    ///      fin: 0=FTF 快消息（BSC 记账、可继续玩）；1=全终局（解锁提现）。
    ///      BSC 侧职责：幂等接收（roundId 唯一）、按相同整数公式复算守恒、
    ///      两消息不一致 → 冻结告警 + 在账回滚。
    function publish(uint256 rid) external {
        SRound storage s = srounds[rid];
        if (s.state != 8) revert WrongStateErr();
        if (address(ccipRouter) == address(0) || bscReceiver == address(0)) revert CcipNotConfiguredErr();

        (bytes32 fastId, bytes32 finalId) = _sendTwo(
            _settlePayload(rid, s, 0, 0),
            _settlePayload(rid, s, 0, 1)
        );

        // 周期记账：决胜轮终结周期；普通轮累计有效轮数
        if (s.burst) needNewCycle = true;
        else cycleRoundCount += 1;

        s.state = 9;
        emit Published(rid, fastId, finalId, pool);
    }

    /// @notice 空局心跳消息：推动 BSC 终局水位线越过空局轮次（否则空局期间玩家提现闸门无法解锁）。
    /// @dev 空局无账务、不占周期；msgType=2，poolBefore==poolAfter，poolBonus=0（赞助只在首个有注轮快照）。
    function publishEmpty(uint256 rid) external {
        SRound storage s = srounds[rid];
        if (s.state != 12) revert WrongStateErr();
        if (address(ccipRouter) == address(0) || bscReceiver == address(0)) revert CcipNotConfiguredErr();

        (bytes32 fastId, bytes32 finalId) = _sendTwo(
            _emptyPayload(rid, 0),
            _emptyPayload(rid, 1)
        );
        s.state = 13;
        emit EmptyPublished(rid, fastId, finalId);
    }

    /// @dev 统一载荷：结算消息（msgType=0）。
    function _settlePayload(uint256 rid, SRound storage s, uint8 msgType, uint8 fin)
        internal view returns (bytes memory)
    {
        return abi.encode(
            msgType,
            fin,
            rid,
            cycleId,
            s.betRoot,
            s.settlementRoot,
            s.settlePrice,
            s.bestDiff,
            s.burst,
            s.betCount,
            s.t,
            s.totalPayout,
            s.rake,
            s.poolBefore,
            pool,                // poolAfter（决胜轮已归零）
            s.fee,
            MIN_SMALL_BETS,
            SMALL_BPS,
            WIN_CAP_BPS,
            s.poolBonus
        );
    }

    /// @dev 统一载荷：流局消息（msgType=1）。poolAfter 为回滚后的 pool（== poolBefore）。
    function _voidPayload(uint256 rid, SRound storage s, uint8 fin) internal view returns (bytes memory) {
        return abi.encode(
            uint8(1),
            fin,
            rid,
            cycleId,
            s.betRoot,
            bytes32(0),          // 无 SettlementRoot
            uint64(0),
            s.bestDiff,
            false,
            s.betCount,
            s.t,
            uint256(0),
            uint256(0),
            s.poolBefore,
            pool,
            uint256(0),
            MIN_SMALL_BETS,
            SMALL_BPS,
            WIN_CAP_BPS,
            s.poolBonus
        );
    }

    /// @dev 统一载荷：空局心跳（msgType=2）。不带账务；betCount=0。
    function _emptyPayload(uint256 rid, uint8 fin) internal view returns (bytes memory) {
        return abi.encode(
            uint8(2),
            fin,
            rid,
            cycleId,
            bytes32(0),
            bytes32(0),
            uint64(0),
            uint64(0),
            false,
            uint256(0),
            uint256(0),
            uint256(0),
            uint256(0),
            pool,
            pool,
            uint256(0),
            MIN_SMALL_BETS,
            SMALL_BPS,
            WIN_CAP_BPS,
            uint256(0)
        );
    }

    /// @dev 同一轮发两条消息：FTF 快通道 + 全终局慢通道；费用原生币支付。
    function _sendTwo(bytes memory fastData, bytes memory finalData) internal returns (bytes32 fastId, bytes32 finalId) {
        Client.EVM2AnyMessage memory mFast = Client.EVM2AnyMessage({
            receiver: abi.encode(bscReceiver),
            data: fastData,
            tokenAmounts: new Client.EVMTokenAmount[](0),
            feeToken: address(0),
            extraArgs: fastExtraArgs
        });
        Client.EVM2AnyMessage memory mFinal = Client.EVM2AnyMessage({
            receiver: abi.encode(bscReceiver),
            data: finalData,
            tokenAmounts: new Client.EVMTokenAmount[](0),
            feeToken: address(0),
            extraArgs: finalExtraArgs
        });
        uint256 fee1 = ccipRouter.getFee(bscChainSelector, mFast);
        uint256 fee2 = ccipRouter.getFee(bscChainSelector, mFinal);
        if (address(this).balance < fee1 + fee2) revert CcipFeeErr();
        fastId = ccipRouter.ccipSend{value: fee1}(bscChainSelector, mFast);
        finalId = ccipRouter.ccipSend{value: fee2}(bscChainSelector, mFinal);
    }

    // ==================== 流局 ====================
    /// @notice 满足故障条件时进入 Voiding：Oracle 死亡 / VRF 超时 / 各阶段卡死超 FINAL_GRACE。
    /// @dev 账务已在 Leaves 阶段落地的（state>=7）先回滚：pool 恢复 poolBefore、rake 冲回。
    ///      空局（state 12）不可流局；已发布（state>=9）不可流局。
    function voidInit(uint256 rid, string calldata reason) external {
        SRound storage s = srounds[rid];
        if (s.state == 0 || s.state >= 9) revert FinalizedErr();

        bool ok = false;
        if (s.state == 1 && _oracleDead()) ok = true;
        // VRF 超时：diff 已算完但随机词未到，且本轮确需 VRF 判定
        if (s.state == 2 && s.diffCursor == s.betCount && !s.vrfReady
            && s.bestDiff != 0
            && cycleRoundCount + 1 < cycleMaxRounds
            && pool >= currentMinVrfJackpot
            && block.timestamp > s.priceTime + VRF_GRACE) ok = true;
        // 通用卡死逃生
        if (s.state <= 8 && block.timestamp > s.priceTime + FINAL_GRACE) ok = true;
        if (!ok) revert VoidConditionsNotMetErr();

        if (s.state >= 7) {                                  // 账务已落地 → 回滚
            pool = s.poolBefore;
            totalRake -= s.rake;
        }
        s.state = 10;
        emit VoidStarted(rid, reason);
    }

    /// @notice 发布流局消息（CCIP 双消息），BSC 据此全额退款并清除在押标记。
    function voidPublish(uint256 rid) external {
        SRound storage s = srounds[rid];
        if (s.state != 10) revert WrongStateErr();
        if (address(ccipRouter) == address(0) || bscReceiver == address(0)) revert CcipNotConfiguredErr();
        (bytes32 fastId, bytes32 finalId) = _sendTwo(
            _voidPayload(rid, s, 0),
            _voidPayload(rid, s, 1)
        );
        s.state = 11;
        emit VoidPublished(rid, fastId, finalId);
    }

    // ==================== 查询 ====================
    function getSettlementSummary(uint256 rid) external view returns (
        uint8 state, uint64 settlePrice, uint64 bestDiff, bool burst,
        uint256 betCount, uint256 t, uint256 totalPayout, uint256 rake,
        bytes32 betRoot, bytes32 settlementRoot
    ) {
        SRound storage s = srounds[rid];
        return (s.state, s.settlePrice, s.bestDiff, s.burst, s.betCount, s.t,
                s.totalPayout, s.rake, s.betRoot, s.settlementRoot);
    }

    function diffListLength(uint256 rid) external view returns (uint256) {
        return _diffs[rid].length;
    }

    function diffAt(uint256 rid, uint256 index) external view returns (uint64) {
        return _diffs[rid][index];
    }

    /// @notice 票价阶梯（与 V5.8 ticketForPool 逐字一致）：1→2→5→10→20→50…
    /// @dev 升档线：pool(wei) >= 10万 × 当前票价(wei) → 升档； mantissa 在 1/2/5 间循环，exp 进位。
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

    // ==================== 内部：档位 / 预言机 ====================
    function _tierOf(uint256 k) internal view returns (uint8 tier, uint16 w) {
        for (uint8 i = 0; i < 6; i++) {
            if (k < TIER_CUM[i]) return (i, TIER_W[i]);
        }
        return (6, 0);
    }

    function _weightSum(uint256 slots) internal view returns (uint256 ws) {
        uint256 lo;
        for (uint8 i = 0; i < 7; i++) {
            uint256 hi = i < 6 ? TIER_CUM[i] : slots;
            if (hi > slots) hi = slots;
            if (hi > lo) ws += (hi - lo) * TIER_W[i];
            lo = hi;
        }
    }

    function _oracleDead() internal view returns (bool) {
        try feed.latestRoundData() returns (uint80, int256 answer, uint256, uint256 updatedAt, uint80) {
            if (answer <= 0 || updatedAt == 0 || updatedAt > block.timestamp) return true;
            return block.timestamp - updatedAt > ORACLE_STALE;
        } catch {
            return true;
        }
    }

    /// @dev 沿用 V5：验证 oracleRoundId 是 target 前最后一跳（candidate<=target<next）。
    function _priceAt(uint80 oracleRoundId, uint64 target) internal view returns (uint64) {
        (uint80 returnedRoundId, int256 answer, , uint256 updatedAt, ) = feed.getRoundData(oracleRoundId);
        if (returnedRoundId != oracleRoundId) revert NoDataAtRoundErr();
        if (updatedAt == 0) revert NoDataAtRoundErr();
        if (answer <= 0) revert BadAnswerErr();
        if (updatedAt > target) revert PriceAfterTargetErr();
        if (uint256(target) - updatedAt >= ORACLE_STALE) revert StalePriceErr();

        uint80 nextRoundId = oracleRoundId + 1;
        (uint80 nextReturnedRoundId, , , uint256 nextUpdatedAt, ) = feed.getRoundData(nextRoundId);
        if (nextReturnedRoundId != nextRoundId) revert NoDataAtRoundErr();
        if (nextUpdatedAt == 0) revert NoDataAtRoundErr();
        if (nextUpdatedAt <= target) revert NextRoundNotAfterTargetErr();

        return uint64((uint256(answer) + 5e3) / 1e4);    // 8 位小数 → 0.0001 USD，四舍五入
    }
}
