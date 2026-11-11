// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MerkleBuilder.sol";

/// @title GuessBetV6 — MegaETH 逐单下注合约
/// @notice V6 核心变化：每笔下注【实时逐单上链】，取代 V5 的“Operator 承诺 BetRoot”。
///
///         安全模型：
///           - 注单自包含双签名，合约独立验签，Relay 只是纯管道，无法伪造注单：
///               (1) 主钱包签名 SessionAuth：授权某 sessionKey、注数上限、有效期；
///               (2) sessionKey 签名 Bet：具体注单内容。
///           - “0–5 分下注”= 下注时间窗：每轮第 0–5 分钟接单，之后合约按区块时间戳
///             直接 revert（“超过 5 分拒绝接单”在链上执行，不依赖 Relay 校验）。
///           - 统一票面制（沿用 V5.8）：每注 = 1 张票，金额 = 当轮票价，注单不带金额。
///           - (user, nonce) 去重：3 套 Relay 并发广播的重复提交只会 revert，无副作用。
///           - SessionAuth.maxBets 由合约计数强制：Session Key 被盗后的对敲盗刷损失
///             被压到 maxBets × 票价 以内。
///           - 本合约【不接触任何资金】，任何人（含用户自己）都可提交签名注单，
///             因此用户可绕过全部 Relay 直连上链（防审查兜底）。
///
///         轮次：10 分钟格点（rid 由 slot 推导），关窗后由 closeRound/buildBetRoot
///               分步构建 BetRoot（permissionless）。
contract GuessBetV6 is MerkleBuilder {
    // ==================== 自定义错误 ====================
    error ZeroAddrErr();
    error BadGenesisErr();
    error NoSuchRoundErr();
    error WrongStateErr();
    error TooEarlyErr();
    error TooLateErr();
    error BadAuthSigErr();
    error BadBetSigErr();
    error AuthExpiredErr();
    error NonceUsedErr();
    error TooManyBetsErr();

    // ==================== 常量 ====================
    uint64 public constant BET_WINDOW = 5 minutes;      // 下注窗口：第 0–5 分钟接单
    uint64 public constant ROUND_DURATION = 10 minutes; // 轮时长
    uint64 public constant START_GRACE = 2 minutes;     // 格点开始后的开局宽限

    uint64 public immutable genesisSlot;                // 10 分钟格点起点（600 对齐）

    // ==================== EIP-712 ====================
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant SESSION_AUTH_TYPEHASH = keccak256(
        "SessionAuth(address user,address sessionKey,uint32 maxBets,uint64 expiry,uint64 authNonce)");
    bytes32 private constant BET_TYPEHASH =
        keccak256("Bet(uint256 roundId,uint64 guess,uint64 nonce)");
    bytes32 private immutable _domain;

    /// @notice 主钱包对会话密钥的授权（EIP-712 由 user 签名）
    /// @param maxBets   该会话密钥允许的最大注数（合约计数强制，防对敲盗刷）
    /// @param expiry    授权有效期（unix 秒）
    /// @param authNonce 授权序号，供 BSC SessionManager 对账/吊销核对
    struct SessionAuth {
        address user;
        address sessionKey;
        uint32 maxBets;
        uint64 expiry;
        uint64 authNonce;
    }

    /// @notice 注单（EIP-712 由 sessionKey 签名）
    /// @param guess 猜价，0.0001 USD 单位（与 V5 口径一致）
    /// @dev 统一票面制：注单不带金额；每注 1 张票，金额 = 当轮 ticket。
    struct BetMsg {
        uint256 roundId;
        uint64 guess;
        uint64 nonce;
    }

    struct Bet {
        address player;
        uint64 guess;
        uint64 nonce;
    }

    // ==================== 轮次 ====================
    // state: 0=未开局 1=Betting 2=Seeding(生成叶子) 3=Building(配对建树) 4=Closed(终态)
    struct Round {
        uint64 bettingClose;
        uint64 priceTime;
        uint8 state;
        uint256 betCount;    // 注数 = 票数（统一票面）
        bytes32 betRoot;     // state=4 后可用
        uint256 seedCursor;  // 已生成叶子数
    }

    mapping(uint256 => Round) public rounds;
    mapping(uint256 => Bet[]) private _bets;
    mapping(address => mapping(uint64 => bool)) public usedNonce;
    /// @dev 会话密钥已用注数：key = keccak256(user, sessionKey, authNonce)
    mapping(bytes32 => uint256) public sessionBetCount;

    // ==================== 事件 ====================
    event RoundStarted(uint256 indexed rid, uint64 bettingClose, uint64 priceTime);
    event BetPlaced(uint256 indexed rid, address indexed player, uint64 guess, uint64 nonce, uint256 betCount);
    event BetRootBuilt(uint256 indexed rid, bytes32 root, uint256 betCount);

    constructor(uint64 _genesisSlot) {
        if (_genesisSlot % uint64(ROUND_DURATION) != 0) revert BadGenesisErr();
        genesisSlot = _genesisSlot;
        _domain = keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes("ZCryptoV6")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    // ==================== 开局（permissionless） ====================
    /// @notice 由 slot 推导 roundId：rid = (slotStart - genesisSlot)/600 + 1
    function roundIdOfSlot(uint64 slotStart) public view returns (uint256) {
        if (slotStart < genesisSlot) revert TooEarlyErr();
        return (slotStart - genesisSlot) / ROUND_DURATION + 1;
    }

    /// @notice 当前时刻所处格点的 roundId
    function currentRoundId() external view returns (uint256) {
        return roundIdOfSlot(uint64(block.timestamp));
    }

    /// @notice 开启指定格点的轮次；仅允许在该格点开始后 START_GRACE 内开局。
    function startRound(uint256 rid) external {
        if (rid == 0) revert NoSuchRoundErr();
        if (rounds[rid].bettingClose != 0) revert WrongStateErr(); // 已开局
        uint64 slotStart = genesisSlot + uint64(rid - 1) * ROUND_DURATION;
        if (block.timestamp < slotStart) revert TooEarlyErr();
        if (block.timestamp > slotStart + START_GRACE) revert TooLateErr();
        Round storage r = rounds[rid];
        r.bettingClose = slotStart + BET_WINDOW;
        r.priceTime = slotStart + ROUND_DURATION;
        r.state = 1;
        emit RoundStarted(rid, r.bettingClose, r.priceTime);
    }

    // ==================== 下注（permissionless，任何人均可代交） ====================
    /// @notice 提交一笔签名注单。msg.sender 只付 Gas，不能改变注单内容。
    /// @dev Relay 转发、用户直连兜底，走的是同一个入口。
    function bet(
        SessionAuth calldata a,
        bytes calldata authSig,
        BetMsg calldata m,
        bytes calldata betSig
    ) external {
        Round storage r = rounds[m.roundId];
        if (r.state != 1) revert NoSuchRoundErr();
        if (block.timestamp >= r.bettingClose) revert TooLateErr();   // 合约时间戳判截止：5 分钟后拒单
        if (a.user == address(0) || a.sessionKey == address(0)) revert ZeroAddrErr();
        if (a.expiry <= block.timestamp) revert AuthExpiredErr();

        // 双签名验证：主钱包授权 + 会话密钥注单
        if (_recover(_sessionAuthDigest(a), authSig) != a.user) revert BadAuthSigErr();
        if (_recover(_betDigest(m), betSig) != a.sessionKey) revert BadBetSigErr();

        // 授权注数上限（合约计数强制）
        bytes32 skey = keccak256(abi.encodePacked(a.user, a.sessionKey, a.authNonce));
        if (sessionBetCount[skey] >= a.maxBets) revert TooManyBetsErr();
        sessionBetCount[skey] += 1;

        // (user, nonce) 去重：3 Relay 并发提交同一注单只会 revert
        if (usedNonce[a.user][m.nonce]) revert NonceUsedErr();
        usedNonce[a.user][m.nonce] = true;

        _bets[m.roundId].push(Bet(a.user, m.guess, m.nonce));
        r.betCount += 1;
        emit BetPlaced(m.roundId, a.user, m.guess, m.nonce, r.betCount);
    }

    // ==================== 关窗与 BetRoot 构建（permissionless，分步） ====================
    /// @notice 关窗并分步生成叶子层；每次最多处理 maxSeeds 笔注单。
    function closeRound(uint256 rid, uint256 maxSeeds) external {
        Round storage r = rounds[rid];
        if (r.state != 1 && r.state != 2) revert WrongStateErr();
        if (block.timestamp < r.bettingClose) revert TooEarlyErr();

        // 空局：无注单，BetRoot 为零根，直接 Closed
        if (r.betCount == 0) {
            r.betRoot = bytes32(0);
            r.state = 4;
            emit BetRootBuilt(rid, bytes32(0), 0);
            return;
        }

        r.state = 2;
        uint256 rows = r.betCount;
        uint256 i = r.seedCursor;
        uint256 steps = 0;
        while (i < rows && steps < maxSeeds) {
            Bet storage b = _bets[rid][i];
            _pushLeaf(rid, _betLeaf(rid, b.player, b.guess, b.nonce));
            i++;
            steps++;
        }
        r.seedCursor = i;
        if (i >= rows) r.state = 3;
    }

    /// @notice 分步配对建树；每次最多完成 maxSteps 个配对哈希。完成后写入 betRoot。
    function buildBetRoot(uint256 rid, uint256 maxSteps) external {
        Round storage r = rounds[rid];
        if (r.state != 3) revert WrongStateErr();
        (bool done, bytes32 root) = _buildStep(rid, maxSteps);
        if (done) {
            r.betRoot = root;
            r.state = 4;
            emit BetRootBuilt(rid, root, r.betCount);
        }
    }

    // ==================== 查询 ====================
    function getBet(uint256 rid, uint256 index)
        external
        view
        returns (address player, uint64 guess, uint64 nonce)
    {
        Bet storage b = _bets[rid][index];
        return (b.player, b.guess, b.nonce);
    }

    function getRoundCore(uint256 rid) external view returns (
        uint64 bettingClose, uint64 priceTime, uint8 state, uint256 betCount, bytes32 betRoot
    ) {
        Round storage r = rounds[rid];
        return (r.bettingClose, r.priceTime, r.state, r.betCount, r.betRoot);
    }

    /// @notice 用户自查注单是否被 BetRoot 承诺（沿用 V5 sorted-pair proof）
    function verifyInclusion(
        uint256 rid, address player, uint64 guess, uint64 nonce, bytes32[] calldata proof
    ) external view returns (bool) {
        Round storage r = rounds[rid];
        if (r.state != 4 || r.betCount == 0) return false;
        bytes32 h = _betLeaf(rid, player, guess, nonce);
        for (uint256 i = 0; i < proof.length; i++) {
            h = _hashPair(h, proof[i]);
        }
        return h == r.betRoot;
    }

    // ==================== 内部 ====================
    /// @dev BetRoot 叶子：与 V5.8 _betLeaf 完全一致 keccak256(rid, player, guess, nonce)
    function _betLeaf(uint256 rid, address player, uint64 guess, uint64 nonce)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(rid, player, guess, nonce));
    }

    function _sessionAuthDigest(SessionAuth calldata a) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            _domain,
            keccak256(abi.encode(SESSION_AUTH_TYPEHASH, a.user, a.sessionKey, a.maxBets, a.expiry, a.authNonce))
        ));
    }

    function _betDigest(BetMsg calldata m) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            _domain,
            keccak256(abi.encode(BET_TYPEHASH, m.roundId, m.guess, m.nonce))
        ));
    }

    /// @dev EIP-2 低 s 值检查 + ecrecover
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
