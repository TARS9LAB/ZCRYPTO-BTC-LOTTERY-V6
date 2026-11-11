// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ZCryptoSessionManagerV6 — BSC 会话密钥管理（V6 定稿）
/// @notice V6 双链架构中的定位：BSC 是会话授权的【权威登记处】，MegaETH 是【执行层】。
///
///   职责边界（与 V6 设计方案一致）：
///     - 本合约只做：注册（主钱包直调/签名）、吊销、会话查询。
///       不消费注单、不做 Nonce 去重、不扣额度——这些全部在 MegaETH GuessBetV6 执行。
///     - Relay/前端在转发注单前用 verifyAuth 做预检（纵深防御）；
///       MegaETH 合约独立验签，不依赖本合约状态（跨链不可读是设计使然）。
///     - 两侧授权的一致性锚点：MegaETH SessionAuth.authNonce == 本合约 generation。
///
///   吊销的跨链时效说明：吊销在 BSC 立即生效，Relay 停止转发；
///   但 MegaETH 无法实时感知——已签发的 SessionAuth 在 MegaETH 侧最长存活至 expiry，
///   损失上界 = maxBets × 当轮票价（对敲盗刷防线），因此 maxBets 不宜过大。
contract ZCryptoSessionManagerV6 {
    // ==================== 自定义错误 ====================
    error ZeroAddrErr();
    error InvalidSignatureErr();
    error InvalidNonceErr();
    error DeadlinePassedErr();
    error InvalidExpiryErr();
    error NoActiveSessionErr();
    error MaxBetsZeroErr();

    // ==================== 常量 ====================
    uint64 public constant MAX_SESSION_DURATION = 1 days;  // 会话有效期硬上限
    uint32 public constant DEFAULT_MAX_BETS = 10;          // 默认授权注数（对敲盗刷损失上界 = maxBets × 票价）

    // ==================== EIP-712 ====================
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256(bytes("ZCrypto SessionManager"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));
    bytes32 public constant REGISTER_TYPEHASH = keccak256(
        "RegisterSession(address user,address key,uint32 maxBets,uint64 expiry,uint256 nonce,uint64 deadline)");
    bytes32 public constant REVOKE_TYPEHASH = keccak256(
        "RevokeSession(address user,uint256 nonce,uint64 deadline)");
    uint256 private constant SECP256K1_HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    // ==================== 存储 ====================
    struct Session {
        address key;        // 当前会话密钥（零地址 = 无有效会话）
        uint64 expiry;      // 有效期（unix 秒）；有效语义：expiry > block.timestamp
        uint32 maxBets;     // 授权注数上限（MegaETH 计数强制）
        uint64 generation;  // 授权代次，每次注册 +1；即 MegaETH SessionAuth.authNonce
    }

    mapping(address => Session) private _sessions;
    mapping(address => uint256) public nonces;   // 注册/吊销签名的顺序 Nonce

    // ==================== 事件 ====================
    /// @dev Relay 监听此事件同步“哪个用户的哪把 key 当前有效、参数是什么”
    event SessionRegistered(address indexed user, address indexed key, uint64 generation, uint32 maxBets, uint64 expiry);
    event SessionRevoked(address indexed user, uint64 generation);

    // ==================== 注册 ====================
    /// @notice 主钱包直接注册会话密钥（推荐路径，无需签名）。
    /// @param maxBets 传 0 使用默认值 DEFAULT_MAX_BETS
    function register(address key, uint32 maxBets, uint64 expiry) external {
        _register(msg.sender, key, maxBets, expiry);
    }

    /// @notice 通过主钱包 EIP-712 签名注册，任何地址可代付 Gas 提交。
    function registerBySig(
        address user, address key, uint32 maxBets, uint64 expiry,
        uint256 nonce, uint64 deadline, bytes calldata signature
    ) external {
        if (user == address(0)) revert ZeroAddrErr();
        if (block.timestamp > deadline) revert DeadlinePassedErr();
        if (nonce != nonces[user]) revert InvalidNonceErr();
        bytes32 structHash = keccak256(abi.encode(
            REGISTER_TYPEHASH, user, key, maxBets, expiry, nonce, deadline));
        if (_recover(_typedDigest(structHash), signature) != user) revert InvalidSignatureErr();
        nonces[user] = nonce + 1;
        _register(user, key, maxBets, expiry);
    }

    /// @dev 新授权立即替换旧密钥并重置计数；generation 单调递增。
    function _register(address user, address key, uint32 maxBets, uint64 expiry) internal {
        if (key == address(0) || key == user) revert ZeroAddrErr();
        if (expiry <= block.timestamp || expiry > block.timestamp + MAX_SESSION_DURATION)
            revert InvalidExpiryErr();
        uint32 actualMax = maxBets == 0 ? DEFAULT_MAX_BETS : maxBets;
        if (actualMax == 0) revert MaxBetsZeroErr();
        uint64 generation = _sessions[user].generation + 1;
        _sessions[user] = Session(key, expiry, actualMax, generation);
        emit SessionRegistered(user, key, generation, actualMax, expiry);
    }

    // ==================== 吊销 ====================
    /// @notice 主钱包直接吊销当前会话，立即生效；同时推进 Nonce 使未执行的旧签名授权失效。
    function revoke() external {
        nonces[msg.sender] += 1;
        _revoke(msg.sender);
    }

    /// @notice 主钱包签名吊销，允许任意地址代付 Gas 提交。
    function revokeBySig(address user, uint256 nonce, uint64 deadline, bytes calldata signature) external {
        if (block.timestamp > deadline) revert DeadlinePassedErr();
        if (nonce != nonces[user]) revert InvalidNonceErr();
        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, user, nonce, deadline));
        if (user == address(0) || _recover(_typedDigest(structHash), signature) != user)
            revert InvalidSignatureErr();
        nonces[user] = nonce + 1;
        _revoke(user);
    }

    function _revoke(address user) internal {
        Session storage s = _sessions[user];
        if (s.key == address(0)) revert NoActiveSessionErr();
        uint64 gen = s.generation;
        s.key = address(0);
        s.expiry = 0;
        emit SessionRevoked(user, gen);
    }

    // ==================== 查询（Relay / 前端预检） ====================
    function sessionOf(address user) external view returns (Session memory) {
        return _sessions[user];
    }

    /// @notice 指定密钥是否为该用户当前有效会话密钥（语义与 MegaETH AuthExpired 对齐）。
    function isActive(address user, address key) public view returns (bool) {
        Session storage s = _sessions[user];
        return key != address(0) && s.key == key && s.expiry > block.timestamp;
    }

    /// @notice 核对一份 MegaETH SessionAuth 是否与 BSC 当前有效会话完全一致。
    /// @dev 参数语义与 GuessBetV6.SessionAuth 逐字段对齐；
    ///      Relay 转发注单前调用：不一致 = 注单携带的是过期/伪造授权，直接拒收。
    function verifyAuth(
        address user, address sessionKey, uint32 maxBets, uint64 expiry, uint64 authNonce
    ) external view returns (bool) {
        Session storage s = _sessions[user];
        return s.key == sessionKey
            && s.expiry == expiry
            && s.maxBets == maxBets
            && s.generation == authNonce
            && s.expiry > block.timestamp;
    }

    // ==================== EIP-712 内部 ====================
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _typedDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
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
