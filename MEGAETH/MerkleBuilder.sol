// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MerkleBuilder — 链上分步 Merkle Root 构建器
/// @notice 供 GuessBetV6 / GuessSettleV6 继承使用。
///         设计目标：注单/结算叶数量可能很大，单笔交易无法完成整棵树，
///         因此以“游标 + 分批”方式逐层构建：
///           1. 调用方先向 _cur[rid] 写入当前层全部节点（叶子层）；
///           2. 反复调用 _buildStep(rid, maxSteps)，每次最多处理 maxSteps 个配对哈希；
///           3. 当层只剩 1 个节点时返回 root。
///         哈希约定与 V5 BetRoot 一致：sorted-pair keccak256(h1, h2)，
///         奇数个节点时最后一个节点自我配对（duplicate-last）。
abstract contract MerkleBuilder {
    mapping(uint256 => bytes32[]) internal _cur;   // 当前层节点
    mapping(uint256 => bytes32[]) internal _nxt;   // 下一层节点
    mapping(uint256 => uint256) internal _pairCursor; // 当前层已处理的节点下标

    error BuilderLevelEmptyErr();

    /// @dev 向当前层追加一个节点（仅允许在“未开始配对”时追加）。
    function _pushLeaf(uint256 rid, bytes32 node) internal {
        require(_pairCursor[rid] == 0 && _nxt[rid].length == 0, "builder: pairing started");
        _cur[rid].push(node);
    }

    /// @dev 当前层节点数。
    function _levelLength(uint256 rid) internal view returns (uint256) {
        return _cur[rid].length;
    }

    /// @dev sorted-pair 哈希，与 V5 _verifyProof 的约定一致。
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b
            ? keccak256(abi.encodePacked(a, b))
            : keccak256(abi.encodePacked(b, a));
    }

    /// @notice 分步构建：每次最多完成 maxSteps 个配对哈希。
    /// @return done   整棵树完成
    /// @return root   完成时的 Merkle Root
    function _buildStep(uint256 rid, uint256 maxSteps)
        internal
        returns (bool done, bytes32 root)
    {
        uint256 len = _cur[rid].length;
        if (len == 0) revert BuilderLevelEmptyErr();

        // 只剩一个节点：整棵树完成
        if (len == 1) {
            return (true, _cur[rid][0]);
        }

        uint256 i = _pairCursor[rid];
        uint256 steps = 0;
        while (i < len && steps < maxSteps) {
            bytes32 left = _cur[rid][i];
            // 奇数节点：最后一个自我配对
            bytes32 right = (i + 1 < len) ? _cur[rid][i + 1] : left;
            _nxt[rid].push(_hashPair(left, right));
            i += 2;
            steps++;
        }
        _pairCursor[rid] = i;

        if (i >= len) {
            // 当前层耗尽：下一层成为当前层
            _cur[rid] = _nxt[rid];
            delete _nxt[rid];
            _pairCursor[rid] = 0;
            if (_cur[rid].length == 1) {
                return (true, _cur[rid][0]);
            }
        }
        return (false, bytes32(0));
    }
}
