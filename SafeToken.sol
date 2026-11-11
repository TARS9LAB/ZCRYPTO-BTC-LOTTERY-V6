// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
}

/// @dev 最小 SafeERC20：兼容返回 false 的非标准代币（BSC USDT 返回 bool）。
library SafeToken {
    error TransferFailedErr();
    error TransferFromFailedErr();
    error ApproveFailedErr();

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IERC20.transfer.selector, to, value));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailedErr();
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, value));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFromFailedErr();
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IERC20.approve.selector, spender, value));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert ApproveFailedErr();
    }
}
