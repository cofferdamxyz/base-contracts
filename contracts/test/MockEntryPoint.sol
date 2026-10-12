// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title MockEntryPoint
/// @notice Minimal deposit bookkeeping (depositTo / balanceOf / withdrawTo) so
///         the paymaster can be tested on the in-memory hardhat network.
contract MockEntryPoint {
    mapping(address => uint256) public balanceOf;

    function depositTo(address account) external payable {
        balanceOf[account] += msg.value;
    }

    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external {
        require(withdrawAmount <= balanceOf[msg.sender], "MockEntryPoint: insufficient deposit");
        balanceOf[msg.sender] -= withdrawAmount;
        (bool ok, ) = withdrawAddress.call{value: withdrawAmount}("");
        require(ok, "MockEntryPoint: withdraw failed");
    }
}
