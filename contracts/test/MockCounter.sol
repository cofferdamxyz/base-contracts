// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title MockCounter
/// @notice Simple counter contract for integration testing.
///         The CofferdamAccount4337.execute() call increments this.
contract MockCounter {
    uint256 public value;

    function increment() external {
        value += 1;
    }

    /// @notice Accepts ETH, for tests of a permission's value cap.
    function deposit() external payable {}
}
