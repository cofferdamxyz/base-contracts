// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {IPaymaster} from "../account/CofferdamPaymaster.sol";

/// @title MockEntryPoint
/// @notice Minimal deposit bookkeeping (depositTo / balanceOf / withdrawTo) so
///         the paymaster can be tested on the in-memory hardhat network, and
///         a pass-through to `validatePaymasterUserOp` so a test controls
///         `tx.origin` (the signer that sends the transaction).
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

    function validatePaymaster(IPaymaster paymaster, IEntryPoint.PackedUserOperation calldata userOp)
        external
        view
        returns (bytes memory context, uint256 validationData)
    {
        return paymaster.validatePaymasterUserOp(userOp, bytes32(0), 0);
    }
}
