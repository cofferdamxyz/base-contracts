// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title USDC
/// @notice Simple ERC20 with 6 decimals and unrestricted mint.
///         Mimics the USDC that Circle DAA would mint to the company wallet
///         in production. For local fork testing only.
contract USDC is ERC20 {
    uint8 private constant _DECIMALS = 6;

    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function decimals() public pure override returns (uint8) {
        return _DECIMALS;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
