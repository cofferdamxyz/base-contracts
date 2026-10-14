// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title CofferdamModuleRegistry
/// @notice Allowlist of authority modules a `CofferdamAccount4337` may install,
///         at genesis or later (decision 0016). The factory pins one registry
///         into every account it deploys. A new module (a post-quantum scheme,
///         a new Partner shape) is a decision plus an entry here, so the
///         account stays crypto-agile without accepting arbitrary code: a
///         module that returns `true` for anyone is a full backdoor.
/// @dev    Owner is the Cofferdam Inc. Safe on mainnet, with a two-step
///         transfer. Removing a module stops new installs only; authorities
///         already on accounts keep working (the account never reads this
///         registry during validation, which ERC-7562 would forbid) and are
///         revoked by their account's High authority.
///         On mainnet only the `cofferdam.xyz`-pinned `WebAuthnPasskeyAuthority`
///         is listed for High: the raw P-256 `PasskeyAuthority` has no RP
///         binding and is for local and test networks.
contract CofferdamModuleRegistry {
    address public owner;
    address public pendingOwner;

    mapping(address => bool) public isAllowedModule;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ModuleAllowed(address indexed module);
    event ModuleDisallowed(address indexed module);

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error AlreadyAllowed();
    error NotAllowed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _initialOwner, address[] memory _initialModules) {
        if (_initialOwner == address(0)) revert ZeroAddress();
        owner = _initialOwner;
        emit OwnershipTransferred(address(0), _initialOwner);
        for (uint256 i = 0; i < _initialModules.length; i++) {
            _allow(_initialModules[i]);
        }
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        address previous = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previous, owner);
    }

    function allowModule(address module) external onlyOwner {
        _allow(module);
    }

    function disallowModule(address module) external onlyOwner {
        if (!isAllowedModule[module]) revert NotAllowed();
        isAllowedModule[module] = false;
        emit ModuleDisallowed(module);
    }

    function _allow(address module) internal {
        if (module == address(0)) revert ZeroAddress();
        if (isAllowedModule[module]) revert AlreadyAllowed();
        isAllowedModule[module] = true;
        emit ModuleAllowed(module);
    }
}
