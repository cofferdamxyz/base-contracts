// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title SelfAttesterRegistry
/// @notice Allow-list of ECDSA recovery addresses corresponding to Self.xyz TEE
///         attester keys. Bridges Self's TEE trust model with onchain enforcement.
/// @dev    Signature scheme: EIP-191 personal_sign over a 32-byte message hash.
///         Layout of the message is decided by the caller (e.g. NullifierRegistry).
///         This contract is pure Solidity.
contract SelfAttesterRegistry {
    address public owner;
    address public pendingOwner;

    mapping(address => bool) public isTrustedAttester;
    uint256 public trustedAttesterCount;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event AttesterAdded(address indexed attester);
    event AttesterRemoved(address indexed attester);

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error AlreadyTrusted();
    error NotTrusted();
    error InvalidSignatureLength();
    error InvalidSignatureValueS();
    error InvalidSignatureValueV();
    error ZeroRecoveredAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _initialOwner, address[] memory _initialAttesters) {
        if (_initialOwner == address(0)) revert ZeroAddress();
        owner = _initialOwner;
        emit OwnershipTransferred(address(0), _initialOwner);
        for (uint256 i = 0; i < _initialAttesters.length; i++) {
            _addAttester(_initialAttesters[i]);
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

    function renounceOwnership() external onlyOwner {
        address previous = owner;
        owner = address(0);
        pendingOwner = address(0);
        emit OwnershipTransferred(previous, address(0));
    }

    function addAttester(address attester) external onlyOwner {
        _addAttester(attester);
    }

    function addAttesters(address[] calldata attesters) external onlyOwner {
        for (uint256 i = 0; i < attesters.length; i++) {
            _addAttester(attesters[i]);
        }
    }

    function removeAttester(address attester) external onlyOwner {
        if (!isTrustedAttester[attester]) revert NotTrusted();
        isTrustedAttester[attester] = false;
        trustedAttesterCount -= 1;
        emit AttesterRemoved(attester);
    }

    function _addAttester(address attester) internal {
        if (attester == address(0)) revert ZeroAddress();
        if (isTrustedAttester[attester]) revert AlreadyTrusted();
        isTrustedAttester[attester] = true;
        trustedAttesterCount += 1;
        emit AttesterAdded(attester);
    }

    function verifyAttesterSig(bytes32 messageHash, bytes calldata signature)
        external
        view
        returns (bool)
    {
        address recovered = _recover(messageHash, signature);
        return isTrustedAttester[recovered];
    }

    function toEthSignedMessageHash(bytes32 hash) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _recover(bytes32 messageHash, bytes calldata signature)
        internal
        pure
        returns (address)
    {
        if (signature.length != 65) revert InvalidSignatureLength();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignatureValueS();
        }
        if (v != 27 && v != 28) revert InvalidSignatureValueV();

        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        address recovered = ecrecover(ethHash, v, r, s);
        if (recovered == address(0)) revert ZeroRecoveredAddress();
        return recovered;
    }
}
