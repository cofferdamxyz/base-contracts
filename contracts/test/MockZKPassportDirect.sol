// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IZKPassportProofVerifier, IZKPassportRootRegistry, IZKPassportSubVerifier} from
    "../identity/zkpassport/IZKPassportDirect.sol";

/// @notice Test double of a version's `SubVerifier`, as
///         `CofferdamZKPassportPepperAdapter` reads it: a pause, the outer
///         verifier per vkey hash and the global OPRF key hash.
contract MockZKPassportSubVerifier is IZKPassportSubVerifier {
    address public immutable owner = msg.sender;
    address public immutable rootVerifier;
    bool public paused;
    bytes32 public globalOPRFPubKeyHash;
    mapping(bytes32 => address) public proofVerifiers;

    constructor(address rootVerifier_, bytes32 globalKeyHash) {
        rootVerifier = rootVerifier_;
        globalOPRFPubKeyHash = globalKeyHash;
    }

    function setPaused(bool p) external {
        require(msg.sender == owner, "owner");
        paused = p;
    }

    function setProofVerifier(bytes32 vkeyHash, address verifier) external {
        require(msg.sender == owner, "owner");
        proofVerifiers[vkeyHash] = verifier;
    }
}

/// @notice Test double of `RootRegistry`: a root is valid for a registry id
///         between two times, inclusive; nothing is valid while paused.
contract MockZKPassportRootRegistry is IZKPassportRootRegistry {
    address public immutable owner = msg.sender;
    bool public paused;
    mapping(bytes32 => mapping(bytes32 => uint256)) public validFrom;
    mapping(bytes32 => mapping(bytes32 => uint256)) public validUntil;

    function setPaused(bool p) external {
        require(msg.sender == owner, "owner");
        paused = p;
    }

    function setRoot(bytes32 registryId, bytes32 root, uint256 from, uint256 until) external {
        require(msg.sender == owner, "owner");
        validFrom[registryId][root] = from;
        validUntil[registryId][root] = until;
    }

    function isRootValid(bytes32 registryId, bytes32 root, uint256 timestamp) external view returns (bool) {
        uint256 until = validUntil[registryId][root];
        return !paused && until != 0 && timestamp >= validFrom[registryId][root] && timestamp <= until;
    }
}

/// @notice Test double of an outer circuit's verifier. A proof is valid when
///         it is `keccak256(abi.encode(SALT, publicInputs))`, so changing any
///         public input after proving invalidates it, as with the real
///         verifier. Each mock has its own salt: a proof made for one never
///         passes another.
contract MockZKPassportProofVerifier is IZKPassportProofVerifier {
    bytes32 public immutable SALT;

    constructor(bytes32 salt) {
        SALT = salt;
    }

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        return proof.length == 32 && bytes32(proof) == keccak256(abi.encode(SALT, publicInputs));
    }
}
