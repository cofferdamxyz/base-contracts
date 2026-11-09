// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IIdentityEvidenceAdapter
/// @notice The proof check behind `CofferdamIdentityRegistry` (decision 0080):
///         turns an opaque `evidence` blob into the identifier it proves, for
///         one account and one action digest. The registry keeps the binding
///         rules; an adapter only answers "which person, and bound to what".
///         Swapping the adapter changes how a proof is checked without a new
///         account generation, because accounts pin the registry, not the
///         adapter.
/// @dev    An adapter is immutable and stateless towards the registry. It must
///         revert on any failure and never return identifier 0. `verify` is a
///         view, so the registry calls it with STATICCALL and an `eth_call`
///         pre-flight gives the same answer as the transaction.
interface IIdentityEvidenceAdapter {
    /// @notice The identifier derivation this adapter produces (provider,
    ///         identifier type and any key it depends on). A registry holds one
    ///         kind for its lifetime: two kinds name the same person with
    ///         unrelated numbers, so mixing them would let one person hold two
    ///         accounts.
    function identifierKind() external view returns (bytes32);

    /// @notice The scope the identifiers are derived under; one per registry,
    ///         for the same reason as `identifierKind`.
    function scopeId() external view returns (bytes32);

    /// @notice Check that `evidence` proves a person, was made for `account`
    ///         and is bound to `digest`, and return that person's identifier.
    ///         Reverts on any failure.
    function verify(address account, bytes32 digest, bytes calldata evidence)
        external
        view
        returns (bytes32 identifier);
}
