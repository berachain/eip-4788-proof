// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { SSZ } from "./SSZ.sol";
import { Verifier } from "./Verifier.sol";

contract ValidatorVerifier is Verifier {
    uint64 internal constant VALIDATOR_REGISTRY_LIMIT = 2 << 40;

    /// @dev Generalized index of the first validator struct root in the
    /// registry.
    uint256 public immutable gIndex;

    event Accepted(uint64 indexed validatorIndex);

    constructor(uint256 _gIndex) {
        gIndex = _gIndex;
    }

    function proveValidator(
        bytes32[] calldata validatorProof,
        SSZ.Validator calldata validator,
        uint64 validatorIndex,
        uint64 ts
    ) public {
        require(
            validatorIndex < VALIDATOR_REGISTRY_LIMIT,
            "validator index out of range"
        );

        uint256 gI = gIndex + validatorIndex;
        bytes32 validatoRoot = SSZ.validatorHashTreeRoot(validator);
        bytes32 blockRoot = getParentBlockRoot(ts);

        require(
            // forgefmt: disable-next-item
            SSZ.verifyProof(
                validatorProof,
                blockRoot,
                validatoRoot,
                gI
            ),
            "invalid validator proof"
        );

        emit Accepted(validatorIndex);
    }
}
