// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { SSZ } from "./SSZ.sol";
import { Verifier } from "./Verifier.sol";

contract WithdrawalsVerifier is Verifier {
    uint64 internal constant MAX_WITHDRAWALS = 2 << 4;

    // Generalized index of the first withdrawal struct root in the withdrawals.
    uint256 public immutable gIndex;

    /// @notice Emitted when a withdrawal is submitted
    event WithdrawalSubmitted(uint64 indexed validatorIndex, uint64 amount);

    constructor(uint256 _gIndex) {
        gIndex = _gIndex;
    }

    function submitWithdrawal(
        bytes32[] calldata withdrawalProof,
        SSZ.Withdrawal memory withdrawal,
        uint8 withdrawalIndex,
        uint64 ts
    ) public {
        // forgefmt: disable-next-item
        require(
            withdrawalIndex < MAX_WITHDRAWALS,
            "withdrawal index out of range"
        );

        uint256 gI = gIndex + withdrawalIndex;
        bytes32 withdrawalRoot = SSZ.withdrawalHashTreeRoot(withdrawal);
        bytes32 blockRoot = getParentBlockRoot(ts);

        require(
            // forgefmt: disable-next-item
            SSZ.verifyProof(
                withdrawalProof,
                blockRoot,
                withdrawalRoot,
                gI
            ),
            "invalid withdrawal proof"
        );

        emit WithdrawalSubmitted(withdrawal.validatorIndex, withdrawal.amount);
    }
}
