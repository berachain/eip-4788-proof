// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { SSZ } from "./SSZ.sol";

contract WithdrawalsVerifier {
    address public constant BEACON_ROOTS =
        0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    uint64 constant MAX_WITHDRAWALS = 2 ** 4;

    // Generalized index of the first withdrawal struct root in the withdrawals.
    uint256 public immutable gIndex;

    /// @notice Emitted when a withdrawal is submitted
    event WithdrawalSubmitted(uint64 indexed validatorIndex, uint64 amount);

    error RootNotFound();

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

    function getParentBlockRoot(uint64 ts)
        internal
        view
        returns (bytes32 root)
    {
        assembly ("memory-safe") {
            mstore(0, ts)
            let success := staticcall(gas(), BEACON_ROOTS, 0, 0x20, 0, 0x20)
            if iszero(success) {
                mstore(0, 0x3033b0ff) // RootNotFound()
                revert(0x1c, 0x04)
            }
            root := mload(0)
        }
    }
}
