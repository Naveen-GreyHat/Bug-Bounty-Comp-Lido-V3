// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IVaultHubLike {
    function onVaultDeposit(uint256 vaultId) external payable;
}

contract FakeVault {
    IVaultHubLike public hub;
    uint256 public vaultId;

    constructor(address _hub, uint256 _vaultId) {
        hub = IVaultHubLike(_hub);
        vaultId = _vaultId;
    }

    // attacker-controlled deposit
    function fakeDeposit() external payable {
        // Forward ETH but exploit accounting order
        hub.onVaultDeposit{value: msg.value}(vaultId);
    }
}
