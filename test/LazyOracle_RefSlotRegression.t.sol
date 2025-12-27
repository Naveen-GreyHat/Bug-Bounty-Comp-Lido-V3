// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "../contracts/0.8.25/vaults/LazyOracle.sol";

/* ------------------------------------------------ */
/* Minimal mock for LidoLocator                     */
/* Only accountingOracle() is actually used        */
/* ------------------------------------------------ */
contract MockLidoLocator {
    address private _accountingOracle;

    constructor(address accountingOracle_) {
        _accountingOracle = accountingOracle_;
    }

    function accountingOracle() external view returns (address) {
        return _accountingOracle;
    }
}

/* ------------------------------------------------ */
/* TEST CONTRACT                                   */
/* ------------------------------------------------ */
contract LazyOracleRefSlotRegressionTest is Test {
    LazyOracle oracle;
    address accountingOracle = address(0xBEEF);

    function setUp() public {
        MockLidoLocator locator = new MockLidoLocator(accountingOracle);

        // IMPORTANT:
        // LazyOracle constructor disables initializers,
        // so we DO NOT call initialize()
        oracle = new LazyOracle(address(locator));
    }

    function test_RefSlotRegressionAccepted() public {
        // impersonate AccountingOracle
        vm.startPrank(accountingOracle);

        // First: newer report
        oracle.updateReportData(
            1000,                 // timestamp
            200,                  // refSlot (NEWER)
            bytes32(uint256(1)),
            "cid-new"
        );

        // Second: older report overwrites newer (BUG)
        oracle.updateReportData(
            900,                  // older timestamp
            150,                  // LOWER refSlot
            bytes32(uint256(2)),
            "cid-old"
        );

        vm.stopPrank();

        (, uint256 refSlot,,) = oracle.latestReportData();

        emit log_named_uint("Stored refSlot", refSlot);

        // ❌ EXPECTED TO FAIL (this proves the bug)
        assertEq(refSlot, 200, "RefSlot regression accepted");
    }
}
