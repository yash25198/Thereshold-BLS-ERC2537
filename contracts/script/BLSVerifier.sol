// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {BLSVerifier} from "../src/BLSVerifier.sol";

contract BLSVerifierScript is Script {
    BLSVerifier public blsVerifier;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        blsVerifier = new BLSVerifier();

        vm.stopBroadcast();
    }
}
