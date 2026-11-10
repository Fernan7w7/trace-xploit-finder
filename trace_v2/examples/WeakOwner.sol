// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract WeakOwnerVault {
    address public owner;
    mapping(address => uint256) public deposits;
    constructor() { owner = msg.sender; }
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function claimOwnership() external { owner = msg.sender; } // BUG: unprotected takeover
    function sweep(address to) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "xfer");
    }
    receive() external payable {}
}
