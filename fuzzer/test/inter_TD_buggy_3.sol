// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract Test2 {
    function bug_time_inter(Test1 t1, uint b) public payable returns (uint) {
        uint goal_ = t1.getGoal();
        if (3000 == goal_) {
            // 时间戳依赖（漏洞点）：仍然依赖区块时间
            if (block.timestamp % 15 == 0) { // winner
                // 在 0.8+ 里需要显式转换为 payable
                payable(msg.sender).transfer(goal_);
            }
        }
        return b; // 避免 returns(uint) 报错
    }
}

contract Test1 {
    uint public goal = 5000;
    function getGoal() public view returns (uint) { // 标注 view
        return goal;
    }
}