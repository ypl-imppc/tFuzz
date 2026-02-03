// 注意：此代码故意设计为在 Solidity < 0.8.0 下存在跨合约整数溢出漏洞
pragma solidity ^0.7.6; // 明确使用无自动溢出检查的版本

contract CalledRuleContract {
    uint private basethreshold = 50000;

    // 漏洞点：当 currentTarget 很大时，乘法会溢出（在 <0.8.0 中）
    function getThreshold(uint currentTarget) public returns (uint) {
        // 移除原限制 require(currentTarget <= 5);
        // 改为允许任意值，使攻击者可传入极大值
        if (currentTarget == 1) { 
            return basethreshold;
        } else {
            // ⚠️ 危险：currentTarget * 1000 可能溢出！
            uint res = currentTarget * 1000; // 在 0.7.x 中，溢出会 wrap
            return res;
        }
    }
}

contract TargetInvestContract {
    uint public total = 0;
    uint public invalidToken = 0;
    address owner;

    constructor() public {
        owner = msg.sender;
    }

    function invest(
        CalledRuleContract rule, 
        uint target, 
        uint investToken
    ) public {
        // 跨合约调用：此处接收可能因溢出而极小的 threshold 值
        uint threshold = rule.getThreshold(target);

        // 攻击者可使 threshold 因溢出变成很小的数（如 0~50000）
        if (threshold <= 50000 && threshold <= investToken) { 
            total += investToken; // 合法路径被触发
        } else if (threshold > 50000) { 
            invalidToken += investToken;
        }
    }

    modifier onlyOwner() { 
        require(msg.sender == owner); 
        _;
    }

    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function close() public onlyOwner {
        selfdestruct(payable(owner));
    }
}