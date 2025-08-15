# extensions/fag_sv_adapter.py
from typing import List, Dict, Set, Optional
from web3 import Web3

class FunctionInfo:
    def __init__(self, selector: str, visibility: str = "external",
                 activity_score: float = 1.0,
                 reads: Optional[Set[str]] = None,
                 writes: Optional[Set[str]] = None):
        # 注意：我们用 4-byte 选择子（十六进制字符串）作为函数“名称”键
        self.selector = selector
        self.visibility = visibility
        self.activity_score = activity_score
        self.reads = reads or set()
        self.writes = writes or set()

class ContractInfo:
    def __init__(self):
        # key: function selector (e.g., "a9059cbb")
        self.functions: Dict[str, FunctionInfo] = {}
        # var -> {selector}
        self.read_map: Dict[str, Set[str]] = {}
        self.write_map: Dict[str, Set[str]] = {}

    def add_function(self, f: FunctionInfo):
        self.functions[f.selector] = f

def build_contract_info_from_abi(abi: List[dict]) -> ContractInfo:
    """
    Phase 1：仅基于 ABI 构造最小 ContractInfo（统一视为 external，
    暂不提供读/写依赖与活跃度；后续 Phase 2 再补）
    """
    ci = ContractInfo()
    for field in abi:
        t = field.get("type")
        if t == "function":
            name = field.get("name")
            inputs = field.get("inputs", [])
            signature = name + "(" + ",".join(i["type"] for i in inputs) + ")"
            selector = Web3.sha3(text=signature)[:4].hex()  # 4-byte 选择子
            ci.add_function(FunctionInfo(selector=selector, visibility="external", activity_score=1.0))
        elif t == "constructor":
            # constructor 不加入 functions；由 Generator 对构造交易
            pass
        elif t == "fallback":
            # fallback 也跳过；若需要可按需加入
            pass
    return ci

def generate_sequences(contract: ContractInfo, include_self_pairs: bool = True) -> List[List[str]]:
    """
    FAGSV 的“简化版本”：
    1) 所有 external/public 可调用函数（此处统一 external）
    2) 按 activity_score 降序（Phase 1 都是 1.0）
    3) 读/写依赖序列（Phase 1 因为空，先跳过；Phase 2 会启用）
    4) 自调用序列 [f, f]（用于促发重入/状态重复迁移）
    5) 去重保序
    """
    funcs = [f for f in contract.functions.values() if f.visibility in ("public", "external")]
    funcs.sort(key=lambda x: x.activity_score, reverse=True)

    sequences: List[List[str]] = []

    # 单函数序列
    for f in funcs:
        sequences.append([f.selector])

    # 依赖前置序列（Phase 1 无读写图，预留接口）
    for f in funcs:
        if not f.reads:
            continue
        writers: Set[str] = set()
        for v in f.reads:
            writers |= contract.write_map.get(v, set())
        ordered_writers = sorted([w for w in writers if w in contract.functions and w != f.selector],
                                 key=lambda s: contract.functions[s].activity_score, reverse=True)
        if ordered_writers:
            sequences.append(ordered_writers + [f.selector])

    # 自调用序列
    if include_self_pairs:
        for f in funcs:
            sequences.append([f.selector, f.selector])

    # 去重保序
    seen = set()
    uniq = []
    for seq in sequences:
        k = tuple(seq)
        if k not in seen:
            uniq.append(seq)
            seen.add(k)
    return uniq