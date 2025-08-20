# extensions/legacy_funseq.py
from typing import Dict, List
from .fag_sv_adapter import build_contract_info_from_ast, build_contract_info_from_abi, generate_sequences
from utils.utils import get_interface_from_abi
import solcx, json

def funInvokSeq(sol_path: str, contract_name: str, abi: list) -> Dict[str, List[str]]:
    """
    兼容你原先的 API（名字/返回结构近似）：
      输入：sol 文件路径、合约名、ABI
      返回：{ function_name: [selector, ..., selector] }
    注意：如果存在同名重载，我们按第一个匹配的 selector。
    """
    # 1) 生成 selector 序列（优先 AST，失败回退 ABI）
    try:
        with open(sol_path, "r", encoding="utf-8") as f:
            _ = f.read()  # 仅用于探测可编译；AST 构建在适配器中完成
        # 构建 ABI->interface 映射
        interface = get_interface_from_abi(abi)
        # AST 路径
        std_in = {
            "language": "Solidity",
            "sources": {sol_path: {"content": _}},
            "settings": {"outputSelection": {"*": {"*": ["abi","evm.bytecode.object","evm.deployedBytecode.object"], "": ["ast"]}}},
        }
        out = solcx.compile_standard(std_in, allow_paths=".")
        ast_root = out.get("sources", {}).get(sol_path, {}).get("ast")
        ci = build_contract_info_from_ast(abi, ast_root, contract_name) if ast_root else None
        sequences = generate_sequences(ci, include_self_pairs=True) if ci else None
    except Exception:
        sequences = None

    if not sequences:
        ci = build_contract_info_from_abi(abi)
        sequences = generate_sequences(ci, include_self_pairs=True)

    # 2) 把“选择子序列”映射为“函数名 -> 序列”（序列仍然用 selector，保持和 Generator 的一致性）
    #    对每个 selector 找对应函数名（若有重载，取第一个）
    sel2name = {}
    for k in interface.keys():
        if k in ("constructor", "fallback"):
            continue
        # 从 ABI 找 name
        for entry in abi:
            if entry.get("type") == "function":
                sig = entry["name"] + "(" + ",".join(inp["type"] for inp in entry.get("inputs",[])) + ")"
                # 你的 utils.get_interface_from_abi 用 Web3.sha3(text=sig)[0:4].hex() 作为 key
        # 直接重用 interface 的 key（已是 selector），需要 name：这里简化为“从 ABI 找第一个具有该 selector 的 name”
    # 解析 ABI -> selector 映射
    from web3 import Web3
    def _sel_of(entry):
        sig = entry["name"] + "(" + ",".join(inp["type"] for inp in entry.get("inputs",[])) + ")"
        return Web3.sha3(text=sig)[0:4].hex()
    for entry in abi:
        if entry.get("type") == "function":
            sel2name.setdefault(_sel_of(entry), entry.get("name"))

    # 聚合
    out_map: Dict[str, List[str]] = {}
    for seq in sequences:
        # 选择一个代表函数名：采用“序列最后一个选择子”的函数名作为 key
        tail = seq[-1]
        fname = sel2name.get(tail, f"func_{tail}")
        out_map[fname] = seq
    return out_map