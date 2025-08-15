# extensions/fag_sv_adapter.py
from typing import List, Dict, Set, Optional, Tuple
from web3 import Web3

# ---------- Data model ----------

class FunctionInfo:
    def __init__(self, selector: str, visibility: str = "external",
                 activity_score: float = 1.0,
                 reads: Optional[Set[str]] = None,
                 writes: Optional[Set[str]] = None):
        self.selector = selector         # 4-byte selector (hex str, e.g., "a9059cbb")
        self.visibility = visibility     # "public"|"external"  (ABI外部可调视作external)
        self.activity_score = activity_score
        self.reads = reads or set()
        self.writes = writes or set()

class ContractInfo:
    def __init__(self):
        self.functions: Dict[str, FunctionInfo] = {}   # selector -> FunctionInfo
        self.read_map: Dict[str, Set[str]] = {}        # var -> {selector}
        self.write_map: Dict[str, Set[str]] = {}       # var -> {selector}

    def add_function(self, f: FunctionInfo):
        self.functions[f.selector] = f

# ---------- Phase 1: ABI-only (fallback) ----------

def build_contract_info_from_abi(abi: List[dict]) -> ContractInfo:
    ci = ContractInfo()
    for field in abi:
        t = field.get("type")
        if t == "function":
            name = field.get("name")
            inputs = field.get("inputs", [])
            signature = name + "(" + ",".join(i["type"] for i in inputs) + ")"
            selector = Web3.sha3(text=signature)[:4].hex()
            ci.add_function(FunctionInfo(selector=selector, visibility="external", activity_score=1.0))
    return ci

# ---------- Phase 2: AST-driven read/write + score ----------

def build_contract_info_from_ast(abi: List[dict], contract_ast: dict, contract_name: str) -> ContractInfo:
    """
    从 solc 的 AST 中解析：
      - 状态变量集合
      - 每个函数对状态变量的 reads / writes
      - activity_score 启发式评分
    备注：visibility 使用 ABI（出现于 ABI 的函数 => external/public）
    """
    # 1) 找出目标 ContractDefinition 节点
    contract_def = None
    if contract_ast.get("nodeType") == "SourceUnit":
        for node in contract_ast.get("nodes", []):
            if node.get("nodeType") == "ContractDefinition" and node.get("name") == contract_name:
                contract_def = node
                break
    if contract_def is None:
        # 有些编译输出把 ContractDefinition 直接作为 ast 根
        if contract_ast.get("nodeType") == "ContractDefinition" and contract_ast.get("name") == contract_name:
            contract_def = contract_ast
    if contract_def is None:
        raise ValueError(f"AST: ContractDefinition {contract_name} not found")

    # 2) 状态变量集合（名字集合）
    state_vars: Set[str] = set()
    for n in contract_def.get("nodes", []):
        if n.get("nodeType") == "VariableDeclaration" and n.get("stateVariable"):
            state_vars.add(n.get("name"))

    # 3) ABI -> selector 映射（只把外部可调的函数纳入）
    abi_selector_to_entry: Dict[str, dict] = {}
    for field in abi:
        if field.get("type") == "function":
            name = field["name"]
            inputs = field.get("inputs", [])
            sig = name + "(" + ",".join(i["type"] for i in inputs) + ")"
            selector = Web3.sha3(text=sig)[:4].hex()
            abi_selector_to_entry[selector] = field

    # 4) 遍历函数 AST：收集 reads/writes
    ci = ContractInfo()
    fn_selector_to_rw: Dict[str, Tuple[Set[str], Set[str]]] = {}

    # 建立 函数名 -> selector 的映射（用 ABI）
    def name_to_selector(func_name: str, param_count: Optional[int] = None) -> Optional[str]:
        # 粗略：按 name 匹配（如同名重载可按参数个数再筛）
        candidates = []
        for sel, entry in abi_selector_to_entry.items():
            if entry.get("name") == func_name:
                if param_count is None or len(entry.get("inputs", [])) == param_count:
                    candidates.append(sel)
        if not candidates:
            return None
        return candidates[0]  # 简化：取第一个匹配

    # AST helpers
    def collect_idents(expr: dict) -> Set[str]:
        """ 收集表达式中的 Identifier 名字 """
        found = set()
        if not isinstance(expr, dict):
            return found
        if expr.get("nodeType") == "Identifier":
            name = expr.get("name")
            if name:
                found.add(name)
        for k, v in expr.items():
            if isinstance(v, dict):
                found |= collect_idents(v)
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, dict):
                        found |= collect_idents(it)
        return found

    def is_state_var_access(expr: dict, names: Set[str]) -> Set[str]:
        """ 返回此表达式中命中的状态变量名集合（无论读或写上下文） """
        idents = collect_idents(expr)
        return {n for n in idents if n in names}

    def collect_rw_in_statement(stmt: dict, names: Set[str]) -> Tuple[Set[str], Set[str]]:
        reads, writes = set(), set()
        if not isinstance(stmt, dict):
            return reads, writes

        nt = stmt.get("nodeType")

        if nt == "Assignment":
            # 左侧写、右侧读
            left = stmt.get("leftHandSide")
            right = stmt.get("rightHandSide")
            writes |= is_state_var_access(left, names)
            reads  |= is_state_var_access(right, names)

        elif nt == "UnaryOperation":
            # ++ / -- 写；其余一元运算记作读
            op = stmt.get("operator")
            sub = stmt.get("subExpression")
            vars_hit = is_state_var_access(sub, names)
            if op in ("++", "--", "++postfix", "--postfix"):
                writes |= vars_hit
            else:
                reads |= vars_hit

        elif nt in ("ExpressionStatement", "Return", "IfStatement", "WhileStatement", "ForStatement", "DoWhileStatement", "Block", "TryStatement"):
            # 递归子节点
            for k, v in stmt.items():
                if isinstance(v, dict):
                    r, w = collect_rw_in_statement(v, names)
                    reads |= r; writes |= w
                elif isinstance(v, list):
                    for it in v:
                        if isinstance(it, dict):
                            r, w = collect_rw_in_statement(it, names)
                            reads |= r; writes |= w

        else:
            # 通用递归
            for k, v in stmt.items():
                if isinstance(v, dict):
                    r, w = collect_rw_in_statement(v, names)
                    reads |= r; writes |= w
                elif isinstance(v, list):
                    for it in v:
                        if isinstance(it, dict):
                            r, w = collect_rw_in_statement(it, names)
                            reads |= r; writes |= w

        return reads, writes

    # 遍历合约内函数
    for n in contract_def.get("nodes", []):
        if n.get("nodeType") == "FunctionDefinition":
            fn_name = n.get("name")
            if not fn_name:
                # fallback/receive 匿名函数：不作为外部可见函数纳入 FAGSV
                continue
            params = n.get("parameters", {}).get("parameters", []) or []
            selector = name_to_selector(fn_name, param_count=len(params))
            if selector is None or selector not in abi_selector_to_entry:
                continue  # 非外部可调用或 ABI 不含该函数

            # 读取函数体中的读写
            reads, writes = set(), set()
            body = n.get("body")
            if isinstance(body, dict):
                r, w = collect_rw_in_statement(body, state_vars)
                reads |= r; writes |= w

            # 评分（可调参）：写*2 + 读 + 参数数*0.5 + payable(1/0)
            abi_entry = abi_selector_to_entry[selector]
            payable_bonus = 1.0 if abi_entry.get("stateMutability") == "payable" else 0.0
            score = 2.0*len(writes) + 1.0*len(reads) + 0.5*len(abi_entry.get("inputs", [])) + payable_bonus

            ci.add_function(FunctionInfo(
                selector=selector,
                visibility="external",            # ABI 外部可调
                activity_score=score,
                reads=reads,
                writes=writes
            ))

            # 建立读/写映射
            for v in reads:
                ci.read_map.setdefault(v, set()).add(selector)
            for v in writes:
                ci.write_map.setdefault(v, set()).add(selector)

    return ci

def generate_sequences(contract: ContractInfo, include_self_pairs: bool = True) -> List[List[str]]:
    """
    FAGSV（带依赖 + 活跃度）：
      1) 基础序列：每个可调函数独立一条
      2) 依赖前置：若 f 读取 v，则将所有写 v 的函数按活跃度降序放在 f 前，得到链 [writers..., f]
      3) 自调用序列： [f, f] （便于触发重入/状态重复）
      4) 去重保序
    """
    funcs = [f for f in contract.functions.values() if f.visibility in ("public", "external")]
    funcs.sort(key=lambda x: x.activity_score, reverse=True)

    sequences: List[List[str]] = []
    # 单函数
    for f in funcs:
        sequences.append([f.selector])

    # 写->读链
    for f in funcs:
        writers: Set[str] = set()
        for v in f.reads:
            writers |= contract.write_map.get(v, set())
        # 排序并去掉自身
        ordered = [w for w in sorted(list(writers), key=lambda s: contract.functions.get(s, FunctionInfo(s)).activity_score, reverse=True)
                   if w != f.selector]
        if ordered:
            sequences.append(ordered + [f.selector])

    # 自调用
    if include_self_pairs:
        for f in funcs:
            sequences.append([f.selector, f.selector])

    # 去重保序
    seen = set()
    uniq = []
    for seq in sequences:
        k = tuple(seq)
        if k not in seen:
            uniq.append(seq); seen.add(k)
    return uniq