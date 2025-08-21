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

    # ---- helpers for per-function Key Attributes & call graph ----
    def has_key_attributes_in_statement(stmt: dict) -> bool:
        """Return True if any of the three Key Attributes appear inside this statement tree."""
        if not isinstance(stmt, dict):
            return False
        stack = [stmt]
        def get(node, *path, default=None):
            cur = node
            for p in path:
                if isinstance(cur, dict) and p in cur:
                    cur = cur[p]
                else:
                    return default
            return cur
        while stack:
            n = stack.pop()
            if not isinstance(n, dict):
                continue
            nt = n.get("nodeType")
            # KA1: value-bearing external calls (call{value}, transfer/send)
            if nt == "FunctionCall":
                names = n.get("names") or []
                if names:
                    lower = [str(x).lower() for x in names]
                    if "value" in lower:
                        return True
                expr = n.get("expression", {})
                if isinstance(expr, dict) and expr.get("nodeType") == "MemberAccess":
                    m = (expr.get("memberName") or "").lower()
                    if m in {"transfer", "send"}:
                        return True
            if nt == "MemberAccess":
                mem = (n.get("memberName") or "").lower()
                if mem in {"call", "value"}:
                    # old-style chain indicator; treat as KA hit conservatively
                    return True
            # KA2: arithmetic ops (+,-,*) or compound (+=,-=,*=)
            if nt == "BinaryOperation" and n.get("operator") in {"+","-","*"}:
                return True
            if nt == "Assignment" and n.get("operator") in {"+=","-=","*="}:
                return True
            # KA3: time references block.timestamp / now
            if nt == "MemberAccess":
                base = get(n, "expression", "name", default="") or get(n, "expression", "memberName", default="")
                mem  = (n.get("memberName") or "").lower()
                if (str(base).lower() == "block" and mem == "timestamp"):
                    return True
            if nt == "Identifier" and (n.get("name") or "").lower() == "now":
                return True
            for _, v in n.items():
                if isinstance(v, dict):
                    stack.append(v)
                elif isinstance(v, list):
                    for it in v:
                        if isinstance(it, dict):
                            stack.append(it)
        return False

    def collect_called_function_names(stmt: dict, own_function_names: Set[str]) -> Set[str]:
        """Collect names of functions (within the same contract) that are called from this statement tree."""
        called: Set[str] = set()
        if not isinstance(stmt, dict):
            return called
        stack = [stmt]
        while stack:
            n = stack.pop()
            if not isinstance(n, dict):
                continue
            nt = n.get("nodeType")
            if nt == "FunctionCall":
                expr = n.get("expression", {})
                # direct internal call: Identifier with function name
                if isinstance(expr, dict) and expr.get("nodeType") == "Identifier":
                    fname = expr.get("name")
                    if fname in own_function_names:
                        called.add(fname)
                # this.f() / super.f() style: MemberAccess -> memberName is function
                if isinstance(expr, dict) and expr.get("nodeType") == "MemberAccess":
                    m = expr.get("memberName")
                    # be conservative: if memberName is one of our function names, count it
                    if m in own_function_names:
                        called.add(m)
            for _, v in n.items():
                if isinstance(v, dict):
                    stack.append(v)
                elif isinstance(v, list):
                    for it in v:
                        if isinstance(it, dict):
                            stack.append(it)
        return called

    # 收集本合约声明的函数名（用于构造调用图）
    own_function_names: Set[str] = set()
    for n in contract_def.get("nodes", []):
        if n.get("nodeType") == "FunctionDefinition" and n.get("name"):
            own_function_names.add(n.get("name"))

    # 第一遍：收集每个函数的读/写、体节点、KeyAttributes、以及它调用了谁
    tmp_funcs = []  # list of dict: {name, selector, body, reads, writes, has_global_flag, has_ka_flag, calls}
    for n in contract_def.get("nodes", []):
        if n.get("nodeType") == "FunctionDefinition":
            fn_name = n.get("name")
            if not fn_name:
                continue  # 匿名/fallback/receive 不纳入
            params = n.get("parameters", {}).get("parameters", []) or []
            selector = name_to_selector(fn_name, param_count=len(params))
            if selector is None or selector not in abi_selector_to_entry:
                continue  # 非外部可调用或 ABI 不含该函数

            reads, writes = set(), set()
            body = n.get("body")
            if isinstance(body, dict):
                r, w = collect_rw_in_statement(body, state_vars)
                reads |= r; writes |= w
            has_global_flag = 1 if (reads or writes) else 0
            has_ka_flag = 1 if (isinstance(body, dict) and has_key_attributes_in_statement(body)) else 0
            calls = collect_called_function_names(body, own_function_names) if isinstance(body, dict) else set()

            tmp_funcs.append({
                "name": fn_name,
                "selector": selector,
                "body": body,
                "reads": reads,
                "writes": writes,
                "has_global_flag": has_global_flag,
                "has_ka_flag": has_ka_flag,
                "calls": calls,
            })

    # 构建入度（函数被多少其他函数调用）
    in_deg: Dict[str, int] = {f["name"]: 0 for f in tmp_funcs}
    for f in tmp_funcs:
        caller = f["name"]
        for callee in f["calls"]:
            if callee in in_deg and callee != caller:
                in_deg[callee] += 1

    # 第二遍：计算评分并写入 ContractInfo
    for f in tmp_funcs:
        fn_name = f["name"]
        selector = f["selector"]
        reads, writes = f["reads"], f["writes"]
        # 评分 = 0.1*全局变量 + 0.5*关键属性 + 0.4*函数入度
        score = 0.1 * float(f["has_global_flag"]) + 0.5 * float(f["has_ka_flag"]) + 0.4 * float(in_deg.get(fn_name, 0))

        ci.add_function(FunctionInfo(
            selector=selector,
            visibility="external",
            activity_score=score,
            reads=reads,
            writes=writes,
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