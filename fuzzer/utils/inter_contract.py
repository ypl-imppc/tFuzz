#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lightweight cross-contract call extraction and XCFG builder from Solidity AST.

Inputs: standard-json compiler output with AST enabled.
Outputs:
- contracts: list of contract names found in the given source
- xcfg: { (A, f) : set of (B, g) } where A.f makes external calls to B.g
- var_types_by_fn: {(A, f): {varName: ContractTypeName}}

Notes:
- We only use local, syntactic information: function parameters and local/state
  variables whose type is another contract name (UserDefinedTypeName.namePath).
- Calls are recognized as FunctionCall whose expression is MemberAccess with
  expression Identifier (i.e. x.g()), and x was declared with type of another
  contract present in the file. Overloaded functions are recorded by name only.
"""

from typing import Dict, Tuple, Set, List, Optional


def _collect_contract_defs(ast_root: dict) -> Dict[str, dict]:
    """Return {contractName: ContractDefinitionNode} from a SourceUnit/ContractDefinition root."""
    out: Dict[str, dict] = {}
    if not isinstance(ast_root, dict):
        return out
    if ast_root.get("nodeType") == "SourceUnit":
        for n in ast_root.get("nodes", []):
            if isinstance(n, dict) and n.get("nodeType") == "ContractDefinition":
                name = n.get("name")
                if name:
                    out[name] = n
    elif ast_root.get("nodeType") == "ContractDefinition":
        name = ast_root.get("name")
        if name:
            out[name] = ast_root
    return out


def _collect_contract_names(ast_root: dict) -> Set[str]:
    return set(_collect_contract_defs(ast_root).keys())


def _var_type_name(var_decl: dict) -> Optional[str]:
    """Return contract type name if the variable is typed as another contract, else None."""
    if not isinstance(var_decl, dict):
        return None
    if var_decl.get("nodeType") != "VariableDeclaration":
        return None
    t = var_decl.get("typeName") or {}
    if isinstance(t, dict) and t.get("nodeType") == "UserDefinedTypeName":
        # namePath typically holds the contract type identifier
        return t.get("namePath")
    return None


def _collect_fn_params(fn_node: dict) -> List[dict]:
    params = fn_node.get("parameters", {})
    return (params.get("parameters") or []) if isinstance(params, dict) else []


def _collect_local_var_decls(stmt: dict) -> List[dict]:
    out: List[dict] = []
    if not isinstance(stmt, dict):
        return out
    stack = [stmt]
    while stack:
        n = stack.pop()
        if not isinstance(n, dict):
            continue
        if n.get("nodeType") == "VariableDeclarationStatement":
            for v in n.get("declarations", []) or []:
                if isinstance(v, dict):
                    out.append(v)
        # descend
        for _, v in n.items():
            if isinstance(v, dict):
                stack.append(v)
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, dict):
                        stack.append(it)
    return out


def _find_member_calls(stmt: dict) -> List[Tuple[str, str]]:
    """Return [(baseIdent, memberName)] pairs for x.g(...) occurrences in stmt tree."""
    res: List[Tuple[str, str]] = []
    if not isinstance(stmt, dict):
        return res
    stack = [stmt]
    while stack:
        n = stack.pop()
        if not isinstance(n, dict):
            continue
        if n.get("nodeType") == "FunctionCall":
            expr = n.get("expression", {})
            if isinstance(expr, dict) and expr.get("nodeType") == "MemberAccess":
                base = expr.get("expression", {})
                if isinstance(base, dict) and base.get("nodeType") == "Identifier":
                    base_name = base.get("name")
                    mem = expr.get("memberName")
                    if base_name and mem:
                        res.append((base_name, mem))
        # descend
        for _, v in n.items():
            if isinstance(v, dict):
                stack.append(v)
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, dict):
                        stack.append(it)
    return res


def build_xcfg_from_standard_json(compiler_output: dict, source_path: str) -> Dict[str, Set[Tuple[Tuple[str, str], Tuple[str, str]]]]:
    """
    Build XCFG edges for a single source file in standard-json output.
    Returns mapping keyed by contract name for clarity:
        { contractA: { ((contractA, fn), (contractB, calleeFn)), ... } }
    """
    xcfg_by_contract: Dict[str, Set[Tuple[Tuple[str, str], Tuple[str, str]]]] = {}
    if not compiler_output:
        return xcfg_by_contract

    ast_root = ((compiler_output.get("sources", {}) or {}).get(source_path, {}) or {}).get("ast")
    contract_defs = _collect_contract_defs(ast_root or {})
    if not contract_defs:
        return xcfg_by_contract
    all_contract_names = set(contract_defs.keys())

    for A_name, A_def in contract_defs.items():
        edges: Set[Tuple[Tuple[str, str], Tuple[str, str]]] = set()
        # state-level contract-typed variables
        state_var_types: Dict[str, str] = {}
        for n in A_def.get("nodes", []) or []:
            if isinstance(n, dict) and n.get("nodeType") == "VariableDeclaration" and n.get("stateVariable"):
                cty = _var_type_name(n)
                if cty and cty in all_contract_names:
                    vname = n.get("name")
                    if vname:
                        state_var_types[vname] = cty

        for n in A_def.get("nodes", []) or []:
            if not (isinstance(n, dict) and n.get("nodeType") == "FunctionDefinition"):
                continue
            fn_name = n.get("name") or ""
            body = n.get("body")
            if not fn_name or not isinstance(body, dict):
                continue  # skip fallback/receive or abstract

            # Build var->contractType mapping: params + local decls + state vars
            var_to_type: Dict[str, str] = {}
            for p in _collect_fn_params(n):
                t = _var_type_name(p)
                if t and t in all_contract_names:
                    v = p.get("name")
                    if v:
                        var_to_type[v] = t
            for v in _collect_local_var_decls(body):
                t = _var_type_name(v)
                if t and t in all_contract_names:
                    vname = v.get("name")
                    if vname:
                        var_to_type[vname] = t
            var_to_type.update(state_var_types)

            for base_ident, member in _find_member_calls(body):
                B = var_to_type.get(base_ident)
                if B and B in all_contract_names:
                    edges.add(((A_name, fn_name), (B, member)))

        xcfg_by_contract[A_name] = edges

    return xcfg_by_contract

