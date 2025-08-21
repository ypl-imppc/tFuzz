

# -*- coding: utf-8 -*-
"""
Key Attributes extraction for Solidity source (AST-based).

Rules (score += 1 for each category present, total in [0..3]):
  KA1: Value-bearing external calls -> addr.call{value: ...}(...), .transfer(...), .send(...)
  KA2: Arithmetic ops or compound assignments -> +, -, *, +=, -=, *=
  KA3: Time references -> block.timestamp, now

Usage:
  from .key_attributes import compute_key_attributes
  ka = compute_key_attributes(ast_root)
  # ka = {"has_value_call": bool, "has_arith_ops": bool, "has_time_ref": bool, "score": int}
"""
from typing import Dict


def compute_key_attributes(ast_root: dict) -> Dict[str, object]:
    """
    Compute Key Attributes from a Solidity AST root.
    Returns a dict with three boolean flags and an integer score in [0..3]:
      {
        "has_value_call": bool,   # KA1: value-bearing external calls (call{value}, transfer, send)
        "has_arith_ops": bool,    # KA2: +, -, * or +=, -=, *=
        "has_time_ref": bool,     # KA3: block.timestamp or now()
        "score": int
      }
    """
    ka1 = ka2 = ka3 = False
    stack = [ast_root]

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

        # ---------- KA1: value-bearing external calls ----------
        # New-style: addr.call{value: ...}(...)
        if n.get("nodeType") == "FunctionCall":
            names = n.get("names") or []
            if names:
                lower_names = [str(x).lower() for x in names]
                if "value" in lower_names:
                    ka1 = True
            # .transfer(...) / .send(...)
            expr = n.get("expression", {})
            if isinstance(expr, dict) and expr.get("nodeType") == "MemberAccess":
                m = (expr.get("memberName") or "").lower()
                if m in {"transfer", "send"}:
                    ka1 = True

        # Old-style chains like something.call.value(...)
        # (We keep this as a soft signal; concrete detection is via FunctionCall above)
        if n.get("nodeType") == "MemberAccess":
            mem = (n.get("memberName") or "").lower()
            if mem in {"call", "value"}:  # presence in chain often indicates call.value
                pass  # covered via FunctionCall with names/value when invoked

        # ---------- KA2: arithmetic ops and compound assignments ----------
        if n.get("nodeType") == "BinaryOperation":
            op = n.get("operator")
            if op in {"+", "-", "*"}:
                ka2 = True
        if n.get("nodeType") == "Assignment":
            op = n.get("operator")
            if op in {"+=", "-=", "*="}:
                ka2 = True

        # ---------- KA3: time references ----------
        if n.get("nodeType") == "MemberAccess":
            # block.timestamp
            base = get(n, "expression", "name", default="") or get(n, "expression", "memberName", default="")
            mem  = (n.get("memberName") or "").lower()
            if (str(base).lower() == "block" and mem == "timestamp"):
                ka3 = True
        if n.get("nodeType") == "Identifier":
            if (n.get("name") or "").lower() == "now":
                ka3 = True

        # continue traversal
        for _, v in n.items():
            if isinstance(v, dict):
                stack.append(v)
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, dict):
                        stack.append(it)

    score = int(ka1) + int(ka2) + int(ka3)
    return {
        "has_value_call": ka1,
        "has_arith_ops": ka2,
        "has_time_ref": ka3,
        "score": score,
    }