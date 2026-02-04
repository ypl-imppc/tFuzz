#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from utils.utils import convert_stack_value_to_int


ARITHMETIC_OPS = {
    "ADD", "SUB", "MUL", "DIV", "SDIV", "MOD", "SMOD", "ADDMOD", "MULMOD",
    "EXP", "SHL", "SHR", "SAR",
}
COMPARE_OPS = {"LT", "GT", "SLT", "SGT", "EQ", "ISZERO"}
HASH_OPS = {"SHA3", "KECCAK256"}
EXTERNAL_CALL_OPS = {"CALL", "DELEGATECALL", "CALLCODE"}
BLOCK_READ_OPS = {"TIMESTAMP", "NUMBER"}
EXTERNAL_INPUT_OPS = {"CALLDATALOAD", "CALLDATACOPY", "CALLVALUE", "CALLER", "SLOAD"}
TERMINATORS = {"STOP", "RETURN", "REVERT", "ASSERTFAIL", "INVALID", "SELFDESTRUCT", "SUICIDE"}


class CompositionalFeatureExtractor:
    def __init__(self):
        self._unchecked_pc_cache = {}

    def new_context(self):
        return {
            "started_at": time.time(),
            "reentrancy": {
                "has_external_call": False,
                "dangerous_call_then_state_write": False,
                "call_in_loop": False,
                "call_with_high_gas": False,
                "guarded_call_pattern": False,
            },
            "overflow": {
                "has_arithmetic": False,
                "unchecked_hit": False,
                "arith_to_sensitive_sink": False,
                "arith_to_key_op": False,
                "operand_from_external_input": False,
                "solidity_ge_08": False,
            },
            "timestamp": {
                "reads_block_var": False,
                "block_var_for_control_flow": False,
                "block_var_for_value_flow": False,
                "only_logging_usage": False,
            },
            "cost": {
                "steps": 0,
                "tx_count": 0,
                "calldata_bytes": 0,
                "wall_time": 0.0,
            },
            "tx_states": [],
        }

    def begin_transaction(self, context, transaction):
        tx_state = {
            "steps": 0,
            "seen_pcs": set(),
            "loop_observed": False,
            "external_call_seen": False,
            "external_call_step": None,
            "pre_call_reads": set(),
            "pre_call_writes": set(),
            "pre_call_any_write": False,
            "last_arith_step": None,
            "last_external_input_step": None,
            "last_block_read_step": None,
            "last_block_compare_step": None,
        }
        context["tx_states"].append(tx_state)
        context["cost"]["tx_count"] += 1
        context["cost"]["calldata_bytes"] += self._calldata_size(transaction)
        return tx_state

    def observe_instruction(self, context, tx_state, instruction, tainted_record, source_map=None):
        op = instruction.get("op")
        if not op:
            return

        context["cost"]["steps"] += 1
        tx_state["steps"] += 1
        step = tx_state["steps"]

        self._update_loop_state(tx_state, instruction)
        self._observe_reentrancy(context, tx_state, instruction)
        self._observe_overflow(context, tx_state, instruction, tainted_record, source_map)
        self._observe_timestamp(context, tx_state, instruction)

    def finalize_context(self, context, solidity_ge_08=False, execution_wall_time=None):
        context["overflow"]["solidity_ge_08"] = bool(solidity_ge_08)
        ts = context["timestamp"]
        ts["only_logging_usage"] = (
            ts["reads_block_var"]
            and not ts["block_var_for_control_flow"]
            and not ts["block_var_for_value_flow"]
        )
        if execution_wall_time is None:
            execution_wall_time = time.time() - context["started_at"]
        context["cost"]["wall_time"] = max(0.0, float(execution_wall_time))
        return {
            "reentrancy": dict(context["reentrancy"]),
            "overflow": dict(context["overflow"]),
            "timestamp": dict(context["timestamp"]),
            "cost": dict(context["cost"]),
        }

    def _update_loop_state(self, tx_state, instruction):
        pc = instruction.get("pc")
        if isinstance(pc, int):
            if pc in tx_state["seen_pcs"]:
                tx_state["loop_observed"] = True
            tx_state["seen_pcs"].add(pc)

        op = instruction.get("op")
        if op in {"JUMP", "JUMPI"}:
            stack = instruction.get("stack", [])
            if stack:
                try:
                    destination = convert_stack_value_to_int(stack[-1])
                    if isinstance(pc, int) and destination < pc:
                        tx_state["loop_observed"] = True
                except Exception:
                    pass

    def _observe_reentrancy(self, context, tx_state, instruction):
        op = instruction.get("op")
        re_features = context["reentrancy"]

        if op == "SLOAD" and not tx_state["external_call_seen"]:
            slot = self._extract_storage_slot(instruction)
            if slot is not None:
                tx_state["pre_call_reads"].add(slot)

        if op == "SSTORE":
            slot = self._extract_storage_slot(instruction)
            if tx_state["external_call_seen"]:
                re_features["dangerous_call_then_state_write"] = True
            else:
                tx_state["pre_call_any_write"] = True
                if slot is not None:
                    tx_state["pre_call_writes"].add(slot)

        if op not in EXTERNAL_CALL_OPS:
            return

        re_features["has_external_call"] = True
        tx_state["external_call_seen"] = True
        if tx_state["external_call_step"] is None:
            tx_state["external_call_step"] = tx_state["steps"]

        if tx_state["loop_observed"]:
            re_features["call_in_loop"] = True

        if self._is_high_gas_forwarding(instruction):
            re_features["call_with_high_gas"] = True

        if tx_state["pre_call_any_write"] or (tx_state["pre_call_reads"] & tx_state["pre_call_writes"]):
            re_features["guarded_call_pattern"] = True

    def _observe_overflow(self, context, tx_state, instruction, tainted_record, source_map):
        op = instruction.get("op")
        of_features = context["overflow"]

        if op in EXTERNAL_INPUT_OPS:
            tx_state["last_external_input_step"] = tx_state["steps"]

        if op in ARITHMETIC_OPS:
            of_features["has_arithmetic"] = True
            tx_state["last_arith_step"] = tx_state["steps"]

            if self._taint_has_external_input(tainted_record):
                of_features["operand_from_external_input"] = True
            elif tx_state["last_external_input_step"] is not None and tx_state["steps"] - tx_state["last_external_input_step"] <= 3:
                of_features["operand_from_external_input"] = True

            pc = instruction.get("pc")
            if isinstance(pc, int) and self._is_unchecked_pc(pc, source_map):
                of_features["unchecked_hit"] = True
            return

        if tx_state["last_arith_step"] is None:
            return
        dist = tx_state["steps"] - tx_state["last_arith_step"]
        if dist < 0:
            return
        if dist <= 5 and (op in COMPARE_OPS or op in {"JUMPI", "REVERT", "ASSERTFAIL", "SSTORE", "CALL"}):
            of_features["arith_to_sensitive_sink"] = True
        if dist <= 3 and op in HASH_OPS:
            of_features["arith_to_key_op"] = True
        if op in TERMINATORS:
            tx_state["last_arith_step"] = None

    def _observe_timestamp(self, context, tx_state, instruction):
        op = instruction.get("op")
        ts_features = context["timestamp"]

        if op in BLOCK_READ_OPS:
            ts_features["reads_block_var"] = True
            tx_state["last_block_read_step"] = tx_state["steps"]
            tx_state["last_block_compare_step"] = None
            return

        if tx_state["last_block_read_step"] is not None:
            read_dist = tx_state["steps"] - tx_state["last_block_read_step"]
            if 0 <= read_dist <= 4 and op in COMPARE_OPS:
                tx_state["last_block_compare_step"] = tx_state["steps"]
            if 0 <= read_dist <= 8 and op in {"CALL", "SSTORE", "MOD", "SMOD", "SHA3", "KECCAK256"}:
                ts_features["block_var_for_value_flow"] = True
            if read_dist > 8 and tx_state["last_block_compare_step"] is None:
                tx_state["last_block_read_step"] = None

        if tx_state["last_block_compare_step"] is not None:
            compare_dist = tx_state["steps"] - tx_state["last_block_compare_step"]
            if 0 <= compare_dist <= 4 and op in {"JUMPI", "REVERT", "ASSERTFAIL"}:
                ts_features["block_var_for_control_flow"] = True
            if compare_dist > 4:
                tx_state["last_block_compare_step"] = None

    def _extract_storage_slot(self, instruction):
        stack = instruction.get("stack", [])
        if not stack:
            return None
        try:
            return int(convert_stack_value_to_int(stack[-1]))
        except Exception:
            return None

    def _is_high_gas_forwarding(self, instruction):
        stack = instruction.get("stack", [])
        op = instruction.get("op")
        if not stack:
            return False
        gas = None
        try:
            if op in {"CALL", "CALLCODE"} and len(stack) >= 7:
                gas = convert_stack_value_to_int(stack[-7])
            elif op == "DELEGATECALL" and len(stack) >= 6:
                gas = convert_stack_value_to_int(stack[-6])
        except Exception:
            gas = None
        if gas is None:
            return False
        return int(gas) > 5000

    def _taint_has_external_input(self, tainted_record):
        if not tainted_record or not getattr(tainted_record, "stack", None):
            return False
        try:
            tail = tainted_record.stack[-2:] if len(tainted_record.stack) >= 2 else tainted_record.stack
            for bucket in tail:
                if not bucket:
                    continue
                blob = " ".join(str(x) for x in bucket)
                if any(tok in blob for tok in ("calldataload", "calldatacopy", "callvalue", "caller", "sload")):
                    return True
        except Exception:
            return False
        return False

    def _is_unchecked_pc(self, pc, source_map):
        if pc in self._unchecked_pc_cache:
            return self._unchecked_pc_cache[pc]
        hit = False
        if source_map is not None:
            try:
                snippet = source_map.get_buggy_line(pc) or ""
                hit = "unchecked" in snippet.lower()
            except Exception:
                hit = False
        self._unchecked_pc_cache[pc] = hit
        return hit

    def _calldata_size(self, transaction):
        data = ""
        if isinstance(transaction, dict):
            data = transaction.get("data", "") or ""
        if not isinstance(data, str):
            return 0
        raw = data[2:] if data.startswith("0x") else data
        if not raw:
            return 0
        return int(len(raw) / 2)
