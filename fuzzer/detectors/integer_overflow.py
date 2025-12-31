#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from z3 import BitVec
from utils.utils import convert_stack_value_to_int, convert_stack_value_to_hex

class IntegerOverflowDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 101
        self.severity = "High"
        self.overflows = {}
        self.underflows = {}

    def _taint_is_numeric(self, taint_index, individual, transaction_index):
        if not taint_index:
            return False
        if "callvalue" in taint_index:
            return True
        if "calldataload" not in taint_index:
            return False
        _function_hash = None
        try:
            _function_hash = individual.chromosome[transaction_index]["arguments"][0]
        except Exception:
            return False
        for tx_str, arg_str in re.findall(r"calldataload_(\d+)_(\d+)", taint_index):
            try:
                if int(tx_str) != transaction_index:
                    continue
                arg_idx = int(arg_str)
                arg_type = individual.generator.interface[_function_hash][arg_idx]
                if arg_type.startswith(("uint", "int")):
                    return True
            except Exception:
                continue
        return False

    def detect_integer_overflow(self, mfe, tainted_record, previous_instruction, current_instruction, individual, transaction_index):
        # Skip the specific Solidity pattern used to negate values (NOT + ADD),
        # but do not disable overflow detection globally (was sticky before).
        compiler_value_negation = (
            previous_instruction
            and previous_instruction["op"] == "NOT"
            and current_instruction
            and current_instruction["op"] == "ADD"
        )
        # Addition
        if previous_instruction and previous_instruction["op"] == "ADD":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2])
            b = convert_stack_value_to_int(previous_instruction["stack"][-1])
            has_overflow = (a + b != convert_stack_value_to_int(current_instruction["stack"][-1])) and not compiler_value_negation
            taint_sources = []
            if tainted_record and tainted_record.stack:
                for pos in (-1, -2):
                    if len(tainted_record.stack) >= abs(pos) and tainted_record.stack[pos]:
                        taint_sources.append(''.join(str(taint) for taint in tainted_record.stack[pos]))
            if not taint_sources:
                fallback_record = mfe.symbolic_taint_analyzer.get_tainted_record(index=-1)
                if fallback_record and fallback_record.stack:
                    for pos in (-1, -2):
                        if len(fallback_record.stack) >= abs(pos) and fallback_record.stack[pos]:
                            taint_sources.append(''.join(str(taint) for taint in fallback_record.stack[pos]))
            if not taint_sources:
                taint_sources.append(f"overflow_{hex(previous_instruction['pc'])}")

            if has_overflow:
                try:
                    from utils.utils import initialize_logger
                    logger = initialize_logger("IntOverflow")
                    logger.debug("ADD overflow candidate at pc %s (tx %s): a=%s b=%s res=%s",
                                 hex(previous_instruction.get("pc", 0)),
                                 transaction_index,
                                 a, b,
                                 convert_stack_value_to_int(current_instruction["stack"][-1]))
                except Exception:
                    pass

                for index in taint_sources:
                    if self._taint_is_numeric(index, individual, transaction_index):
                        _function_hash = individual.chromosome[transaction_index]["arguments"][0]
                        _is_string = False
                        for _argument_index in [int(a.split("_")[-1]) for a in index.split() if a.startswith("calldataload_"+str(transaction_index)+"_")]:
                            if individual.generator.interface[_function_hash][_argument_index] == "string":
                                _is_string = True
                        if not _is_string:
                            self.overflows[index] = previous_instruction["pc"], transaction_index
                            # Report immediately if the overflow stems from user-controlled data,
                            # even if it does not flow into storage/conditions later.
                            return previous_instruction["pc"], transaction_index, "overflow"
                # Overflow observed but taint not propagated properly; still report it generically
                index = taint_sources[0]
                self.overflows[index] = previous_instruction["pc"], transaction_index
                return previous_instruction["pc"], transaction_index, "overflow"
            else:
                if compiler_value_negation:
                    return None, None, None
                # No concrete overflow, but arithmetic on tainted numeric data can still be unsafe.
                for index in taint_sources:
                    if self._taint_is_numeric(index, individual, transaction_index):
                        self.overflows[index] = previous_instruction["pc"], transaction_index
                        return previous_instruction["pc"], transaction_index, "overflow"
        # Multiplication
        elif previous_instruction and previous_instruction["op"] == "MUL":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2])
            b = convert_stack_value_to_int(previous_instruction["stack"][-1])
            taint_sources = []
            if tainted_record and tainted_record.stack:
                for pos in (-1, -2):
                    if len(tainted_record.stack) >= abs(pos) and tainted_record.stack[pos]:
                        taint_sources.append(''.join(str(taint) for taint in tainted_record.stack[pos]))
            if not taint_sources:
                fallback_record = mfe.symbolic_taint_analyzer.get_tainted_record(index=-1)
                if fallback_record and fallback_record.stack:
                    for pos in (-1, -2):
                        if len(fallback_record.stack) >= abs(pos) and fallback_record.stack[pos]:
                            taint_sources.append(''.join(str(taint) for taint in fallback_record.stack[pos]))
            if not taint_sources:
                taint_sources.append(f"overflow_{hex(previous_instruction['pc'])}")
            if a * b != convert_stack_value_to_int(current_instruction["stack"][-1]):
                try:
                    from utils.utils import initialize_logger
                    logger = initialize_logger("IntOverflow")
                    logger.debug("MUL overflow candidate at pc %s (tx %s): a=%s b=%s res=%s",
                                 hex(previous_instruction.get("pc", 0)),
                                 transaction_index,
                                 a, b,
                                 convert_stack_value_to_int(current_instruction["stack"][-1]))
                except Exception:
                    pass
                for index in taint_sources:
                    if "calldataload" in index or "callvalue" in index:
                        self.overflows[index] = previous_instruction["pc"], transaction_index
                        return previous_instruction["pc"], transaction_index, "overflow"
                index = taint_sources[0]
                self.overflows[index] = previous_instruction["pc"], transaction_index
                return previous_instruction["pc"], transaction_index, "overflow"
            else:
                for index in taint_sources:
                    if self._taint_is_numeric(index, individual, transaction_index):
                        self.overflows[index] = previous_instruction["pc"], transaction_index
                        return previous_instruction["pc"], transaction_index, "overflow"
        # Subtraction
        elif previous_instruction and previous_instruction["op"] == "SUB":
            a = convert_stack_value_to_int(previous_instruction["stack"][-1])
            b = convert_stack_value_to_int(previous_instruction["stack"][-2])
            result_val = convert_stack_value_to_int(current_instruction["stack"][-1])
            # Underflow wraps to a huge 256-bit value (typically > 2^255).
            underflow = result_val > (1 << 255)

            index = None
            if tainted_record and tainted_record.stack:
                # Prefer taint on either operand
                for pos in (-1, -2):
                    if len(tainted_record.stack) >= abs(pos) and tainted_record.stack[pos]:
                        index = ''.join(str(taint) for taint in tainted_record.stack[pos])
                        break

            if not index:
                # Fallback: grab the most recent taint record to avoid missing inter-contract flows
                fallback_record = mfe.symbolic_taint_analyzer.get_tainted_record(index=-1)
                if fallback_record and fallback_record.stack:
                    for pos in (-1, -2):
                        if len(fallback_record.stack) >= abs(pos) and fallback_record.stack[pos]:
                            index = ''.join(str(taint) for taint in fallback_record.stack[pos])
                            break

            if underflow:
                if not index:
                    # Last resort: synthesize an identifier so we still report the underflow
                    index = "underflow_" + hex(previous_instruction["pc"])

                self.underflows[index] = previous_instruction["pc"], transaction_index
                return previous_instruction["pc"], transaction_index, "underflow"
            elif index and self._taint_is_numeric(index, individual, transaction_index):
                self.underflows[index] = previous_instruction["pc"], transaction_index
                return previous_instruction["pc"], transaction_index, "underflow"
        # Check if overflow flows into storage
        if current_instruction and current_instruction["op"] == "SSTORE":
            if tainted_record and tainted_record.stack and tainted_record.stack[-2]: # Storage value
                index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                if index in self.overflows:
                    return self.overflows[index][0], self.overflows[index][1], "overflow"
                if index in self.underflows:
                    return self.underflows[index][0], self.underflows[index][1], "underflow"
        # Check if overflow flows into call
        elif current_instruction and current_instruction["op"] == "CALL":
            if tainted_record and tainted_record.stack and tainted_record.stack[-3]: # Call value
                index = ''.join(str(taint) for taint in tainted_record.stack[-3])
                if index in self.overflows:
                    return self.overflows[index][0], self.overflows[index][1], "overflow"
                if index in self.underflows:
                    return self.underflows[index][0], self.underflows[index][1], "underflow"
        # Check if overflow flows into condition
        elif current_instruction and current_instruction["op"] in ["LT", "GT", "SLT", "SGT", "EQ"]:
            if tainted_record and tainted_record.stack:
                if tainted_record.stack[-1]: # First operand
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    if index in self.overflows:
                        return self.overflows[index][0], self.overflows[index][1], "overflow"
                    if index in self.underflows:
                        return self.underflows[index][0], self.underflows[index][1], "underflow"
                if tainted_record.stack[-2]: # Second operand
                    index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                    if index in self.overflows:
                        return self.overflows[index][0], self.overflows[index][1], "overflow"
                    if index in self.underflows:
                        return self.underflows[index][0], self.underflows[index][1], "underflow"
        return None, None, None
