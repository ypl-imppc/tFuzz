#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import simplify
from utils.utils import convert_stack_value_to_int

class ReentrancyDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 107
        self.severity = "High"
        self.sloads = {}
        self.calls = set()

    def detect_reentrancy(self, tainted_record, current_instruction, transaction_index):
        # Remember sloads
        if current_instruction["op"] == "SLOAD":
            if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                storage_index = convert_stack_value_to_int(current_instruction["stack"][-1])
                self.sloads[storage_index] = current_instruction["pc"], transaction_index
        # Track CALLs with enough gas/value and tainted destination/value, even if no prior SLOAD was seen.
        elif current_instruction["op"] == "CALL":
            stack = current_instruction.get("stack", [])
            if len(stack) < 7:
                return None, None
            # CALL arguments (top of stack is outSize): [gas, to, value, inOffset, inSize, outOffset, outSize]
            gas = convert_stack_value_to_int(stack[-7])
            value = convert_stack_value_to_int(stack[-5])
            value_tainted = tainted_record and tainted_record.stack and len(tainted_record.stack) >= 5 and tainted_record.stack[-5]
            dest_tainted = tainted_record and tainted_record.stack and len(tainted_record.stack) >= 6 and tainted_record.stack[-6]
            if gas > 2300 and (value > 0 or value_tainted):
                self.calls.add((current_instruction["pc"], transaction_index))
            if gas > 2300 and dest_tainted:
                self.calls.add((current_instruction["pc"], transaction_index))
                # Classic pattern: SLOAD -> CALL -> SSTORE on same slot
                if self.sloads:
                    for pc, index in self.sloads.values():
                        if pc < current_instruction["pc"]:
                            return current_instruction["pc"], index
                # Heuristic: tainted destination/value external call with enough gas is reentrancy-prone
                if value > 0 or value_tainted:
                    return current_instruction["pc"], transaction_index
        # Check if this sstore is happening after a call and if it is happening after an sload which shares the same storage index
        elif current_instruction["op"] == "SSTORE" and self.calls:
            if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                storage_index = convert_stack_value_to_int(current_instruction["stack"][-1])
                if storage_index in self.sloads:
                    for pc, index in self.calls:
                        if pc < current_instruction["pc"]:
                            return pc, index
        # Clear sloads and calls from previous transactions
        elif current_instruction["op"] in ["STOP", "RETURN", "REVERT", "ASSERTFAIL", "INVALID", "SUICIDE", "SELFDESTRUCT"]:
            self.sloads = {}
            self.calls = set()
        return None, None
