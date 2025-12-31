#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import collections

from utils import settings
from utils.utils import *

UINT_MAX = {
    1: int("0xff", 16),
    2: int("0xffff", 16),
    3: int("0xffffff", 16),
    4: int("0xffffffff", 16),
    5: int("0xffffffffff", 16),
    6: int("0xffffffffffff", 16),
    7: int("0xffffffffffffff", 16),
    8: int("0xffffffffffffffff", 16),
    9: int("0xffffffffffffffffff", 16),
    10: int("0xffffffffffffffffffff", 16),
    11: int("0xffffffffffffffffffffff", 16),
    12: int("0xffffffffffffffffffffffff", 16),
    13: int("0xffffffffffffffffffffffffff", 16),
    14: int("0xffffffffffffffffffffffffffff", 16),
    15: int("0xffffffffffffffffffffffffffffff", 16),
    16: int("0xffffffffffffffffffffffffffffffff", 16),
    17: int("0xffffffffffffffffffffffffffffffffff", 16),
    18: int("0xffffffffffffffffffffffffffffffffffff", 16),
    19: int("0xffffffffffffffffffffffffffffffffffffff", 16),
    20: int("0xffffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0xffffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0xffffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0xffffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0xffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0xffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}

INT_MAX = {
    1: int("0x7f", 16),
    2: int("0x7fff", 16),
    3: int("0x7fffff", 16),
    4: int("0x7fffffff", 16),
    5: int("0x7fffffffff", 16),
    6: int("0x7fffffffffff", 16),
    7: int("0x7fffffffffffff", 16),
    8: int("0x7fffffffffffffff", 16),
    9: int("0x7fffffffffffffffff", 16),
    10: int("0x7fffffffffffffffffff", 16),
    11: int("0x7fffffffffffffffffffff", 16),
    12: int("0x7fffffffffffffffffffffff", 16),
    13: int("0x7fffffffffffffffffffffffff", 16),
    14: int("0x7fffffffffffffffffffffffffff", 16),
    15: int("0x7fffffffffffffffffffffffffffff", 16),
    16: int("0x7fffffffffffffffffffffffffffffff", 16),
    17: int("0x7fffffffffffffffffffffffffffffffff", 16),
    18: int("0x7fffffffffffffffffffffffffffffffffff", 16),
    19: int("0x7fffffffffffffffffffffffffffffffffffff", 16),
    20: int("0x7fffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0x7fffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0x7fffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0x7fffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0x7fffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}

INT_MIN = {
    1: int("-0x80", 16),
    2: int("-0x8000", 16),
    3: int("-0x800000", 16),
    4: int("-0x80000000", 16),
    5: int("-0x8000000000", 16),
    6: int("-0x800000000000", 16),
    7: int("-0x80000000000000", 16),
    8: int("-0x8000000000000000", 16),
    9: int("-0x800000000000000000", 16),
    10: int("-0x80000000000000000000", 16),
    11: int("-0x8000000000000000000000", 16),
    12: int("-0x800000000000000000000000", 16),
    13: int("-0x80000000000000000000000000", 16),
    14: int("-0x8000000000000000000000000000", 16),
    15: int("-0x800000000000000000000000000000", 16),
    16: int("-0x80000000000000000000000000000000", 16),
    17: int("-0x8000000000000000000000000000000000", 16),
    18: int("-0x800000000000000000000000000000000000", 16),
    19: int("-0x80000000000000000000000000000000000000", 16),
    20: int("-0x8000000000000000000000000000000000000000", 16),
    21: int("-0x800000000000000000000000000000000000000000", 16),
    22: int("-0x80000000000000000000000000000000000000000000", 16),
    23: int("-0x8000000000000000000000000000000000000000000000", 16),
    24: int("-0x800000000000000000000000000000000000000000000000", 16),
    25: int("-0x80000000000000000000000000000000000000000000000000", 16),
    26: int("-0x8000000000000000000000000000000000000000000000000000", 16),
    27: int("-0x800000000000000000000000000000000000000000000000000000", 16),
    28: int("-0x80000000000000000000000000000000000000000000000000000000", 16),
    29: int("-0x8000000000000000000000000000000000000000000000000000000000", 16),
    30: int("-0x800000000000000000000000000000000000000000000000000000000000", 16),
    31: int("-0x80000000000000000000000000000000000000000000000000000000000000", 16),
    32: int("-0x8000000000000000000000000000000000000000000000000000000000000000", 16)
}

MAX_RING_BUFFER_LENGTH = 10
MAX_ARRAY_LENGTH = 2

class CircularSet:
    def __init__(self, set_size=MAX_RING_BUFFER_LENGTH, initial_set=None):
        self._q = collections.deque(maxlen=set_size)
        if initial_set:
            self._q.extend(initial_set)

    @property
    def empty(self):
        return len(self._q) == 0

    def add(self, value):
        if value not in self._q:
            self._q.append(value)
        else:
            self._q.remove(value)
            self._q.append(value)

    def head_and_rotate(self):
        value = self._q[-1]
        self._q.rotate(1)
        return value

    def discard(self, value):
        if value in self._q:
            self._q.remove(value)

    def __repr__(self):
        return repr(self._q)


class Generator:
    def __init__(self, interface, bytecode, accounts, contract):
        self.logger = initialize_logger("Generator")
        self.interface = interface
        self.bytecode = bytecode
        self.accounts = accounts
        self.contract = contract

        # Pools
        self.function_circular_buffer = CircularSet(set_size=len(self.interface), initial_set=set(self.interface))
        self.accounts_pool = {}
        self.amounts_pool = {}
        self.arguments_pool = {}
        self.timestamp_pool = {}
        self.blocknumber_pool = {}
        self.balance_pool = {}
        self.callresult_pool = {}
        self.gaslimit_pool = {}
        self.extcodesize_pool = {}
        self.returndatasize_pool = {}
        self.argument_array_sizes_pool = {}
        self.strings_pool = CircularSet()
        self.bytes_pool = CircularSet()
        # Addresses known to be valid contract instances (e.g., helper contracts deployed from the same source file)
        self.preferred_addresses = []
        # Parameter usage accounting: {function_selector: {index: {"type": str, "values": set()}}}
        self.param_usage = {}
        # Parameter selection strategy hint: 'mixed'|'basic'|'boundary'
        self.param_strategy = 'mixed'

    # ---- usage recording helpers ----
    def _record_arg_usage(self, function: str, index: int, value, type_str: str = None):
        try:
            if function not in self.param_usage:
                self.param_usage[function] = {}
            if index not in self.param_usage[function]:
                self.param_usage[function][index] = {"type": type_str or "", "values": set()}
            # Flatten lists/arrays
            if isinstance(value, list):
                for v in value:
                    self.param_usage[function][index]["values"].add(str(v))
            else:
                self.param_usage[function][index]["values"].add(str(value))
        except Exception:
            # never break fuzzing on accounting failures
            pass

    def get_argument_value_with_recording(self, type, function, argument_index):
        val = self.get_random_argument(type, function, argument_index)
        self._record_arg_usage(function, argument_index, val, str(type))
        return val

    # ---- NEW: seed argument pools from a simple {type: [values]} dict ----
    def seed_argument_pools_from_typedict(self, type_dict: dict):
        """
        将类似 functionParameter.paramGenerate() 返回的字典：
          {'address':[...], 'uint':[...], 'int':[...], 'bool':[...], 'string':[...], 'byte':[...]}
        注入到当前 generator 的参数池中，覆盖到所有函数的所有同类型形参。
        """
        # 先处理全局字符串/bytes池，便于 get_random_argument 直接复用
        if "string" in type_dict and type_dict["string"]:
            for s in type_dict["string"]:
                self.add_string_to_pool(str(s))
        if "byte" in type_dict and type_dict["byte"]:
            for b in type_dict["byte"]:
                try:
                    # 允许 int / bytes / bytearray
                    if isinstance(b, int):
                        self.add_bytes_to_pool(self.get_random_bytes(1))  # 填个占位，下面统一走 arguments_pool
                    elif isinstance(b, (bytes, bytearray)):
                        self.add_bytes_to_pool(bytes(b))
                except Exception:
                    pass
        
        # 针对每个函数的每个形参位，若类型前缀匹配，则写入 arguments_pool[func][idx]
        def _match_prefix(sol_ty: str) -> str:
            t = sol_ty.lower()
            if t.startswith("uint"):   return "uint"
            if t.startswith("int"):    return "int"
            if t.startswith("address"):return "address"
            if t.startswith("bool"):   return "bool"
            if t.startswith("string"): return "string"
            if t.startswith("bytes"):  # bytes/bytesN 都归为 byte 池
                return "byte"
            return ""
        
        for func_sel, arg_types in self.interface.items():
            if func_sel == "constructor":
                continue
            for idx, ty in enumerate(arg_types):
                key = _match_prefix(ty)
                if key and key in type_dict and type_dict[key]:
                    if func_sel not in self.arguments_pool:
                        self.arguments_pool[func_sel] = dict()
                    if idx not in self.arguments_pool[func_sel]:
                        self.arguments_pool[func_sel][idx] = CircularSet()
                    seed_vals = list(type_dict[key])
                    if key in ("uint", "int"):
                        try:
                            seed_vals.extend(self._candidate_values_for_type(ty, limit=6))
                        except Exception:
                            pass
                    for v in seed_vals:
                        self.arguments_pool[func_sel][idx].add(v)
    

    def generate_random_individual(self):
        individual = []

        if "constructor" in self.interface and self.bytecode:
            arguments = ["constructor"]
            for index in range(len(self.interface["constructor"])):
                arguments.append(self.get_argument_value_with_recording(self.interface["constructor"][index], "constructor", index))
            individual.append({
                "account": self.get_random_account("constructor"),
                "contract": self.bytecode,
                "amount": self.get_random_amount("constructor"),
                "arguments": arguments,
                "blocknumber": self.get_random_blocknumber("constructor"),
                "timestamp": self.get_random_timestamp("constructor"),
                "gaslimit": self.get_random_gaslimit("constructor"),
                "returndatasize": dict()
            })

        function, argument_types = self.get_random_function_with_argument_types()
        arguments = [function]
        for index in range(len(argument_types)):
            arguments.append(self.get_argument_value_with_recording(argument_types[index], function, index))
        individual.append({
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "call_return": dict(),
            "extcodesize": dict(),
            "returndatasize": dict()
        })

        address, call_return_value = self.get_random_callresult_and_address(function)
        individual[-1]["call_return"] = {address: call_return_value}

        address, extcodesize_value = self.get_random_extcodesize_and_address(function)
        individual[-1]["extcodesize"] = {address: extcodesize_value}

        address, value = self.get_random_returndatasize_and_address(function)
        individual[-1]["returndatasize"] = {address: value}

        return individual


    def generate_individual_from_sequence(self, sequence):
        """
        根据给定的函数选择子序列（例如 ["a9059cbb", "095ea7b3"]）生成一个个体（chromosome）。
        会自动处理 constructor（若 interface/bytecode 存在时）并为每次调用随机生成参数与上下文。
        """
        individual = []

        # 1) constructor（若有）
        if "constructor" in self.interface and self.bytecode:
            args = ["constructor"]
            for idx, arg_ty in enumerate(self.interface["constructor"]):
                args.append(self.get_argument_value_with_recording(arg_ty, "constructor", idx))
            individual.append({
                "account": self.get_random_account("constructor"),
                "contract": self.bytecode,
                "amount": self.get_random_amount("constructor"),
                "arguments": args,
                "blocknumber": self.get_random_blocknumber("constructor"),
                "timestamp": self.get_random_timestamp("constructor"),
                "gaslimit": self.get_random_gaslimit("constructor"),
                "returndatasize": dict()
            })
            addr, val = self.get_random_returndatasize_and_address("constructor")
            individual[-1]["returndatasize"] = {addr: val}

        # 2) 依序添加每个函数调用
        #    将给定序列扩展/截断到固定长度（依据设置），满足“长度为 N”的初始测试案例要求
        desired_len = max(1, int(getattr(settings, 'MAX_INDIVIDUAL_LENGTH', 10)))
        flat_seq = list(sequence) if sequence else []
        if not flat_seq:
            # 若序列为空，退化为随机函数选择子
            try:
                fsel, _ = self.get_random_function_with_argument_types()
                flat_seq = [fsel]
            except Exception:
                flat_seq = []
        # 重复拼接直至长度满足，然后截断
        expanded = []
        while len(expanded) < desired_len:
            expanded.extend(flat_seq)
            if not flat_seq:  # 避免死循环
                break
        expanded = expanded[:desired_len]

        for selector in expanded:
            if selector not in self.interface:
                # 防御：若序列中有不在 interface 的条目，跳过
                continue
            args = [selector]
            arg_types = self.interface[selector]
            for idx, arg_ty in enumerate(arg_types):
                args.append(self.get_argument_value_with_recording(arg_ty, selector, idx))
            tx = {
                "account": self.get_random_account(selector),
                "contract": self.contract,
                "amount": self.get_random_amount(selector),
                "arguments": args,
                "blocknumber": self.get_random_blocknumber(selector),
                "timestamp": self.get_random_timestamp(selector),
                "gaslimit": self.get_random_gaslimit(selector),
                "call_return": dict(),
                "extcodesize": dict(),
                "returndatasize": dict()
            }
            # 附带环境池的值（与随机生成保持一致）
            addr, ret_val = self.get_random_callresult_and_address(selector)
            tx["call_return"] = {addr: ret_val}

            addr, extc_val = self.get_random_extcodesize_and_address(selector)
            tx["extcodesize"] = {addr: extc_val}

            addr, rds_val = self.get_random_returndatasize_and_address(selector)
            tx["returndatasize"] = {addr: rds_val}

            individual.append(tx)

        return individual



    def generate_random_input(self):
        input = {}

        function, argument_types = self.get_random_function_with_argument_types()
        arguments = [function]
        for index in range(len(argument_types)):
            arguments.append(self.get_argument_value_with_recording(argument_types[index], function, index))

    # ---- combination helpers (basic + boundary) ----
    def _candidate_values_for_type(self, ty: str, limit: int = 4):
        """Return a small list of candidate values emphasizing boundary seeds."""
        ty_l = (ty or "").lower()
        # Prefer per-function argument pool when available is handled by caller
        if ty_l.startswith('bool'):
            return [False, True]
        if ty_l.startswith('uint'):
            # include near-zero and near-maximum seeds
            try:
                bits = int((ty_l.split('[')[0] or 'uint').replace('uint', '') or '256')
            except ValueError:
                bits = 256
            bytes_len = max(1, min(32, int(bits / 8)))
            max_val = UINT_MAX.get(bytes_len, UINT_MAX[32])
            vals = [
                max_val,
                max_val - 1,
                max_val // 2,
                0,
                1,
                2,
            ]
            # keep a couple of small-byte boundaries when they fit
            for v in (255, 256):
                if v <= max_val:
                    vals.append(v)
            # preserve order and limit size
            seen = []
            for v in vals:
                if v not in seen:
                    seen.append(v)
            return seen[:limit]
        if ty_l.startswith('int'):
            try:
                bits = int((ty_l.split('[')[0] or 'int').replace('int', '') or '256')
            except ValueError:
                bits = 256
            bytes_len = max(1, min(32, int(bits / 8)))
            max_v = INT_MAX.get(bytes_len, INT_MAX[32])
            min_v = INT_MIN.get(bytes_len, INT_MIN[32])
            vals = [max_v, min_v, -1, 0, 1]
            return vals[:limit]
        if ty_l.startswith('address'):
            if getattr(self, "preferred_addresses", None):
                preferred = list(self.preferred_addresses)
                samp = preferred + [a for a in self.accounts if a not in preferred]
            else:
                samp = self.accounts[:]
            return samp[:min(len(samp), max(1, limit))]
        if ty_l.startswith('string'):
            out = []
            if not self.strings_pool.empty:
                for _ in range(min(limit, len(self.strings_pool._q))):
                    out.append(self.get_random_string_from_pool())
                return out
            return [self.get_string(0), self.get_string(1)]
        if ty_l.startswith('bytes'):
            # return few small lengths
            return [self.get_random_bytes(0), self.get_random_bytes(1), self.get_random_bytes(4)]
        return []

    def iter_param_combinations(self, function_selector: str, max_cases: int = 5):
        """Yield up to max_cases combinations of argument values for a given function.
        Priority order: values from arguments_pool -> boundary candidates -> fall back to random.
        """
        arg_types = self.interface.get(function_selector, [])
        if not arg_types:
            return
        # Build value lists per argument
        value_lists = []
        for idx, ty in enumerate(arg_types):
            lst = []
            if function_selector in self.arguments_pool and idx in self.arguments_pool[function_selector]:
                # take up to max_cases from pool
                pool_vals = list(self.arguments_pool[function_selector][idx]._q)
                lst = pool_vals[:max_cases]
            if not lst:
                lst = self._candidate_values_for_type(ty)
            if not lst:
                # final fallback to a single random value
                lst = [self.get_argument_value_with_recording(ty, function_selector, idx)]
            value_lists.append(lst)

        # Cartesian product with cap
        # simple round-robin: pick i-th of each list, wrap if necessary
        for i in range(max_cases):
            combo = []
            for idx, lst in enumerate(value_lists):
                if not lst:
                    combo.append(None)
                else:
                    combo.append(lst[i % len(lst)])
            yield combo
        input = {
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "returndatasize": dict()
        }

        address, value = self.get_random_returndatasize_and_address(function)
        input["returndatasize"] = {address: value}

        return input

    def get_random_function_with_argument_types(self):
        function_hash = self.function_circular_buffer.head_and_rotate()
        if function_hash == "constructor":
            function_hash = self.function_circular_buffer.head_and_rotate()
        return function_hash, self.interface[function_hash]

    #
    # TIMESTAMP
    #

    def add_timestamp_to_pool(self, function, timestamp):
        if not function in self.timestamp_pool:
            self.timestamp_pool[function] = CircularSet()
        self.timestamp_pool[function].add(timestamp)

    def get_random_timestamp(self, function):
        if function in self.timestamp_pool:
            return self.timestamp_pool[function].head_and_rotate()
        return None

    def remove_timestamp_from_pool(self, function, timestamp):
        if function in self.timestamp_pool:
            self.timestamp_pool[function].discard(timestamp)
            if self.timestamp_pool[function].empty:
                del self.timestamp_pool[function]

    #
    # BLOCKNUMBER
    #

    def add_blocknumber_to_pool(self, function, blocknumber):
        if not function in self.blocknumber_pool:
            self.blocknumber_pool[function] = CircularSet()
        self.blocknumber_pool[function].add(blocknumber)

    def get_random_blocknumber(self, function):
        if function in self.blocknumber_pool:
            return self.blocknumber_pool[function].head_and_rotate()
        return None

    def remove_blocknumber_from_pool(self, function, blocknumber):
        if function in self.blocknumber_pool:
            self.blocknumber_pool[function].discard(blocknumber)
            if self.blocknumber_pool[function].empty:
                del self.blocknumber_pool[function]

    #
    # BALANCE
    #

    def add_balance_to_pool(self, function, balance):
        if not function in self.balance_pool:
            self.balance_pool[function] = CircularSet()
        self.balance_pool[function].add(balance)

    def get_random_balance(self, function):
        if function in self.balance_pool:
            return self.balance_pool[function].head_and_rotate()
        return None

    #
    # CALL RESULT
    #

    def add_callresult_to_pool(self, function, address, result):
        if not function in self.callresult_pool:
            self.callresult_pool[function] = dict()
        if not address in self.callresult_pool[function]:
            self.callresult_pool[function][address] = CircularSet()
        self.callresult_pool[function][address].add(result)

    def get_random_callresult_and_address(self, function):
        if function in self.callresult_pool:
            address = random.choice(list(self.callresult_pool[function].keys()))
            value = self.callresult_pool[function][address].head_and_rotate()
            return address, value
        return None, None

    def get_random_callresult(self, function, address):
        if function in self.callresult_pool:
            if address in self.callresult_pool[function]:
                value = self.callresult_pool[function][address].head_and_rotate()
                return value
        return None

    def remove_callresult_from_pool(self, function, address, result):
        if function in self.callresult_pool and address in self.callresult_pool[function]:
            self.callresult_pool[function][address].discard(result)
            if self.callresult_pool[function][address].empty:
                del self.callresult_pool[function][address]
                if len(self.callresult_pool[function]) == 0:
                    del self.callresult_pool[function]

    #
    # EXTCODESIZE
    #

    def add_extcodesize_to_pool(self, function, address, size):
        if not function in self.extcodesize_pool:
            self.extcodesize_pool[function] = dict()
        if not address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address] = CircularSet()
        self.extcodesize_pool[function][address].add(size)

    def get_random_extcodesize_and_address(self, function):
        if function in self.extcodesize_pool:
            address = random.choice(list(self.extcodesize_pool[function].keys()))
            return address, self.extcodesize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_extcodesize(self, function, address):
        if function in self.extcodesize_pool:
            if address in self.extcodesize_pool[function]:
                return self.extcodesize_pool[function][address].head_and_rotate()
        return None

    def remove_extcodesize_from_pool(self, function, address, size):
        if function in self.extcodesize_pool and address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address].discard(size)
            if self.extcodesize_pool[function][address].empty:
                del self.extcodesize_pool[function][address]
                if len(self.extcodesize_pool[function]) == 0:
                    del self.extcodesize_pool[function]

    #
    # RETURNDATASIZE
    #

    def add_returndatasize_to_pool(self, function, address, size):
        if not function in self.returndatasize_pool:
            self.returndatasize_pool[function] = dict()
        if not address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address] = CircularSet()
        self.returndatasize_pool[function][address].add(size)

    def get_random_returndatasize_and_address(self, function):
        if function in self.returndatasize_pool:
            address = random.choice(list(self.returndatasize_pool[function].keys()))
            return address, self.returndatasize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_returndatasize(self, function, address):
        if function in self.returndatasize_pool:
            if address in self.returndatasize_pool[function]:
                return self.returndatasize_pool[function][address].head_and_rotate()
        return None

    def remove_returndatasize_from_pool(self, function, address, size):
        if function in self.returndatasize_pool and address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address].discard(size)
            if self.returndatasize_pool[function][address].empty:
                del self.returndatasize_pool[function][address]
                if len(self.returndatasize_pool[function]) == 0:
                    del self.returndatasize_pool[function]

    #
    # GASLIMIT
    #

    def add_gaslimit_to_pool(self, function, gaslimit):
        if not function in self.gaslimit_pool:
            self.gaslimit_pool[function] = CircularSet()
        self.gaslimit_pool[function].add(gaslimit)

    def remove_gaslimit_from_pool(self, function, gaslimit):
        if function in self.gaslimit_pool:
            self.gaslimit_pool[function].discard(gaslimit)
            if self.gaslimit_pool[function].empty:
                del self.gaslimit_pool[function]

    def clear_gaslimits_in_pool(self, function):
        if function in self.gaslimit_pool:
            del self.gaslimit_pool[function]

    def get_random_gaslimit(self, function):
        if function in self.gaslimit_pool:
            return self.gaslimit_pool[function].head_and_rotate()
        return settings.GAS_LIMIT

    #
    # ACCOUNTS
    #

    def add_account_to_pool(self, function, account):
        if not function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()
        self.accounts_pool[function].add(account)

    def remove_account_from_pool(self, function, account):
        if function in self.accounts_pool:
            self.accounts_pool[function].discard(account)
            if self.accounts_pool[function].empty:
                del self.accounts_pool[function]

    def clear_accounts_in_pool(self, function):
        if function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()

    def get_random_account_from_pool(self, function):
        return self.accounts_pool[function].head_and_rotate()

    def get_random_account(self, function):
        if function in self.accounts_pool:
            return self.get_random_account_from_pool(function)
        else:
            return random.choice(self.accounts)

    #
    # AMOUNTS
    #

    def add_amount_to_pool(self, function, amount):
        if not function in self.amounts_pool:
            self.amounts_pool[function] = CircularSet()
        self.amounts_pool[function].add(amount)

    def remove_amount_from_pool(self, function, amount):
        if function in self.amounts_pool:
            self.amounts_pool[function].discard(amount)
            if self.amounts_pool[function].empty:
                del self.amounts_pool[function]

    def get_random_amount_from_pool(self, function):
        return self.amounts_pool[function].head_and_rotate()

    def get_random_amount(self, function):
        if function not in self.amounts_pool:
            max_uint = UINT_MAX[32]
            max_payable = max(0, settings.ACCOUNT_BALANCE - settings.GAS_LIMIT * settings.GAS_PRICE)
            seed_amounts = [
                0,
                1,
                2,
                max_payable,
                max_payable - 1 if max_payable > 0 else 0,
                max_payable // 2 if max_payable > 1 else 1,
            ]
            for amt in seed_amounts:
                # Ensure non-negative values only
                if amt >= 0:
                    self.add_amount_to_pool(function, amt)
        return self.get_random_amount_from_pool(function)

    #
    # STRINGS
    #

    def add_string_to_pool(self, string):
        self.strings_pool.add(string)


    def get_random_string_from_pool(self):
        return self.strings_pool.head_and_rotate()

    #
    # BYTES
    #

    def add_bytes_to_pool(self, string):
        self.bytes_pool.add(string)


    def get_random_bytes_from_pool(self):
        return self.bytes_pool.head_and_rotate()
    

    #
    # FUNCTION ARGUMENTS
    #

    def add_parameter_array_size(self, function, parameter_index, array_size):
        if function not in self.argument_array_sizes_pool:
            self.argument_array_sizes_pool[function] = dict()
        if parameter_index not in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index] = CircularSet()
        self.argument_array_sizes_pool[function][parameter_index].add(min(array_size, MAX_ARRAY_LENGTH))

    def _get_parameter_array_size_from_pool(self, function, argument_index):
        return self.argument_array_sizes_pool[function][argument_index].head_and_rotate()

    def remove_parameter_array_size_from_pool(self, function, parameter_index, array_size):
        if function in self.argument_array_sizes_pool and parameter_index in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index].discard(array_size)
            if self.argument_array_sizes_pool[function][parameter_index].empty:
                del self.argument_array_sizes_pool[function][parameter_index]
                if len(self.argument_array_sizes_pool[function]) == 0:
                    del self.argument_array_sizes_pool[function]


    def add_argument_to_pool(self, function, argument_index, argument):
        if type(argument) is list:
            for element in argument:
                self.add_argument_to_pool(function, argument_index, element)
            return
        if function not in self.arguments_pool:
            self.arguments_pool[function] = {}
        if argument_index not in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index] = CircularSet()
        self.arguments_pool[function][argument_index].add(argument)

    def remove_argument_from_pool(self, function, argument_index, argument):
        if type(argument) is list:
            for element in argument:
                self.remove_argument_from_pool(function, argument_index, element)
            return
        if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index].discard(argument)
            if self.arguments_pool[function][argument_index].empty:
                del self.arguments_pool[function][argument_index]
                if len(self.arguments_pool[function]) == 0:
                    del self.arguments_pool[function]

    def _get_random_argument_from_pool(self, function, argument_index):
        return self.arguments_pool[function][argument_index].head_and_rotate()

    def _sample_from_pool_or_random(self, function, argument_index, random_generator, pool_bias=0.6):
        """
        Return a value from the argument pool with a given probability; otherwise generate
        a fresh random value (which is cached back into the pool for future reuse).
        This prevents the seeded pools (often small constants) from starving boundary cases,
        which are required to surface arithmetic bugs such as overflows.
        """
        try:
            has_pool = function in self.arguments_pool and argument_index in self.arguments_pool[function]
            if has_pool and random.random() < pool_bias:
                return self._get_random_argument_from_pool(function, argument_index)
            val = random_generator()
            self.add_argument_to_pool(function, argument_index, val)
            return val
        except Exception:
            # Never break fuzzing because of pool bookkeeping.
            return random_generator()

    def get_random_argument(self, type, function, argument_index):
        # Boolean
        if type.startswith("bool"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self._sample_from_pool_or_random(
                        function,
                        argument_index,
                        lambda: bool(random.randint(0, 1))
                    ))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                return self._sample_from_pool_or_random(
                    function,
                    argument_index,
                    lambda: bool(random.randint(0, 1))
                )

        # Unsigned integer
        elif type.startswith("uint"):
            bytes = int(int(type.replace("uint", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self._sample_from_pool_or_random(
                        function,
                        argument_index,
                        lambda: self.get_random_unsigned_integer(0, UINT_MAX[bytes])
                    ))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                return self._sample_from_pool_or_random(
                    function,
                    argument_index,
                    lambda: self.get_random_unsigned_integer(0, UINT_MAX[bytes])
                )

        # Signed integer
        elif type.startswith("int"):
            bytes = int(int(type.replace("int", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self._sample_from_pool_or_random(
                        function,
                        argument_index,
                        lambda: self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes])
                    ))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                return self._sample_from_pool_or_random(
                    function,
                    argument_index,
                    lambda: self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes])
                )

        # Address
        elif type.startswith("address"):
            def _pick_address():
                # Strongly favor known deployed helpers to ensure cross-contract calls succeed.
                if self.preferred_addresses and random.random() < 0.7:
                    addr = self.preferred_addresses[0]
                    self.preferred_addresses = self.preferred_addresses[1:] + [addr]
                    return addr
                return random.choice(self.accounts)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self._sample_from_pool_or_random(
                        function,
                        argument_index,
                        _pick_address,
                        pool_bias=0.85
                    ))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                return self._sample_from_pool_or_random(
                    function,
                    argument_index,
                    _pick_address,
                    pool_bias=0.85
                )

        # String
        elif type.startswith("string"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_string(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.strings_pool.empty:
                    self.add_string_to_pool(self.get_string(0))
                    self.add_string_to_pool(self.get_string(1))
                    self.add_string_to_pool(self.get_string(32))
                    self.add_string_to_pool(self.get_string(33))
                return self.get_random_string_from_pool()

        # Bytes1 ... Bytes32
        elif type.startswith("bytes1") or \
             type.startswith("bytes2") or \
             type.startswith("bytes3") or \
             type.startswith("bytes4") or \
             type.startswith("bytes5") or \
             type.startswith("bytes6") or \
             type.startswith("bytes7") or \
             type.startswith("bytes8") or \
             type.startswith("bytes9") or \
             type.startswith("bytes10") or \
             type.startswith("bytes11") or \
             type.startswith("bytes12") or \
             type.startswith("bytes13") or \
             type.startswith("bytes14") or \
             type.startswith("bytes15") or \
             type.startswith("bytes16") or \
             type.startswith("bytes17") or \
             type.startswith("bytes18") or \
             type.startswith("bytes19") or \
             type.startswith("bytes20") or \
             type.startswith("bytes21") or \
             type.startswith("bytes22") or \
             type.startswith("bytes23") or \
             type.startswith("bytes24") or \
             type.startswith("bytes25") or \
             type.startswith("bytes26") or \
             type.startswith("bytes27") or \
             type.startswith("bytes28") or \
             type.startswith("bytes29") or \
             type.startswith("bytes30") or \
             type.startswith("bytes31") or \
             type.startswith("bytes32"):
            length = int(type.replace("bytes", "").split("[")[0])
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_bytes(length))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_bytes(random.randint(0, length))

        # Bytes
        elif type.startswith("bytes"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_random_bytes(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.bytes_pool.empty:
                    self.add_bytes_to_pool(self.get_random_bytes(0))
                    self.add_bytes_to_pool(self.get_random_bytes(1))
                    self.add_bytes_to_pool(self.get_random_bytes(32))
                    self.add_bytes_to_pool(self.get_random_bytes(33))
                return self.get_random_bytes_from_pool()

        # Unknown type
        else:
            self.logger.error("Unsupported type: "+str(type))

    def _get_array_sizes(self, argument_index, function, type):
        sizes = []
        for size in re.compile(r"\[(.*?)\]").findall(type):
            # Dynamic array
            if size == "":
                if function in self.argument_array_sizes_pool \
                        and argument_index in self.argument_array_sizes_pool[function]:
                    sizes.append(self._get_parameter_array_size_from_pool(function, argument_index))
                else:
                    sizes.append(random.randint(0, MAX_ARRAY_LENGTH))
            # Fixed size array
            else:
                sizes.append(int(size))
        return sizes

    @staticmethod
    def get_random_unsigned_integer(min, max):
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([min, min + 1, min + 2])
        elif seed == 1:
            return random.choice([max, max - 1, max - 2])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_random_signed_integer(min, max):
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([0, -1, min, min + 1])
        elif seed == 1:
            return random.choice([0, 1, max, max - 1])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_string(length):
        return ''.join('A' for _ in range(length))

    @staticmethod
    def get_random_bytes(length):
        return bytearray(random.getrandbits(8) for _ in range(length))
