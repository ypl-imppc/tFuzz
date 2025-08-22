#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import solcx
import random
import logging
import argparse
import re

from eth_utils import encode_hex, decode_hex, to_canonical_address
from z3 import Solver

from evm import InstrumentedEVM
from detectors import DetectorExecutor
from engine import EvolutionaryFuzzingEngine
from engine.components import Generator, Individual, Population
from engine.analysis import SymbolicTaintAnalyzer
from engine.analysis import ExecutionTraceAnalyzer
from engine.environment import FuzzingEnvironment
from engine.operators import LinearRankingSelection
from engine.operators import DataDependencyLinearRankingSelection
from engine.operators import Crossover
from engine.operators import DataDependencyCrossover
from engine.operators import Mutation
from engine.fitness import fitness_function

from extensions.fag_sv_adapter import (
    build_contract_info_from_ast,
    build_contract_info_from_abi,
    generate_sequences as fagsv_gen_sequences,
)

from utils import settings
from utils.source_map import SourceMap
from utils.utils import initialize_logger, compile, get_interface_from_abi, get_pcs_and_jumpis, get_function_signature_mapping
from utils.control_flow_graph import ControlFlowGraph
from typing import List

def _generate_fagsv_sequences_from_interface(interface: dict, include_self_pairs: bool = True) -> List[List[str]]:
    """
    Phase 1：只基于 ABI/interface 的简化 FAGSV。
    用 interface 的 key（4字节选择子）作为函数标识，忽略 'constructor' 与 'fallback'。
    返回若干序列（每个序列是若干 selector 构成的列表）。
    """
    selectors = [k for k in interface.keys() if k not in ("constructor", "fallback")]
    sequences: List[List[str]] = []

    # 单调用序列
    for s in selectors:
        sequences.append([s])

    # 自调用序列，用于触发可重入/状态重复迁移
    if include_self_pairs:
        for s in selectors:
            sequences.append([s, s])

    # 去重保序
    seen = set()
    uniq = []
    for seq in sequences:
        key = tuple(seq)
        if key not in seen:
            uniq.append(seq)
            seen.add(key)
    return uniq

def _compile_with_ast(source_path: str, solc_version: str = None):
    """
    使用 standard-json 编译，返回 (output, ast_by_source)
    """
    if solc_version:
        solcx.install_solc(solc_version, allow_osx=True)
        solcx.set_solc_version(solc_version)
    # standard-json
    with open(source_path, "r", encoding="utf-8") as f:
        source_code = f.read()
    std_input = {
        "language": "Solidity",
        "sources": {source_path: {"content": source_code}},
        "settings": {"outputSelection": {"*": {"*": ["abi","evm.bytecode.object","evm.deployedBytecode.object"], "": ["ast"]}}},
    }
    output = solcx.compile_standard(std_input, allow_paths=".")
    ast_by_source = output.get("sources", {}).get(source_path, {}).get("ast")
    return output, ast_by_source


# Heuristic auto-selector for the top-level contract in a multi-contract .sol file.
def _auto_select_top_caller_from_source(source_text: str) -> str:
    """
    Heuristic auto-selector for the top-level contract in a multi-contract .sol file.
    We pick the contract that *calls other contracts* but is *not called by others*.

    Implementation notes:
      - Parse contract blocks via regex (no dependency on solc availability here).
      - For each contract A and every other contract name B, if A declares a variable or
        parameter of type B (e.g., `B x;` or `function f(B x)`) and later uses `x.<member>`
        inside A's body, we add a directed edge A -> B.
      - We then return a contract with out-degree > 0 and in-degree == 0. If multiple exist,
        return the one with the largest out-degree; if none match, return the last contract
        (fallback keeps behavior deterministic across runs).
    """
    # Capture `contract Name { ... }` blocks including nested braces conservatively.
    # This simple parser assumes no `contract` keyword inside comments/strings.
    contract_pattern = re.compile(r"contract\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{(?P<body>[\s\S]*?)\}\s*", re.MULTILINE)
    contracts = [(m.group("name"), m.group("body")) for m in contract_pattern.finditer(source_text)]
    if not contracts:
        return ""

    names = [n for n, _ in contracts]
    # Build adjacency sets
    out_edges = {n: set() for n in names}
    in_edges = {n: set() for n in names}

    # Precompile helper regexes per contract name B
    # Pattern to find identifiers declared with type B: either var decls or params
    def _var_decl_regex(B):
        # Matches: `B x` (variable/parameter), capturing `x`
        return re.compile(r"\b" + re.escape(B) + r"\s+([A-Za-z_][A-Za-z0-9_]*)\b")

    for A_name, A_body in contracts:
        for B in names:
            if B == A_name:
                continue
            # Collect potential identifiers of type B in A's body
            ids = set(m.group(1) for m in _var_decl_regex(B).finditer(A_body))
            if not ids:
                continue
            # If any identifier of type B is used with a member access (id.<something>),
            # treat it as a cross-contract call usage.
            called = False
            for ident in ids:
                if re.search(r"\b" + re.escape(ident) + r"\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(", A_body):
                    called = True
                    break
            if called:
                out_edges[A_name].add(B)
                in_edges[B].add(A_name)

    # Select contract with out>0 and in==0; tie-breaker: max out-degree, then last occurrence order
    candidates = [n for n in names if len(out_edges[n]) > 0 and len(in_edges[n]) == 0]
    if candidates:
        # sort by out-degree (desc) and by original order (stable by names.index)
        candidates.sort(key=lambda x: (len(out_edges[x]), names.index(x)))
        return candidates[-1]  # highest out-degree, and latest in order among equals

    # Fallbacks: contract with max out-degree, else last contract defined
    best = max(names, key=lambda x: len(out_edges[x]))
    if len(out_edges[best]) > 0:
        return best
    return names[-1]

class Fuzzer:
    def __init__(self, contract_name, abi, deployment_bytecode, runtime_bytecode, test_instrumented_evm, blockchain_state, solver, args, seed, source_map=None):
        global logger

        logger = initialize_logger("Fuzzer  ")
        logger.title("Fuzzing contract %s", contract_name)
        self.logger = logger
        self.abi = abi

        cfg = ControlFlowGraph()
        cfg.build(runtime_bytecode, settings.EVM_VERSION)

        self.contract_name = contract_name
        self.interface = get_interface_from_abi(abi)
        self.deployement_bytecode = deployment_bytecode
        self.blockchain_state = blockchain_state
        self.instrumented_evm = test_instrumented_evm
        self.solver = solver
        self.source_map = source_map
        self.args = args

        # Get some overall metric on the code
        self.overall_pcs, self.overall_jumpis = get_pcs_and_jumpis(runtime_bytecode)

        # Initialize results
        self.results = {"errors": {}}

        # Initialize fuzzing environment
        self.env = FuzzingEnvironment(instrumented_evm=self.instrumented_evm,
                                      contract_name=self.contract_name,
                                      solver=self.solver,
                                      results=self.results,
                                      symbolic_taint_analyzer=SymbolicTaintAnalyzer(),
                                      detector_executor=DetectorExecutor(source_map, get_function_signature_mapping(abi)),
                                      interface=self.interface,
                                      overall_pcs=self.overall_pcs,
                                      overall_jumpis=self.overall_jumpis,
                                      len_overall_pcs_with_children=0,
                                      other_contracts = list(),
                                      args=args,
                                      seed=seed,
                                      cfg=cfg,
                                      abi=abi)

    def run(self):
        contract_address = None
        self.instrumented_evm.create_fake_accounts()

        if self.args.source:
            for transaction in self.blockchain_state:
                if transaction['from'].lower() not in self.instrumented_evm.accounts:
                    self.instrumented_evm.accounts.append(self.instrumented_evm.create_fake_account(transaction['from']))

                if not transaction['to']:
                    result = self.instrumented_evm.deploy_contract(transaction['from'], transaction['input'], int(transaction['value']), int(transaction['gas']), int(transaction['gasPrice']))
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s", self.contract_name, transaction['from'], result._error)
                        sys.exit(-2)
                    else:
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.debug("Contract deployed at %s", contract_address)
                        self.env.other_contracts.append(to_canonical_address(contract_address))
                        cc, _ = get_pcs_and_jumpis(self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())
                        self.env.len_overall_pcs_with_children += len(cc)
                else:
                    input = {}
                    input["block"] = {}
                    input["transaction"] = {
                        "from": transaction["from"],
                        "to": transaction["to"],
                        "gaslimit": int(transaction["gas"]),
                        "value": int(transaction["value"]),
                        "data": transaction["input"]
                    }
                    input["global_state"] = {}
                    out = self.instrumented_evm.deploy_transaction(input, int(transaction["gasPrice"]))

            if "constructor" in self.interface:
                del self.interface["constructor"]

            if not contract_address:
                if "constructor" not in self.interface:
                    result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0], self.deployement_bytecode)
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s", self.contract_name, self.instrumented_evm.accounts[0], result._error)
                        sys.exit(-2)
                    else:
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.debug("Contract deployed at %s", contract_address)

            if contract_address in self.instrumented_evm.accounts:
                self.instrumented_evm.accounts.remove(contract_address)

            self.env.overall_pcs, self.env.overall_jumpis = get_pcs_and_jumpis(self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())

        if self.args.abi:
            contract_address = self.args.contract

        self.instrumented_evm.create_snapshot()

        generator = Generator(interface=self.interface,
                            bytecode=self.deployement_bytecode,
                            accounts=self.instrumented_evm.accounts,
                            contract=contract_address)
        try:
            if self.args.source and os.path.isfile(self.args.source):
                from engine.components.contract_scraper import create_contractpools
                with open(self.args.source, "r", encoding="utf-8") as _f:
                    _source = _f.read()

                # 组建“已知地址集合”：现有 EVM 账户 + 区块链状态里的 from/to
                known_addrs = set(a.lower() for a in self.instrumented_evm.accounts if isinstance(a, str))
                for tx in (self.blockchain_state or []):
                    if isinstance(tx, dict):
                        if tx.get("from"): known_addrs.add(tx["from"].lower())
                        if tx.get("to"):   known_addrs.add(tx["to"].lower())

                # 抓取：address/ETH(int, wei)/int/string
                ap, ethp, intp, strp = create_contractpools(_source, known_addrs)

                # 规范化字符串（去掉两端引号）
                norm_str = []
                for s in (strp or []):
                    if isinstance(s, str) and len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
                        norm_str.append(s[1:-1])
                    else:
                        norm_str.append(str(s))

                # 把 ETH pool 视为 uint（金钱常量→wei）
                typedict = {
                    "address": list(ap or []),
                    "uint":    sorted({int(x) for x in (ethp or set()) if int(x) >= 0}),
                    "int":     sorted({int(x) for x in (intp or set())}),
                    "string":  norm_str,
                }
                # 常用兜底值
                typedict["uint"].extend([0])       # 允许 0 值调用
                typedict["int"].extend([0, -1, 1]) # 邻域探索

                # 注入到 Generator（若方法存在）
                if hasattr(generator, "seed_argument_pools_from_typedict"):
                    generator.seed_argument_pools_from_typedict(typedict)
                    self.logger.debug("Seeded argument pools from contract_scraper pools.")
        except AssertionError as ae:
            # 若硬编码地址不在已知集合里，contract_scraper 会 assert；这里降级为警告，不阻断运行
            self.logger.warning(f"contract_scraper address check failed: {ae}")
        except Exception as e:
            self.logger.debug(f"contract_scraper seeding skipped: {type(e).__name__}: {e}")

            
        try:
            from engine.components.functionParameter import paramGenerate  # 你的原文件
            _typedict = paramGenerate()
            if isinstance(_typedict, dict) and hasattr(generator, "seed_argument_pools_from_typedict"):
                generator.seed_argument_pools_from_typedict(_typedict)
                self.logger.debug("Seeded argument pools from functionParameter.paramGenerate().")
        except Exception as _e:
            self.logger.debug(f"Param seeding skipped: {type(_e).__name__}: {_e}")

        # Create initial population (FAGSV with AST -> fallback to ABI -> fallback to random)
        size = 2 * len(self.interface)
        pop_size = settings.POPULATION_SIZE if settings.POPULATION_SIZE else size

        template = Individual(generator=generator)
        if getattr(self.args, "tx_seed", "random") == "fagsv":
            sequences = None
            try:
                # 1) 先尝试 AST 驱动（Phase 2）
                output, ast_root = _compile_with_ast(self.args.source, solc_version=None)  # 若有 --solc，可传进来
                if ast_root:
                    # 从 AST 里找到目标合约节点；本适配器在 build_contract_info_from_ast 内会再校验
                    ci = build_contract_info_from_ast(self.abi, ast_root, self.contract_name)
                    sequences = fagsv_gen_sequences(ci, include_self_pairs=True)
            except Exception as e:
                self.logger.warning("FAGSV AST path failed, fallback to ABI-only. Reason: %s", e)

            if not sequences:
                # 2) 回退：ABI-only（Phase 1）
                ci = build_contract_info_from_abi(self.abi)
                sequences = fagsv_gen_sequences(ci, include_self_pairs=True)

            indvs = []
            for seq in sequences[:pop_size]:
                chrom = generator.generate_individual_from_sequence(seq)
                indvs.append(Individual(generator=generator).init(chromosome=chrom))
            while len(indvs) < pop_size:
                indvs.append(Individual(generator=generator).init())
            population = Population(indv_template=template,
                                    indv_generator=generator,
                                    size=pop_size).init(indvs=indvs)
        else:
            population = Population(indv_template=template,
                                    indv_generator=generator,
                                    size=pop_size).init()

        # Create genetic operators
        if self.args.data_dependency:
            selection = DataDependencyLinearRankingSelection(env=self.env)
            crossover = DataDependencyCrossover(pc=settings.PROBABILITY_CROSSOVER, env=self.env)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)
        else:
            selection = LinearRankingSelection()
            crossover = Crossover(pc=settings.PROBABILITY_CROSSOVER)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)

        # Create and run our evolutionary fuzzing engine
        engine = EvolutionaryFuzzingEngine(population=population, selection=selection, crossover=crossover, mutation=mutation, mapping=get_function_signature_mapping(self.env.abi))
        engine.fitness_register(lambda x: fitness_function(x, self.env))
        engine.analysis.append(ExecutionTraceAnalyzer(self.env))

        self.env.execution_begin = time.time()
        self.env.population = population

        engine.run(ng=settings.GENERATIONS)

        if self.env.args.cfg:
            if self.env.args.source:
                self.env.cfg.save_control_flow_graph(os.path.splitext(self.env.args.source)[0]+'-'+self.contract_name, 'pdf')
            elif self.env.args.abi:
                self.env.cfg.save_control_flow_graph(os.path.join(os.path.dirname(self.env.args.abi), self.contract_name), 'pdf')

        self.instrumented_evm.reset()

def main():
    args = launch_argument_parser()

    logger = initialize_logger("Main    ")

    # Check if contract has already been analyzed
    if args.results and os.path.exists(args.results):
        os.remove(args.results)
        logger.info("Contract "+str(args.source)+" has already been analyzed: "+str(args.results))
        sys.exit(0)

    # Initializing random
    if args.seed:
        seed = args.seed
        if not "PYTHONHASHSEED" in os.environ:
            logger.debug("Please set PYTHONHASHSEED to '1' for Python's hash function to behave deterministically.")
    else:
        seed = random.random()
    random.seed(seed)
    logger.title("Initializing seed to %s", seed)

    # Initialize EVM
    instrumented_evm = InstrumentedEVM(settings.RPC_HOST, settings.RPC_PORT)
    instrumented_evm.set_vm_by_name(settings.EVM_VERSION)

    # Create Z3 solver instance
    solver = Solver()
    solver.set("timeout", settings.SOLVER_TIMEOUT)

    # Parse blockchain state if provided
    blockchain_state = []
    if args.blockchain_state:
        if args.blockchain_state.endswith(".json"):
            with open(args.blockchain_state) as json_file:
                for line in json_file.readlines():
                    blockchain_state.append(json.loads(line))
        elif args.blockchain_state.isnumeric():
            settings.BLOCK_HEIGHT = int(args.blockchain_state)
            instrumented_evm.set_vm(settings.BLOCK_HEIGHT)
        else:
            logger.error("Unsupported input file: " + args.blockchain_state)
            sys.exit(-1)

    # Compile source code to get deployment bytecode, runtime bytecode and ABI
    if args.source:
        if args.source.endswith(".sol"):
            compiler_output = compile(args.solc_version, settings.EVM_VERSION, args.source)
            if not compiler_output:
                logger.error("No compiler output for: " + args.source)
                sys.exit(-1)
            # Auto-select the top-level contract (calls others, not called by others) when -c/--contract is not provided
            if not args.contract:
                try:
                    with open(args.source, "r", encoding="utf-8") as _sf:
                        _src_text = _sf.read()
                    auto_choice = _auto_select_top_caller_from_source(_src_text)
                    if auto_choice and auto_choice in compiler_output['contracts'][args.source]:
                        logger.info(f"Auto-selected contract: {auto_choice} (calls other contracts and is not called by others)")
                        args.contract = auto_choice
                    else:
                        # Fallback to last contract in compiler output for deterministic behavior
                        all_names = list(compiler_output['contracts'][args.source].keys())
                        if all_names:
                            args.contract = all_names[-1]
                            logger.info(f"Auto-selection fallback to last contract: {args.contract}")
                except Exception as _e:
                    logger.warning(f"Auto-selection failed: {type(_e).__name__}: {_e}")
            for contract_name, contract in compiler_output['contracts'][args.source].items():
                if args.contract and contract_name != args.contract:
                    continue
                if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode']['object']:
                    source_map = SourceMap(':'.join([args.source, contract_name]), compiler_output)
                    Fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'], contract['evm']['deployedBytecode']['object'], instrumented_evm, blockchain_state, solver, args, seed, source_map).run()
        else:
            logger.error("Unsupported input file: " + args.source)
            sys.exit(-1)

    if args.abi:
        with open(args.abi) as json_file:
            abi = json.load(json_file)
            runtime_bytecode = instrumented_evm.get_code(to_canonical_address(args.contract)).hex()
            Fuzzer(args.contract, abi, None, runtime_bytecode, instrumented_evm, blockchain_state, solver, args, seed).run()

def launch_argument_parser():
    parser = argparse.ArgumentParser()

    # Contract parameters
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-s", "--source", type=str,
                        help="Solidity smart contract source code file (.sol).")
    group1.add_argument("-a", "--abi", type=str,
                        help="Smart contract ABI file (.json).")

    #group2 = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-c", "--contract", type=str,
                        help="Contract name to be fuzzed (if Solidity source code file provided) or blockchain contract address (if ABI file provided).")

    parser.add_argument("-b", "--blockchain-state", type=str,
                        help="Initialize fuzzer with a blockchain state by providing a JSON file (if Solidity source code file provided) or a block number (if ABI file provided).")

    # Compiler parameters
    parser.add_argument("--solc", help="Solidity compiler version (default '" + str(
        solcx.get_solc_version()) + "'). Installed compiler versions: " + str(solcx.get_installed_solc_versions()) + ".",
                        action="store", dest="solc_version", type=str)
    parser.add_argument("--evm", help="Ethereum VM (default '" + str(
        settings.EVM_VERSION) + "'). Available VM's: 'homestead', 'byzantium' or 'petersburg'.", action="store",
                        dest="evm_version", type=str)

    # Evolutionary parameters
    group3 = parser.add_mutually_exclusive_group(required=False)
    group3.add_argument("-g", "--generations",
                        help="Number of generations (default " + str(settings.GENERATIONS) + ").", action="store",
                        dest="generations", type=int)
    group3.add_argument("-t", "--timeout",
                        help="Number of seconds for fuzzer to stop.", action="store",
                        dest="global_timeout", type=int)
    parser.add_argument("-n", "--population-size",
                        help="Size of the population.", action="store",
                        dest="population_size", type=int)
    parser.add_argument("-pc", "--probability-crossover",
                        help="Size of the population.", action="store",
                        dest="probability_crossover", type=float)
    parser.add_argument("-pm", "--probability-mutation",
                        help="Size of the population.", action="store",
                        dest="probability_mutation", type=float)

    # Miscellaneous parameters
    parser.add_argument("-r", "--results", type=str, help="Folder or JSON file where results should be stored.")
    parser.add_argument("--seed", type=float, help="Initialize the random number generator with a given seed.")
    parser.add_argument("--cfg", help="Build control-flow graph and highlight code coverage.", action="store_true")
    parser.add_argument("--rpc-host", help="Ethereum client RPC hostname.", action="store", dest="rpc_host", type=str)
    parser.add_argument("--rpc-port", help="Ethereum client RPC port.", action="store", dest="rpc_port", type=int)

    parser.add_argument("--data-dependency",
                        help="Disable/Enable data dependency analysis: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="data_dependency", type=int)
    parser.add_argument("--constraint-solving",
                        help="Disable/Enable constraint solving: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="constraint_solving", type=int)
    parser.add_argument("--environmental-instrumentation",
                        help="Disable/Enable environmental instrumentation: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="environmental_instrumentation", type=int)
    parser.add_argument("--max-individual-length",
                        help="Maximal length of an individual (default: " + str(settings.MAX_INDIVIDUAL_LENGTH) + ")", action="store",
                        dest="max_individual_length", type=int)
    parser.add_argument("--max-symbolic-execution",
                        help="Maximum number of symbolic execution calls before restting population (default: " + str(settings.MAX_SYMBOLIC_EXECUTION) + ")", action="store",
                        dest="max_symbolic_execution", type=int)

    parser.add_argument("--tx-seed", choices=["random", "fagsv"], default="random",
                        help="Initial transaction sequence seeding strategy.")

    version = "ConFuzzius - Version 0.0.2 - "
    version += "\"By three methods we may learn wisdom:\n"
    version += "First, by reflection, which is noblest;\n"
    version += "Second, by imitation, which is easiest;\n"
    version += "And third by experience, which is the bitterest.\"\n"
    parser.add_argument("-v", "--version", action="version", version=version)

    args = parser.parse_args()

    if not args.contract:
        args.contract = ""

    if args.source and args.contract.startswith("0x"):
        parser.error("--source requires --contract to be a name, not an address.")
    if args.source and args.blockchain_state and args.blockchain_state.isnumeric():
        parser.error("--source requires --blockchain-state to be a file, not a number.")

    if args.abi and not args.contract.startswith("0x"):
        parser.error("--abi requires --contract to be an address, not a name.")
    if args.abi and args.blockchain_state and not args.blockchain_state.isnumeric():
        parser.error("--abi requires --blockchain-state to be a number, not a file.")

    if args.evm_version:
        settings.EVM_VERSION = args.evm_version
    if not args.solc_version:
        args.solc_version = solcx.get_solc_version()
    if args.generations:
        settings.GENERATIONS = args.generations
    if args.global_timeout:
        settings.GLOBAL_TIMEOUT = args.global_timeout
    if args.population_size:
        settings.POPULATION_SIZE = args.population_size
    if args.probability_crossover:
        settings.PROBABILITY_CROSSOVER = args.probability_crossover
    if args.probability_mutation:
        settings.PROBABILITY_MUTATION = args.probability_mutation

    if args.data_dependency == None:
        args.data_dependency = 1
    if args.constraint_solving == None:
        args.constraint_solving = 1
    if args.environmental_instrumentation == None:
        args.environmental_instrumentation = 1

    if args.environmental_instrumentation == 1:
        settings.ENVIRONMENTAL_INSTRUMENTATION = True
    elif args.environmental_instrumentation == 0:
        settings.ENVIRONMENTAL_INSTRUMENTATION = False

    if args.max_individual_length:
        settings.MAX_INDIVIDUAL_LENGTH = args.max_individual_length
    if args.max_symbolic_execution:
        settings.MAX_SYMBOLIC_EXECUTION = args.max_symbolic_execution

    if args.abi:
        settings.REMOTE_FUZZING = True

    if args.rpc_host:
        settings.RPC_HOST = args.rpc_host
    if args.rpc_port:
        settings.RPC_PORT = args.rpc_port

    return args

if '__main__' == __name__:
    main()
