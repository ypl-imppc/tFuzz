# tFuzz 项目文档

本仓库实现了一个面向 Solidity 合约的**跨合约（Cross-Contract）漏洞检测**模糊测试器，核心思想是：在本地/远程可选的 EVM 执行环境中，对目标合约进行**高效灰盒 fuzzing + 演化算法（遗传算法）**探索，并结合**符号污点/分支表达式**与多类**漏洞探测器（detectors）**输出结果。

> 本文件以 `fuzzer/main.py` 为入口，直接给出“整体结构、运行方式、核心数据流、关键模块说明、未启用/未引用代码标注”等。

---

## 1. 快速开始

### 1.1 运行位置
`fuzzer/main.py` 里大量使用 `from evm import ...` / `from engine import ...` 这类**相对当前目录**的导入方式（而不是 `fuzzer.evm`）。因此推荐从 `fuzzer/` 目录运行：

```bash
cd fuzzer
python3 main.py -s test/reentrancy/inter_RE_buggy_6.sol -r ./out.json
```

**使用conda activate tfuzz-py38这个环境运行测试**

也可以在仓库根目录运行，但需要把 `fuzzer/` 加到 `PYTHONPATH`：

```bash
PYTHONPATH=./fuzzer python3 fuzzer/main.py -s fuzzer/test/reentrancy/inter_RE_buggy_6.sol -r ./out.json
```

### 1.2 依赖安装
依赖位于 `fuzzer/requirements.txt`：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r fuzzer/requirements.txt
```

Solidity 编译使用 `py-solc-x`（`solcx`），会在运行时按需安装/切换 solc（见 `fuzzer/utils/utils.py` 的 `compile()` 与 `fuzzer/main.py` 的 `_compile_with_ast()`）。

### 1.3 常用命令行参数（入口：`fuzzer/main.py`）
最常用的两种模式：

- **源码模式（推荐）**：`-s/--source` 指向 `.sol`，从编译产物获得 ABI/bytecode，并可用 source-map/AST 做增强分析。
- **ABI 模式**：`-a/--abi` + `-c/--contract`（链上地址），通过 RPC 读取 bytecode 做远程 fuzz（会将 `settings.REMOTE_FUZZING=True`）。

示例（源码）：
```bash
cd fuzzer
python3 main.py -s test/overflow/inter_IO_buggy_6.sol -r ./out.json
```

示例（ABI + 远程 RPC，需要节点可达）：
```bash
cd fuzzer
python3 main.py -a /path/to/abi.json -c 0x... --rpc-host localhost --rpc-port 8545 -r ./out.json
```

输出结果：
- 结果写入由 `-r/--results` 控制：可写到单个 `.json`，也可写到目录（每个合约一个 json），见 `fuzzer/engine/analysis/execution_trace_analysis.py` 的 `finalize()`。

---

## 2. 代码结构总览（含未启用/未引用标注）

仓库根目录：

- `README.md`：一句话项目定位。
- `tFuzz_项目文档.md`：本文件（新人文档）。
- `需求文档.docx`：需求/设计相关文档（仓库内存在，但运行不依赖）。
- `fuzzer/`：核心实现与测试数据。

`fuzzer/` 目录结构：

- `fuzzer/main.py`：**程序入口**，参数解析、编译、初始化 EVM/求解器、构建并运行 `Fuzzer`。
- `fuzzer/requirements.txt`：Python 依赖列表。
- `fuzzer/evm/`：EVM 执行与环境插桩（基于 py-evm，支持远程 RPC）。
  - `fuzzer/evm/__init__.py`：`InstrumentedEVM`（核心执行器）。
  - `fuzzer/evm/storage_emulation.py`：存储模拟 + opcode 级环境插桩（TIMESTAMP/BALANCE/CALL 等）。
- `fuzzer/engine/`：遗传算法演化引擎 + 组件 + 操作子 + 分析器。
  - `fuzzer/engine/engine.py`：`EvolutionaryFuzzingEngine`（选择/交叉/变异循环）。
  - `fuzzer/engine/components/`：个体、种群、输入生成与参数池。
    - `generator.py`：`Generator`（生成 transaction 序列、参数池、边界值/组合种子等）。
    - `individual.py`：`Individual`（chromosome -> EVM 输入解码，ABI 编码 data）。
    - `population.py`：`Population`（一组个体及统计接口）。
    - `contract_scraper.py`：从 Solidity 源码抓取硬编码常量生成参数池（地址/金额/int/string）。
    - `functionParameter.py`：提供一份基础种子池（address/uint/int/bool/string/byte）。
  - `fuzzer/engine/operators/`：遗传算子（selection/crossover/mutation），含数据依赖版本。
  - `fuzzer/engine/analysis/`：`ExecutionTraceAnalyzer`（执行 trace、覆盖率、符号引导、探测器触发等），`SymbolicTaintAnalyzer`（符号污点传播）。
  - `fuzzer/engine/fitness/__init__.py`：适应度函数（优先“特征路径命中数”，否则分支覆盖/数据依赖）。
  - `fuzzer/engine/plugin_interfaces/`：分析器/算子的接口与元类校验。
- `fuzzer/detectors/`：漏洞探测器（默认启用部分）。
  - `fuzzer/detectors/__init__.py`：`DetectorExecutor`（集中调度）。
  - 其他 `*.py`：具体探测器实现（见下文“默认启用 vs 未启用”）。
- `fuzzer/utils/`：编译、source-map、CFG、跨合约静态信息提取、通用函数、全局配置。
  - `settings.py`：全局参数与默认值。
  - `utils.py`：编译/ABI->selector 映射/bytecode 工具/日志等。
  - `source_map.py`：PC->源代码片段定位（用于报错定位）。
  - `inter_contract.py`：从 AST 构建跨合约调用边（XCFG）。
  - `control_flow_graph.py`：CFG 生成与可视化（依赖 Graphviz 的 `dot`）。
- `fuzzer/extensions/`：交易序列种子相关扩展（FAGSV 等）。
  - `fag_sv_adapter.py`：**当前入口使用**的 FAGSV 适配器（从 ABI/AST 生成序列）。
  - `fag_sv_adapter_v1.py`：**未引用/疑似历史版本**（入口未使用）。
  - `key_attributes.py`：**未引用/工具脚本**（fag_sv_adapter.py 内部有同名概念但不 import 此文件）。
  - `legacy_funseq.py`：**未引用/历史文件**。
- `fuzzer/test/`：测试合约与部分运行结果样例（不被代码自动遍历，作为数据集/手工运行输入）。
- `fuzzer/not_found_list.md`：数据集缺失条目清单（运行不依赖）。

---

## 3. 整体执行流程（从 `main.py` 到漏洞结果）

下面按默认源码模式（`-s`）描述主流程，便于新人对“数据怎么流动、哪块负责什么”建立直觉。

### 3.1 参数解析与全局配置
入口函数：
- `fuzzer/main.py:main()` -> `launch_argument_parser()`

要点：
- `--tx-seed` 默认是 `fagsv`：初始种群会走 `extensions/fag_sv_adapter.py` 生成函数序列。
- `--data-dependency` 默认 1：启用“数据依赖”版本的 selection/crossover（依赖 `ExecutionTraceAnalyzer` 动态提取 SLOAD/SSTORE 的读写槽位）。
- `--cfg`：生成 CFG pdf（见 `utils/control_flow_graph.py`，需要 Graphviz）。
- 会将命令行参数写回 `utils/settings.py` 中的全局变量（例如 `GENERATIONS/POPULATION_SIZE/PROBABILITY_*`）。

### 3.2 初始化 EVM 与 Z3 求解器
在 `main()` 内：
- `InstrumentedEVM(settings.RPC_HOST, settings.RPC_PORT)`
- `Solver().set("timeout", settings.SOLVER_TIMEOUT)`

执行环境分两类：
- **本地 fuzz（默认）**：不连 RPC，基于 py-evm 的内存 DB。
- **远程 fuzz（ABI 模式）**：`args.abi` 会设置 `settings.REMOTE_FUZZING=True`，storage/code/balance 等可通过 RPC 懒加载（见 `evm/storage_emulation.py` 的 `EmulatorAccountDB`）。

### 3.3 编译 + 合约选择 + SourceMap
源码模式下：
- 使用 `utils.utils.compile()` 做 standard-json 编译（关闭 optimizer，保留更多潜在可触发路径）。
- 若未指定 `-c/--contract`，会使用 `_auto_select_top_caller_from_source()` 做**启发式合约选择**：倾向选择“调用其他合约但不被其他合约调用”的顶层合约。
- 为每个候选合约构建 `SourceMap`（用于把 PC 映射到源代码片段，便于报告定位）。

### 3.4 构建 `Fuzzer` 与 `FuzzingEnvironment`
`Fuzzer.__init__()` 做的事：
- 根据 runtime bytecode 构建 `ControlFlowGraph`（用于 coverage/可视化等）。
- 解析 ABI 得到 `interface`：`selector -> [argTypes]`（见 `utils/utils.py:get_interface_from_abi()`）。
- 初始化 `FuzzingEnvironment`，把 `instrumented_evm/solver/detector_executor/symbolic_taint_analyzer/interface/abi/cfg` 等注入进去。

### 3.5 `Fuzzer.run()`：部署、跨合约准备、种子、演化
核心步骤（强烈建议新人按这个顺序读 `Fuzzer.run()`）：

1) **创建账户、部署目标合约**
- `instrumented_evm.create_fake_accounts()` + `deploy_contract()` 或读取链上 bytecode。

2) **跨合约探索准备**
- 预部署“常量返回 stub 合约”（对任意 call 都返回固定 32-byte 常量），帮助满足跨合约条件分支。
- 若提供 `--source`，使用 `_compile_with_ast()` + `utils/inter_contract.py:build_xcfg_from_standard_json()` 构建 XCFG，并尝试预部署同文件内的其它合约（非目标合约），把地址加入 `env.other_contracts`。

3) **输入生成器 `Generator` 与参数池种子**
- 强制对 non-payable 函数把 `amount` 池中加入 `0`（避免无意义的立即 revert）。
- `contract_scraper.py` 从源码抓硬编码常量（地址、ETH 单位、整数、字符串），注入 generator 的 type pool。
- `functionParameter.py:paramGenerate()` 再注入一套通用 seeds。
- 将 “stub 合约地址 + 预部署辅助合约地址” 作为 address-type 参数的优先候选（generator 内有 `preferred_addresses` 与 address pool 注入逻辑）。

4) **初始化种群**
- 默认 `--tx-seed=fagsv`：
  - 先走 AST 驱动：`extensions/fag_sv_adapter.py:build_contract_info_from_ast()`，再 `generate_sequences()`。
  - AST 失败则回退 ABI-only：`build_contract_info_from_abi()`。
  - 对生成的序列调用 `generator.generate_individual_from_sequence(seq)` 生成若干个体，补齐到 `population_size`。
- 非 `fagsv`：完全随机初始化。
- 另外会尝试用 `generator.iter_param_combinations()` 为每个函数追加少量“基础+边界值组合”个体（上限不超过 population size）。

5) **选择/交叉/变异 + 适应度 + 执行分析**
- `EvolutionaryFuzzingEngine.run()` 循环产生下一代。
- 每一代会调用 `ExecutionTraceAnalyzer.register_step()`：
  - 执行所有个体（把 chromosome 解码成 EVM 输入并在 InstrumentedEVM 中运行）。
  - 更新 code coverage / branch coverage / visited branches / data dependencies（SLOAD/SSTORE）。
  - 触发 detectors 报告漏洞。
  - 若覆盖率停滞，会进行一定次数的符号引导（并可能重置种群）。

6) **结果落盘**
- 在 `ExecutionTraceAnalyzer.finalize()` 汇总并写入 `--results` 指定路径。

---

## 4. 核心数据结构

### 4.1 Individual / Chromosome / Transaction（“个体”是什么）
`engine/components/individual.py`：
- `Individual.chromosome`：一串“基因”，每个基因对应一次交易调用（或 constructor）。
- `Individual.decode()`：把 chromosome 转为 EVM 执行输入列表 `solution`，每个元素是：
  - `transaction`: `{from,to,value,gaslimit,data}`
  - `block`: `{timestamp,blocknumber}`
  - `global_state`: `{balance,call_return,extcodesize}`
  - `environment`: `{returndatasize}`

其中 `data` 的编码逻辑是：
- constructor：拼接部署 bytecode
- function：`selector + ABI-encoded(args)`（`eth_abi.encode_abi`）

### 4.2 Generator
`engine/components/generator.py` 的 `Generator` 负责随机/半随机地产生 chromosome，并维护大量池（pool）用于复用“好值”：
- `accounts_pool`：调用者地址池
- `amounts_pool`：value（Wei）池
- `arguments_pool`：按函数+参数位维护的参数池
- `timestamp_pool/blocknumber_pool/balance_pool`：环境字段池
- `callresult_pool/extcodesize_pool/returndatasize_pool`：用于“环境插桩”的返回值池
- `preferred_addresses`：优先作为 address-type 参数的“有效合约实例地址”

这些池的来源：
1) 初始常量 seeds（`functionParameter.py`）
2) 源码抓取 seeds（`contract_scraper.py`）
3) 运行时符号引导、异常反馈（`ExecutionTraceAnalyzer` 会在 REVERT 等情况下从池中剔除“明显坏值”，并从模型中加入“可能更好”的值）
4) 跨合约准备阶段预部署的地址（stub/helper contracts）

---

## 5. 漏洞探测（Detectors）

探测器统一由 `fuzzer/detectors/__init__.py:DetectorExecutor` 调度，在 `ExecutionTraceAnalyzer` 的 trace 执行过程中被触发。

### 5.1 默认启用的探测器（当前代码路径会跑到）
在 `DetectorExecutor.__init__()` 中实例化并 `initialize_detectors()` 调用的有：
- `IntegerOverflowDetector`（SWC-101，高）：检测 ADD/SUB 相关 overflow/underflow，并结合 taint/流向（SSTORE/CALL/条件）给出报告。
- `ReentrancyDetector`（SWC-107，高）：SLOAD -> CALL(value>0) -> SSTORE 的启发式序列检测；并在 executor 层用 source-map 过滤“看起来不像转账调用”的行（避免误报）。
- `BlockDependencyDetector`（SWC-116，低）：时间戳相关依赖（TIMESTAMP/now）流入条件并影响 value-bearing call 的启发式检测。
- `UncheckedReturnValueDetector`（SWC-104，中）：外部调用返回值未被检查的启发式检测。

### 5.2 存在但默认未启用的探测器（代码在，但入口注释掉）
`fuzzer/detectors/` 目录下还有多种 detector 文件，但在 `DetectorExecutor` 中被注释掉，默认不会运行：
- `assertion_failure.py`
- `arbitrary_memory_access.py`
- `transaction_order_dependency.py`
- `unsafe_delegatecall.py`
- `leaking_ether.py`
- `locking_ether.py`
- `unprotected_selfdestruct.py`

如果要启用：通常需要在 `DetectorExecutor.__init__()` / `initialize_detectors()` / `run_detectors()` 中解除注释并按模式接入。

---

## 6. 跨合约能力

该项目的跨合约探索主要来自三类机制（都在 `Fuzzer.run()` 附近）：

1) **XCFG（跨合约调用边）**
- 通过编译产物 AST 构建跨合约调用边：`utils/inter_contract.py:build_xcfg_from_standard_json()`。
- 目前的 XCFG 是轻量语法分析：识别“变量类型是另一个合约 + 对该变量 member call”的情况。

2) **预部署同文件内的辅助合约**
- 编译输出中，除目标合约外的其它合约会尝试部署到本地 EVM，把地址加入 `env.other_contracts`，并在 generator 中优先作为 address 参数使用。

3) **常量返回 stub 合约**
- 预先部署若干“恒定返回值”的 stub 合约，用于满足跨合约条件检查（例如 `require(other.balance()>X)` 之类），减少因为缺少被调合约而无法覆盖分支的问题。

---

## 7. 结果与可视化

### 7.1 结果 JSON
在 `ExecutionTraceAnalyzer.finalize()` 写入：
- 交易数、吞吐、覆盖率、耗时、内存
- 漏洞 `errors`（按 PC 聚合，包含 SWC-ID、severity、对应交易序列、可选 source-map 行列/代码片段）
- 每代的覆盖率曲线（`generations`）
- 可选：`best_test_case`（便于复现实验）

### 7.2 CFG 输出
`--cfg` 会调用 `ControlFlowGraph.save_control_flow_graph(..., 'pdf')` 生成 pdf，依赖系统中存在 `dot`（Graphviz）。

---

## 8. 未使用/未启用/易混淆点清单

### 8.1 `main.py` 内未被调用的函数
- `_generate_fagsv_sequences_from_interface()`：定义在 `fuzzer/main.py` 但当前逻辑实际使用 `extensions/fag_sv_adapter.py` 的 `generate_sequences()`，该函数未被引用。

### 8.2 `extensions/` 中未被入口引用的文件
入口只 import `extensions/fag_sv_adapter.py`，以下文件目前未被运行路径引用：
- `fuzzer/extensions/fag_sv_adapter_v1.py`
- `fuzzer/extensions/key_attributes.py`
- `fuzzer/extensions/legacy_funseq.py`

### 8.3 `detectors/` 中未启用的探测器
见上文 5.2：文件存在但在 `DetectorExecutor` 内被注释。

### 8.4 `test/` 目录的定位
`fuzzer/test/` 是数据集与样例输出，不会被程序自动批量遍历；需要你在命令行指定 `-s` 指向某个 `.sol` 才会执行。

### 8.5 运行环境细节
- 远程 fuzz（ABI 模式）依赖 RPC 可达，否则会在获取区块/存储/代码时报错。
- 生成 CFG pdf 依赖 Graphviz；否则会提示安装。
- solc 版本：代码会尝试安装/切换多个版本，但离线环境会失败；建议预先把常用版本安装到 `solcx`。

