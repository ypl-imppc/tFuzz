# tFuzz
A novel cross-contract grey-box fuzzing approach that synergistically combines semantic transaction sequencing with evolutionary feature path exploration.This project is the supporting material of the paper titled "tFuzz: Evolutionary Fuzzing of Cross-Contract Vulnerabilities via Semantic Transaction Sequencing and Feature Path Coverage", including: data set, test results, source code, etc.

This paper proposes tFuzz, a novel cross-contract grey-box fuzzing approach. tFuzz efficiently detects cross-contract vulnerabilities through a semantics-based transaction sequence generation algorithm and a genetic algorithm (GA) guided by feature path coverage. Specifically, semantic transaction sequences are jointly determined by function activity within the contract and the def-use chains of global state variables. The function activity metric integrates the number of vulnerability features within the function, the number of global state variables, and the in-degree of the function in the cross-contract control flow graph (CCFG). Furthermore, feature path coverage uses the number of execution paths containing vulnerability features as its fitness function, effectively guiding the fuzzing process toward rapid convergence.

- [Folder introduction]
- [Bash Command]
- [Publications]

## Folder introduction

### test
The folder "test" includes 64,274 solidity files .

### requirements.txt
tFuzz

### optimization_results.csv
actScores

## Bash Command

Run tFuzz a single file:

python fuzzer/main.py -s path/to/solidity.sol

### License
ContractFull is licensed and distributed under the AGPLv3 license.

### References

-[ConFuzzius: A. K. Iannillo, A. Gervais, R. State, and Ieee. 2021. "CONFUZZIUS: A Data Dependency-Aware Hybrid Fuzzer for Smart Contracts." In 6th IEEE European Symposium on Security and Privacy (Euro S and P), 103-19. Electr Network: Ieee.]
