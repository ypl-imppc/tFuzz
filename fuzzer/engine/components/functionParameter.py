import re

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

def _is_valid_addr(s: str) -> bool:
    return isinstance(s, str) and _ADDR_RE.fullmatch(s or "") is not None

def paramGenerate():
    """
    Provide seed parameter pools for different Solidity types.
    - Addresses are strictly validated to be 20-byte hex (0x + 40 hex chars).
    - Include a small, deterministic set of canonical addresses to avoid
      feeding invalid strings into ABI encoders.
    """
    # ---------- address (20 bytes / 160 bits) ----------
    # Use canonical, strictly valid addresses only
    addressCandidates = [
        "0x0000000000000000000000000000000000000000",
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
    ]
    addressParams = [a for a in addressCandidates if _is_valid_addr(a)]

    # ---------- uint (default uint256) ----------
    # Keep a few small values + boundary-like seeds
    uintParams = [0, 1, 2, 10, 99, 127, 255, 256, 1024]

    # ---------- int (default int256) ----------
    intParams = [-2, -1, 0, 1, 2, 127, -127]

    # ---------- byte/bytes1 ----------
    byteParams = [0x00, 0x01, 0xff]

    # ---------- bool ----------
    boolParams = [True, False]

    # ---------- string ----------
    stringParams = ["", "a", "1", "test"]

    paramDic = {
        "address": addressParams,
        "uint": uintParams,
        "int": intParams,
        "byte": byteParams,
        "bool": boolParams,
        "string": stringParams,
    }
    return paramDic