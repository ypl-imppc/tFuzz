# contract_scraper.py
import re
from decimal import Decimal, InvalidOperation

def create_contractpools(_contractSol, _known_addresses):
    """
    从 Solidity 源码中抓取硬编码值，构建后续随机方法生成时可用的输入池。
    返回: addresspool, ETHpool, intpool, stringpool
    """
    contractSol = _contractSol
    # Always scrape addresses from source; validate against known set if provided
    addresspool = scrape_addresses(contractSol)
    if _known_addresses:
        assert addresspool.intersection(_known_addresses) == addresspool, \
            "A hardcoded address was found that does not exist on the blockchain used."

    ETHpool = scrape_vals(contractSol)
    intpool = scrape_ints(contractSol)
    stringpool = scrape_strings(contractSol)
    return addresspool, ETHpool, intpool, stringpool


def scrape_addresses(_contractSol):
    """抓取硬编码以 0x 开头的 40 位十六进制地址（大小写均可）"""
    contractSol = _contractSol
    addresspool = set()
    regex = r"0x[0-9a-fA-F]{40}"
    for match in re.finditer(regex, contractSol, re.MULTILINE):
        addresspool.add(match.group().lower())  # 统一小写
    return addresspool


def scrape_vals(_contractSol):
    """
    抓取硬编码的 ETH 金额：形如 '1 wei|gwei|szabo|finney|ether'。
    统一换算为 wei（整数），并放入 ETHpool。
    """
    contractSol = _contractSol
    ETHpool = set()
    # 捕获数值+单位；单位边界用 \b，避免匹配到更长标识符
    regex = r"([0-9]*\.?[0-9]+)\s*(wei|gwei|szabo|finney|ether)\b"
    for m in re.finditer(regex, contractSol, re.MULTILINE):
        num_s, unit = m.groups()
        try:
            val = Decimal(num_s)
        except InvalidOperation:
            continue
        scale = {
            'wei':   Decimal(1),
            'gwei':  Decimal(10) ** 9,
            'szabo': Decimal(10) ** 12,
            'finney':Decimal(10) ** 15,
            'ether': Decimal(10) ** 18,
        }[unit]
        wei = val * scale
        # 必须是整数 wei
        assert wei == wei.to_integral_value(), f"A non-integer wei value was found: {wei}"
        ETHpool.add(int(wei))
    return ETHpool


def scrape_ints(_contractSol):
    """
    抓取硬编码整数（排除 pragma 行与变量声明中的初始化字面量），
    并把 n, n+1, n-1 都加入 pool，提高邻域探索。
    """
    contractSol = _contractSol

    # 删除 pragma 行，避免把版本号当作整数抓取
    contractSol = re.sub(r"(?:pragma\s+solidity)\s*\^?[0-9.]*", "", contractSol)

    # 删除形如 `uint x = 123` 或 `int256 y= -5` 中的字面量，避免误抓
    contractSol = re.sub(
        r"\b(?:u?int(?:8|16|32|64|128|256)?)\s+[A-Za-z_]\w*\s*=\s*-?\d+",
        lambda m: re.sub(r"-?\d+", "", m.group(0)),
        contractSol
    )

    intpool = set()
    # 抓取独立的十进制整数（避免紧接标识符的情形）
    for m in re.finditer(r"(?<![A-Za-z0-9_])-?\d+\b", contractSol):
        n = int(m.group())
        intpool.update({n, n + 1, n - 1})
    return intpool


def scrape_strings(_contractSol):
    """
    抓取硬编码字符串；会先移除 require/revert 中的报错信息（避免把错误信息塞入 pool）。
    单引号统一转双引号，去掉 %。
    """
    contractSol = _contractSol
    stringpool = set()

    # 去掉 require/revert 的错误消息
    regex = r"(require)|(revert)"
    errorMatch = re.search(regex, contractSol, re.MULTILINE)
    start = 0
    while errorMatch:
        contractSol, new_start = remove_errorStrings(contractSol, 0, errorMatch.end() + start)
        start = new_start
        errorMatch = re.search(regex, contractSol[start:], re.MULTILINE)

    # 抓取剩余字符串（排除 import 行）
    regex = r"(?<!import )([\"'])(?:(?=(\\?))\2.)*?\1"
    matches = re.finditer(regex, contractSol, re.MULTILINE)
    for match in matches:
        scrapedString = match.group()
        if scrapedString[0] == "'":
            assert scrapedString[-1] == "'", \
                f"If a scraped string starts with \"'\" it should also end with it, instead this ends with {scrapedString[-1]}."
            scrapedString = '"' + scrapedString[1:-1] + '"'
        stringpool.add(scrapedString.replace("%", ""))
    return stringpool


def remove_errorStrings(_contractSol, _brack_ctr, _pos):
    """
    从 require/revert 语句中移除括号内的错误字符串（若存在）。
    返回：更新后的源码字符串、继续扫描的起点。
    """
    assert _brack_ctr >= 0, "The bracket counter cannot be smaller than 0!"
    regex = r"[\(\)\n]"
    match = re.search(regex, _contractSol[_pos:])
    found = match.group()
    assert found is not None, "Nothing was found!"
    pos = _pos + match.span()[0]

    if found == "\n":
        # 换行，直接跳过
        return _contractSol, pos + 1
    elif found == "(":
        # 进入括号
        brack_ctr = _brack_ctr + 1
        position = pos + 1
        return remove_errorStrings(_contractSol, brack_ctr, position)
    elif found == ")":
        # 退出括号
        brack_ctr = _brack_ctr - 1
        if brack_ctr == 0:
            regex = r"([\"'])(?:(?=(\\?))\2.)*?\1\s*\)\Z"
            errorstring = re.search(regex, _contractSol[:pos + 1])
            if errorstring:
                # 找到错误字符串，删掉
                _contractSol = _contractSol[:errorstring.span()[0]] + _contractSol[errorstring.span()[1]:]
                return _contractSol, match.span()[0]
            else:
                return _contractSol, pos + 1
        else:
            position = pos + 1
            return remove_errorStrings(_contractSol, brack_ctr, position)
    else:
        raise AssertionError(f"Found unexpected pattern: {found}")