# contract_scraper.py
import re

def create_contractpools(_contractSol, _known_addresses):
    """
    从 Solidity 源码中抓取硬编码值，构建后续随机方法生成时可用的输入池。
    返回: addresspool, ETHpool, intpool, stringpool
    """
    contractSol = _contractSol
    if len(_known_addresses) > 0:
        addresspool = scrape_addresses(contractSol)
    else:
        addresspool = set()
    assert addresspool.intersection(_known_addresses) == addresspool, \
        "A hardcoded address was found that does not exist on the blockchain used."
    ETHpool = scrape_vals(contractSol)
    intpool = scrape_ints(contractSol)
    stringpool = scrape_strings(contractSol)
    return addresspool, ETHpool, intpool, stringpool


def scrape_addresses(_contractSol):
    """抓取硬编码以 0x 开头的 40 位地址（大小写混合均可）"""
    contractSol = _contractSol
    addresspool = set()
    regex = r"0x[A-Za-z0-9]{40}"
    addressMatches = re.finditer(regex, contractSol, re.MULTILINE)
    for match in addressMatches:
        addresspool.add(match.group().lower()) # <--- 统一小写
    return addresspool


def scrape_vals(_contractSol):
    """
    抓取硬编码的 ETH 金额：形如 '1 wei|szabo|finney|ether'。
    统一换算为 wei（整数），并放入 ETHpool。
    """
    contractSol = _contractSol
    ETHpool = set()
    regex = r"[0-9]*\.?[0-9]+\s*(wei|szabo|finney|ether)"
    valMatches = re.finditer(regex, contractSol, re.MULTILINE)
    for match in valMatches:
        regex = r"[0-9]*\.?[0-9]+"
        val = float(re.search(regex, match.group()).group())
        unit = match.group().split()[-1]

        if unit == "wei":
            assert val % 1 == 0, f"A non-integer wei value was found: {val}"
            ETHpool.add(int(val))
        elif unit == "szabo":
            val = val * 10**12
            assert val % 1 == 0, f"A non-integer wei value was found: {val}"
            ETHpool.add(int(val))
        elif unit == "ether":
            val = val * 10**18
            assert val % 1 == 0, f"A non-integer wei value was found: {val}"
            ETHpool.add(int(val))
        else:
            # finney
            val = val * 10**15
            assert val % 1 == 0, f"A non-integer wei value was found: {val}"
            ETHpool.add(int(val))
    return ETHpool


def scrape_ints(_contractSol):
    """
    抓取硬编码整数（排除 pragma 行与紧随 int/uint 声明的字面量），
    并把 n, n+1, n-1 都加入 pool，提高邻域探索。
    """
    contractSol = _contractSol
    intpool = set()

    # 删除 pragma 行，避免把版本号当作整数抓取
    regex = r"(pragma solidity)\s*[\ˆ\^]?[0-9\.]*"
    pragmaMatch = re.search(regex, contractSol, re.MULTILINE)
    while pragmaMatch:
        contractSol = contractSol[:pragmaMatch.span()[0]] + contractSol[pragmaMatch.span()[1]:]
        pragmaMatch = re.search(regex, contractSol, re.MULTILINE)

    # 忽略紧跟在 int/uint 声明后的整数；其余负号与数字匹配
    regex = r"-?(?<![(int)\d])\d+"
    intMatches = re.finditer(regex, contractSol, re.MULTILINE)
    for match in intMatches:
        n = int(match.group())
        intpool.add(n)
        intpool.add(n + 1)
        intpool.add(n - 1)
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
            return remove_errorStrings(_contractSol, _brack_ctr, position)
    else:
        raise AssertionError(f"Found unexpected pattern: {found}")