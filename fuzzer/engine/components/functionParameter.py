def paramGenerate():
    # function parameters of address type, length is 20, 160bit, 20Byte
    addressParams = ['0x12abcbfd12abcbfd12abcbfd12abcbfd12abcbfd12abcbfd']

    # function parameters of uint type, default is uint256
    uintParams = [0, 1, 99, 127]

    # function parameters of int type, default is int256
    intParams = [-1, 0, 1]

    # function parameters of byte type, default is byte1
    byteParams = [0x01, 0x00]

    # function parameters of bool type
    boolParams = [True, False]

    # function parameters of string type
    stringParams = ['a', '1']

    # function parameters of mapping type
    # mapping key

    # mapping value

    paramDic = {}
    paramDic.update({'address': addressParams})
    paramDic.update({'uint': uintParams})
    paramDic.update({'byte': byteParams})
    paramDic.update({'bool': boolParams})
    paramDic.update({'string': stringParams})
    return paramDic