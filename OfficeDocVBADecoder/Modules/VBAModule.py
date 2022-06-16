import re
import Modules.MathModule as MM

possibleStarts = ["autoopen", "auto_open", "auto_exec", "autoexec", "document_open", "documentopen", "workbook_open", "workbookopen"]

def FunctionList (funcs):
    funcNames = []
    for i in funcs:
        x = re.search (r"(?:.*)(?:(?:sub|function)\s)(\w*)(?:\(|\s|$)(?:.*)", i)
        if x is not None:
            funcNames.append(x.groups()[0])

    return funcNames

def FunctionalizeVBA (vbaArray):
    functions = {"null": []}
    inFunc = 0

    currBuffer = []
    currName = ""
    for line in vbaArray:
        line = line.lower().strip()
        i = line.split()
        if "alias" in i:
            functions["null"].append(line)
        elif "end" in i and ("sub" in i or "function" in i):
            inFunc = 0
            currBuffer.append(line)
            functions[currName] = currBuffer
            currBuffer = []
            currName = ""
        elif ("function" in i or "sub" in i) and inFunc == 0:
            currName = line
            inFunc += 1
        else:
            if len(line) == 0:
                continue
            if inFunc > 0:
                currBuffer.append(line)
            else:
                functions["null"].append(line)

    return functions

def FunctionWalk (funcName, funcDict, funcList, trace):
    trace.append(funcName)
    for line in funcDict[funcName]:
        splitLine = [x for x in re.split (r'[\(\),\s]', line) if x != '']

        potentialCall = [x for x in splitLine if x in funcList and x not in funcName]
        if len(potentialCall) > 0:
            trace = FunctionWalk ([x for x in funcDict if potentialCall[0] in x][0], funcDict, funcList, trace)

    return trace


def CleanFunctions (funcs):
    for funcNames in funcs:
        code = funcs[funcNames]
        if (funcNames == "null"):
            code = [x for x in code if "attribute" not in x]
        code = [x for x in code if x[0]!="'" and x[0:2]!="\\'"]
        funcs[funcNames] = code

    allNames = FunctionList(funcs)
    initPoint = [x for x in allNames if x in possibleStarts][0]
    startFunc = [x for x in funcs if initPoint in x][0]

    walked = FunctionWalk (startFunc, funcs, allNames, [])
    print (walked)

    usedFuncs = {"null": funcs["null"]}
    for i in funcs:
        if i in walked:
            usedFuncs[i] = funcs[i]

    for funcNames in usedFuncs:
        code = usedFuncs[funcNames]
        for line in code:
            splitLine = [x for x in re.split(r'\s+(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)', line) if x != '']
            print (splitLine)

    return usedFuncs


    for funcNames in funcs:
        code = funcs[funcNames]

        variables = {}
        count = 0

        print (funcNames)
        while count < len(code):
            line = code[count]
            splitLine = [x for x in re.split (r'[\(\),\s]', line) if x != '']
            print (splitLine)
            count += 1

    return funcs
        # for count in range(len(code)):
            # line = [x.strip() for x in code[count].split("=")]

            # # Variable Declaration
            # if " as " in line[0]:
                # varName = line[0].split()
                # # varName2 = varName[varName.index("as") - 1]
                # # variables.setdefault(varName2, [])
                # # variables[varName2].append(["init", varName[varName.index("as") + 1], count])

            # # If statement
            # elif re.match(r'#?if(\s|\()', line[0]):
                # continue

            # # For statement
            # elif re.match(r'for(\s|\()', line[0]):
                # continue

            # # While statement
            # elif re.match(r'while(\s|\()', line[0]):
                # continue

            # # Normal Assignment
            # elif len(line) == 2:
                # line[0] = line[0][4:] if re.match(r'set\s', line[0]) else line[0]
                # variables.setdefault(line[0], line[1])

                # if MM.CheckValue(line[1]):
                    # line[1] = MM.MathSolver(line[1], variables)
                    # code[count] = line[0] + " = " + line[1]

            # # Funtion call
            # else:
                # ProcessCustomFunction()

        # funcs[funcNames] = code
    # return funcs

# def ProcessCustomFunction(line):
    # funcCall = re.split(r'[\s|,|\(]', line)
    # if funcCall[0] in allNames:
        # print (funcCall)
    # return

# def ProcessBuiltInFunction():
    # return

# def ProcessMathAssignment():
    # return

# def ProcessWhileLoop():
    # return

# def ProcessForLoop():
    # return
