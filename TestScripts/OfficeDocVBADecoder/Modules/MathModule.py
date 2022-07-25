import re

def CastToFloat (x, variables):
    try:
        y = float(x)
        return y
    except:
        try:
            return float(variables[x])
        except:
            return "exit"

def CheckValue (x):
    return len(x) == len(re.findall(r'[\s0-9A-Za-z\+\-\*\/]', x))

def MathSolver (equation, variables):
    saveEq = equation
    equation = '(' + equation + ')'

    while '(' in equation:
        indexOpen = equation.rfind('(')
        indexClose = equation[indexOpen:].find(')')
        inner = equation[indexOpen+1:indexClose+indexOpen]

        splitStr = [CastToFloat(x.strip(), variables) for x in re.split (r'[\+\-\*\/]', inner)]
        if "exit" in splitStr:
            return saveEq
        ops = [x for x in inner if x in '+-*/']

        while len(ops) > 0:
            if '*' in ops:
                indOp = ops.index('*')
                res = splitStr[indOp] * splitStr[indOp+1]
            elif '/' in ops:
                indOp = ops.index('/')
                res = splitStr[indOp] / splitStr[indOp+1]
            elif '+' in ops:
                indOp = ops.index('+')
                res = splitStr[indOp] + splitStr[indOp+1]
            elif '-' in ops:
                indOp = ops.index('-')
                res = splitStr[indOp] - splitStr[indOp+1]

            del splitStr[indOp:indOp+2]
            del ops[indOp]
            splitStr.insert(indOp, res)

        equation = equation[:indexOpen] + str(splitStr[0]) + equation[indexClose+indexOpen+1:]

    return equation
