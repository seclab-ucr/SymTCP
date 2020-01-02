

import idaapi

from cfg import *

ENTRY_FUNC = 0xffffffff8178ffa0


mycg = CallGraph()
mycfg = CFG()


entry_func = idaapi.get_func(ENTRY_FUNC)


visited = set()

def traverse(func):
    func_name = Name(func.startEA)
    assert func_name

    if func_name in visited:
        return
    visited.add(func_name)

    myfunc = Function(func.startEA, func_name)

    f = idaapi.FlowChart(func)
    for bb in f:
        mybb = BasicBlock(bb.startEA, bb.endEA - bb.startEA)
        mybb.last_inst_addr = PrevHead(bb.endEA)
        mybb.last_inst = GetDisasm(mybb.last_inst_addr)
        for pred_bb in bb.preds():
            mybb.preds.append(pred_bb.startEA)
        for succ_bb in bb.succs():
            mybb.succs.append(succ_bb.startEA)
        mycfg.nodes[bb.startEA] = mybb
        myfunc.blocks.append(mybb)

    for i in FuncItems(func.startEA):
        for ref in CodeRefsFrom(i, 0):
            callee = idaapi.get_func(ref)
            if callee:
                myfunc.callees.append((i, ref))
                traverse(callee)
                

    for ref in CodeRefsTo(func.startEA, 0):
        caller = idaapi.get_func(GetFunctionAttr(ref, FUNCATTR_START))
        if caller:
            myfunc.callers.append((ref, caller.startEA))

    mycg.nodes[func.startEA] = myfunc
    mycg.nodes_by_names[func_name] = myfunc
        

traverse(entry_func)

# set entry
mycg.entry = mycg.nodes[entry_func.startEA]
mycfg.entry = mycfg.nodes[entry_func.startEA]


import cPickle

# dump cfg
file1 = AskFile(1, "*.txt", "Select cfg output file")
fd1 = open(file1, 'wb')
cPickle.dump(mycfg, fd1)
fd1.close()

# dump call graph
file2 = AskFile(1, "*.txt", "Select call graph output file")
fd2 = open(file2, 'wb')
cPickle.dump(mycg, fd2)
fd2.close()

