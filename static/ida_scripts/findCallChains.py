
import idaapi

# tcp_v4_rcv
#START_EA = 0xC1780B10
START_EA = 0x000000000002A5E0

# mark drop functions
#TARGET_EA = 0xC16FAB00
#TARGET_EA = 0x08073204
#TARGET_EA = 0x08017320
#TARGET_EA = 0x0801FF67
#TARGET_EA = 0x0801033F
#TARGET_EA = 0x0801AE28    # set state TCP_NEW_SYN_RECV
TARGET_EA = 0x0000000000017240 # tcp_drop

entry_func = idaapi.get_func(START_EA)
entry_func_name = Name(entry_func.startEA) or "Entry"
marked_func = idaapi.get_func(TARGET_EA)
marked_func_name = Name(marked_func.startEA) or "MarkedFunc"

# debug output
print("Entry Function Address: %x" % START_EA)
print("Entry Function Name: '%s'" % entry_func_name)
print("Marked Instruction Address: %x" % TARGET_EA)
print("Marked Instruction belongs to function '%s'" % marked_func_name)

# There are 2 steps:
# 1. Find all possible call chains (no recursive, i.e. recursive level = 1)
# 2. Find all possible paths within each function in the call chain

# 1. Find all possible call chains
# backwards or fowards? or both at the same time?

all_call_chains = []

def convert_call_stack_to_call_chain(call_stack, reverse=False):
    call_chain = []
    sorted_call_stack = sorted(call_stack.iteritems(), key=lambda (k,v): v['level'], reverse=reverse)

    for k, v in sorted_call_stack:
        call_chain.append([k, v['start_ea'], v['call_site'], v['level']])

    # quickfix
    if reverse:
        for i in range(len(call_chain)):
            call_chain[i][3] = len(call_chain) - 1 - call_chain[i][3] 
    else:
        for i in range(len(call_chain)-1):
            call_chain[i][2] = call_chain[i+1][2]
        call_chain[-1][2] = 0

    return call_chain


# ~75s
def find_call_chain_forward(curr_func, target_func, call_stack, curr_level):
    global fd
    #fd.write("Current Func: %s\n" % (Name(curr_func.startEA) or "N/A"))
    if curr_func == target_func:
        all_call_chains.append(convert_call_stack_to_call_chain(call_stack))
        return

    for i in FuncItems(curr_func.startEA):
        for xref in XrefsFrom(i, 0):
            #fd.write("%s calls %s from 0x%x. Type: %d" % (Name(curr_func.startEA), Name(xref.to), i, xref.type))
            #fd.write("\n")
            if xref.type == fl_CN or xref.type == fl_CF:
                callee = idaapi.get_func(xref.to)
                callee_name = Name(callee.startEA) or "N/A" 
                if callee_name not in call_stack:
                    curr_level += 1
                    call_stack[callee_name] = {'level': curr_level, 'start_ea': callee.startEA, 'call_site': i}
                    find_call_chain_forward(callee, target_func, call_stack, curr_level)
                    del call_stack[callee_name]
                    curr_level -= 1

# ~25s
def find_call_chain_forward2(curr_func, target_func, call_stack, curr_level):
    global fd
    #fd.write("Current Func: %s\n" % (Name(curr_func.startEA) or "N/A"))
    if curr_func == target_func:
        all_call_chains.append(convert_call_stack_to_call_chain(call_stack))
        return

    for i in FuncItems(curr_func.startEA):
        for ref in CodeRefsFrom(i, 0):
            callee = idaapi.get_func(ref)
            callee_name = Name(callee.startEA) or "N/A" 
            if callee_name not in call_stack:
                curr_level += 1
                call_stack[callee_name] = {'level': curr_level, 'start_ea': callee.startEA, 'call_site': i}
                find_call_chain_forward2(callee, target_func, call_stack, curr_level)
                del call_stack[callee_name]
                curr_level -= 1

# ~1s
def find_call_chain_backward(curr_func, target_func, call_stack, curr_level):
    global fd
    if curr_func == target_func:
        all_call_chains.append(convert_call_stack_to_call_chain(call_stack, True))
        return

    for xref in XrefsTo(curr_func.startEA, 0):
        if xref.type == fl_CN or xref.type == fl_CF:
            caller = idaapi.get_func(idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_START))
            caller_name = Name(caller.startEA) or "N/A"
            if caller_name not in call_stack:
                curr_level += 1
                call_stack[caller_name] = {'level': curr_level, 'start_ea': caller.startEA, 'call_site': xref.frm}
                find_call_chain_backward(caller, target_func, call_stack, curr_level)
                del call_stack[caller_name]
                curr_level -= 1

# ~1s
def find_call_chain_backward2(curr_func, target_func, call_stack, curr_level):
    global fd
    if curr_func == target_func:
        all_call_chains.append(convert_call_stack_to_call_chain(call_stack, True))
        return

    for ref in CodeRefsTo(curr_func.startEA, 0):
        caller = idaapi.get_func(idc.GetFunctionAttr(ref, idc.FUNCATTR_START))
        if caller:
            caller_name = Name(caller.startEA) or "N/A"
            if caller_name not in call_stack:
                curr_level += 1
                call_stack[caller_name] = {'level': curr_level, 'start_ea': caller.startEA, 'call_site': ref}
                find_call_chain_backward2(caller, target_func, call_stack, curr_level)
                del call_stack[caller_name]
                curr_level -= 1


file = AskFile(1, "*.txt", "Select output file")
fd = open(file, 'w')

# forwards
#find_call_chain_forward2(entry_func, marked_func, {entry_func_name: {'level': 0, 'start_ea': START_EA, 'call_site': 0}}, 0)
# backwards
find_call_chain_backward2(marked_func, entry_func, {marked_func_name: {'level': 0, 'start_ea': marked_func.startEA, 'call_site': TARGET_EA}}, 0)

for cc in all_call_chains:
    func_name, start_ea, call_site, lvl = cc[0]
    fd.write("%s,%x,%x" % (func_name, start_ea, call_site))
    for func_name, start_ea, call_site, lvl in cc[1:]:
        fd.write("|%s,%x,%x" % (func_name, start_ea, call_site))
    fd.write("\n")

#f = idaapi.FlowChart(get_func(idc.ScreenEA()))

fd.close()

