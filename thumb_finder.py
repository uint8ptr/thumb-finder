import idaapi
import idautils
import idc

def get_end(start):
    MAX_SCAN_SIZE = 0x10000000

    end = idaapi.inf_get_max_ea()

    if end-start > MAX_SCAN_SIZE:
        end = idaapi.getseg(start).end_ea

    return end

def try_add_function(ea):
    flags = idaapi.get_flags(ea)

    if idaapi.is_code(flags):
        print("Found already defined function at 0x%08x" % ea)
        return

    success = idaapi.add_func(ea)

    if not success:
        print("Found bad function at 0x%08x" % ea)

        end = get_end(ea)
        func_end = idaapi.next_unknown(ea, end)

        for op in idautils.Heads(ea, func_end):
            idaapi.del_items(op)

    else:
        print("Found new function at 0x%08x" % ea)

def find_push():
    OP_PUSH = 0xB4, 0xB5
    OP_PUSH16 = 0xF84D, 0xE92D

    ea_list = []
    start = idaapi.inf_get_min_ea()
    end = get_end(start)

    for ea in range(start, end, 2):
        if idaapi.get_byte(ea+1) in OP_PUSH:
            ea_list += [ea]

        elif idaapi.get_word(ea) in OP_PUSH16:
            ea_list += [ea]

    return ea_list

def check_epilogue(start, end):
    OP_BXLR = 0x4770
    OP_POP_PC = 0xBD
    OP_POP_PC16 = 0xE8BD

    for ea in range(start, end, 2):
        if idaapi.get_word(ea) == OP_BXLR:
            return True

        elif idaapi.get_word(ea) == OP_POP_PC16:
            return True

        elif idaapi.get_byte(ea+1) == OP_POP_PC:
            return True

    return False

def find_functions_lazy():
    prologues = find_push()

    for ea in prologues:
        try_add_function(ea)

def find_functions_neighbors():
    for func in idautils.Functions():
       start = idc.find_func_end(func) 
       end = idc.get_next_func(func)

       if end == idc.BADADDR:
            end = get_end(start)

       new_func_start = idaapi.next_unknown(start, end)
       
       if new_func_start != idc.BADADDR and check_epilogue(new_func_start, end):
           try_add_function(new_func_start)

def find_functions():
    find_functions_lazy()
    find_functions_neighbors()

    print("Running autoanalysis")
    idaapi.auto_wait()
