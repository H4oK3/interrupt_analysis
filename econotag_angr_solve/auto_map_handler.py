#!/usr/bin/env python
# Author: Hao Ke, Brendan Dolan-Gavitt
import sys
import angr
import claripy
from simuvex import o
import simuvex
import capstone
import IPython
import pyvex
import struct


# setup capstone disasembler
cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
cst = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

# addresses of MSR and MRS instructions
msr_mrs = [
    0x10780, 0x10790, 0x10798, 0x107a8,
    0x107b4, 0x107c0, 0x107c8, 0x107d8,
    0x107e0, 0x107f0, 0x107f8, 0x10808,
    0x10870, 0x10878, 0x402eac, 0x402ebc,
    0x402ecc, 0x402edc, 0x402eec, 0x402efc,
]

# flags for disabling IRQ and FIQ
CPSR_IRQ_DISABLE = 0x80
CPSR_FIQ_DISABLE = 0x40

# setup symbolic variable for IRQ anf FIQ flags
cpsr = claripy.BVV(CPSR_IRQ_DISABLE|CPSR_FIQ_DISABLE,32)

# input: s (state)
# 
# setup procedure for hooking the MSR and MRS instructions
def cpsr_hook(s):
    global cpsr
    pc = s.se.any_int(s.ip)
    data = s.se.any_str(s.memory.load(pc,4))
    i = list(cs.disasm(data, pc))[0]
    if i.mnemonic == 'msr':
        cpsr = getattr(s.regs, i.op_str.split()[1])
    elif i.mnemonic == 'mrs':
        setattr(s.regs, i.op_str.split()[0][:-1], cpsr)

# input: s (state), mode (string, {'arm','thumb'}), nbef (int), naft (int)
# 
# a helper function for quick disassembling of instructions at a given path's
# current address; mode should be either 'arm' or 'thumb'
# 
# output: a list of strings; each string corresponds to instruction + operands
def disas(s,mode,nbef=0,naft=0):
    # initialize empty list for instruction strings
    insts = []
    # get conrete value for program counter
    pc = s.se.any_int(s.ip)
    # initialize the capstone disasembler and size of full instruction in bytes
    # to None
    cap = None
    size = None
    
    # set cap and size dependent on mode
    if mode == "arm":
        cap = cs
        size = 4
    elif mode == "thumb":
        cap = cst
        size = 2
        # reduce pc by 1 since thumb is weird and instructions are stored 1 
        # byte behind the jump target
        pc = pc - 1
    else:
        # raise error if mode is something other than 'arm' or 'thumb'
        raise ValueError("Bad mode!")
    
    # disasemble nbef instructions from before current address 
    for i in range(1,nbef+1):
        tmp_pc = pc - (size*i)
        data = s.se.any_str(s.memory.load(tmp_pc,size))
        i = list(cap.disasm(data,tmp_pc))[0]
        insts.append(str(hex(tmp_pc))+":  "+i.mnemonic + "  " + i.op_str)
    # reverse since we put everything in backwards effectively
    insts.reverse()
    
    # disassemble instruction at current address
    data = s.se.any_str(s.memory.load(pc,size))
    i = list(cap.disasm(data,pc))[0]
    insts.append(str(hex(pc))+":  "+i.mnemonic + "  " + i.op_str)
    
    # disasemble naft instructions from after current address 
    for i in range(1,naft+1):
        tmp_pc = pc + (size*i)
        data = s.se.any_str(s.memory.load(tmp_pc,size))
        i = list(cap.disasm(data,tmp_pc))[0]
        insts.append(str(hex(tmp_pc))+":  "+i.mnemonic + "  " + i.op_str)
    
    return insts

# input: s (state), mode (string, {'arm','thumb'}), nbef (int), naft (int)
# 
# a pretty-printer for the disasembler
def p_disas(s,mode,nbef=0,naft=0):
    insts = disas(s,mode,nbef,naft)
    i = 0
    for i in range(nbef):
        print(insts[i])
    if i == 0:
        i = -1
    # highlight the current instruction
    print(">>> "+insts[i+1])
    for j in range(i+2,len(insts)):
        print(insts[j])

# load the vector table of interrupt handler addresses into the given state
def load_vector_table(state):
    # vector table
    vector_table = [
        0x0001001d,0x00003275,0x0001001d,0x00003f35,
        0x0001001d,0x0001001d,0x0001001d,0x004029d1,
        0x0001001d,0x0001001d,0x0001001d
    ]
    # start address of vector table
    start_addr = 0x00400120
    # load each address into state's memory
    load_addr = start_addr
    for entry in vector_table:
        c_rep = claripy.BVV(entry,32)
        state.memory.store(load_addr,c_rep,endness='Iend_LE')
        load_addr += 0x4

def load_mem_dump(state, f, start_addr):
    data = f.read(4)
    while len(data) == 4:
        int_data = struct.unpack("<I", data)[0]
        c_rep = claripy.BVV(int_data,32)
        state.memory.store(start_addr,c_rep,endness='Iend_LE')
        start_addr += 4
        data = f.read(4)

def get_handler_mapping(p,state):
    # setup path and pathgroup

    path = p.factory.path(state)
    pg = p.factory.path_group(path)
 
    pg.step(until=lambda lpg: len(lpg.active) >= 3, step_func=lambda lpg: lpg.prune())
    # IPython.embed()

    # step to the next basic block (which in this case we expect to be the
    # interrupt handlers)
    successors = pg.active
    
    # record the mapping of interrupt numbers to handlers
    mapping = {}
    for child in successors:
        # keep resolving new interrupt numbers from r0 until r0 is no longer
        # satisfiable
        m = child.state.memory.load(0x80020028,endness='Iend_LE')
        while (satisfiable(child.state,m)):
            # get address of child path and resolve interrupt number
            handler_addr = hex(child.addr)
            inter_num = int(child.state.se.any_int(m))
            
            # add number to mapping
            if handler_addr not in mapping:
                mapping[handler_addr] = []
            mapping[handler_addr].append(inter_num)
            
            # add constraint on r0 so that it can't be resolved to what it was
            # most recently resolved to; we do this to ensure we get an 
            # exhaustive list of all possible resolutions for r0 for the
            # current child's state
            child.state.se.add(m != inter_num)

    return mapping

# input: angr state and the value to determine satisfiability of
#
# tries to resolve value using state's solver; returns false if unsatisfiable 
# error, and true otherwise; we do this instead of using the 
# state.se.satisfiable built-in function as it returns a weird claripy error in
# the true case
# 
# output: boolean indicating satisfiability of value
def satisfiable(state,value):
    try:
        state.se.any_int(value)
    except simuvex.SimUnsatError:
        return False
    return True

# initializes project and state for econotag.bin
# 
# output: project and state
def setup():
    # setup project
    load_options = {'main_opts': {'backend': 'blob', 'custom_arch': 'arm'}}
    if (len(sys.argv) < 2):
        print "[+]Usage: python auto_map_handler.py bin_name mem_dump;"
        exit(1)
    else:
        project_name = sys.argv[1]
    p = angr.Project(project_name,load_options=load_options)
    
    # set entry to the address of the function just before the function which
    # jumps to the interrupt handlers; this ensure that r0 and other values
    # initialized appropriately
    state = p.factory.blank_state(
        add_options={o.BYPASS_UNSUPPORTED_IRCCALL},
        remove_options={o.LAZY_SOLVES},
        addr=0x18
        )

    # load vector table into state memory
    #load_vector_table(state)
    load_mem_dump(state, open(sys.argv[2]), 0x400000)

    # setup hooks for all MSR and MRS instructions
    for addr in msr_mrs:
        p.hook(addr, cpsr_hook, length=4)

    return p,state

# main routine
def main():
    # get project and state
    p,state = setup()

    # get mapping of interupt numbers and handlers
    mapping = get_handler_mapping(p,state)
    # print results
    print("Found the following interupt number and handler mappings:\n")
    for key in mapping:
        print("%s: %s" % (key,", ".join([str(x) for x in mapping[key]])))

main()

"""
OUTPUT:
Found the following interupt number and handler mappings:

0x3f35: 3
0x1001d: 6, 0, 9, 10, 2, 4, 5, 8
0x4029d1: 7
0x3275: 1

"""
