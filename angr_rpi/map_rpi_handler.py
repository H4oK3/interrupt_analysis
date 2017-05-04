#!/usr/bin/env python
import sys
import angr
import claripy
from simuvex import o
import simuvex
import capstone
import IPython
import pyvex
import struct
import logging
from termcolor import colored

"""
irq_usr
dereference handle_arch_irq
dereference again
bcm2836_arm_irqchip_handle_irq : 80101464
handle_domain_irq
__handle_domain_irq : 8016f340
generic_handle_irq : 8016ed34
generic_handle_irq_desc <- this one calls the specific IRQ handler

Qs:
Can you show me how did you trace all the func calls again?
Why don't we just use pg.found()?
generic_handle_irq : 8016ed34
radix_tree_lookup : 0x8044bfa8	　
__radix_tree_lookup : 0x8044bed0
...
handle_percpu_devid_irq : 0x80173fb4
"""



cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
cst = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)


CPSR_IRQ_DISABLE = 0x80
CPSR_FIQ_DISABLE = 0x40

# source: Brendan Dolan-Gavitt, econotag.py
# setup symbolic variable for IRQ anf FIQ flags
cpsr = claripy.BVV(CPSR_IRQ_DISABLE|CPSR_FIQ_DISABLE,32)
msr_mrs = [0xffff1028,0xffff1030,0xffff1038,0xffff10a8,0xffff10b0,0xffff10b8,0xffff1128,0xffff1130,
0xffff1138,0xffff11a4,0xffff11ac,0xffff11b4,0x80701588,0x802030c8,0x807015a8,0x807015b0,0x8010dba8,
0x8016f354,0x8017bedc,0x80107e7c,0x80173fc8,0x80173ff0]
stop_flag = False




def cpsr_hook(s):
	global cpsr
	pc = s.se.any_int(s.ip)
	if pc & 1:
		# Thumb mode
		ilen = 2
		dis = cst
		pc = pc & ~1
	else:
		ilen = 4
		dis = cs
	data = s.se.any_str(s.memory.load(pc ,ilen))
	insns = list(dis.disasm(data, pc))
	# IPython.embed()
	# print "[DBG]", "Disassembling",len(data),"bytes at",hex(pc),"found",len(insns),"instructions"
	# print "[DBG]", "Bytes:", data.encode('hex')
	if not insns: return
	i = insns[0]
	# print "[DBG]", i.mnemonic
	if i.mnemonic == 'msr':
		cpsr = getattr(s.regs, i.op_str.split()[1])
	elif i.mnemonic == 'mrs':
		setattr(s.regs, i.op_str.split()[0][:-1], cpsr)
	elif i.mnemonic == 'mrc':
		# IPython.embed()
		# 0x2030c8
		if("c13, c0, #4" in i.op_str):
			# Write Thread ID Privileged Read Write only Register
			# here is where the problem at: if we set this to 0, it will
			# jmp to some nonsense addr
			print colored("[DBG] Handled "+ str(i.mnemonic) + " " + hex(pc) + " " + i.op_str, 'red')
			setattr(s.regs, i.op_str.split()[2][:-1], 0)
			# IPython.embed()
		elif("c1, c0, #0" in i.op_str):
			# Read Control Register
			# 0x80701588 usr_irq
			print colored("[DBG] Handled "+ str(i.mnemonic) + " " + hex(pc) + " " + i.op_str, 'red')
			setattr(s.regs, i.op_str.split()[2][:-1], 0)
			# IPython.embed()
		else:
			print colored("[DBG] Unhandled mrc " + i.op_str,'red')
			# IPython.embed()
		# setattr(s.regs, i.op_str.split()[2][:-1], 0)
	else:
		# IPython.embed()
		print colored("[DBG] Unhandled inst: " + hex(pc) + " " + str(i.mnemonic), 'red')
		# IPython.embed()
		# exit(0)

def until_func(lpg):

	if len(lpg.active) >= 5:
		print "True 1"
		IPython.embed()
		return True
	else:
		print colored("[DBG] Keep stepping.." + str(lpg.active), 'yellow')
		# IPython.embed()
		return False


def step_func(lpg):
	global msr_mrs
	# for actp in lpg.active:
	# 	if actp.addr == 0x8016f340:
	# 		print colored("[DBG] FOUND __handle_domain_irq !", "red")
	# 		IPython.embed()
	if lpg.errored:
		for errp in lpg.errored:
			hook_addr = errp.addr
			print colored( "[DBG]" + str(errp.error),'red')

			msr_mrs.append(hook_addr)
			msr_mrs = list(set(msr_mrs))

			path = p.factory.path(state)
			pg = p.factory.path_group(path)
			print colored("[+]Hooking " + str(hex(hook_addr)),'red')
			# IPython.embed()
			exit(1)
			p.hook(hook_addr, cpsr_hook, length=(2 if hook_addr & 1 else 4))
			# for addr in msr_mrs:
			# 	p.hook(addr, cpsr_hook, length=4)
	
		
		return pg
	else:
		return lpg



def get_handler_mapping(p,state):
	# setup path and pathgroup

	path = p.factory.path(state)
	pg = p.factory.path_group(path)
	
	
	# pg.explore(find=0x8016ed5c)
	pg.explore(find=0x8016ed48) # try to resolve r1
	# pg.explore(find=0x8046e810)

	path_g = pg.found[0]
	pg_pruned = p.factory.path_group(path_g)
	IPython.embed()


	r1_values = []
	jmp_addrs = []
	p_state = path_g.state
	r1 = p_state.regs.r1

	while (satisfiable(p_state,r1)):
		r1_value = p_state.se.any_int(r1)
		r1_values.append(r1_value)
		p_state.se.add(r1 != r1_value)
	

	

	# Try to solve r3

	# r3_values = []
	# jmp_addrs = []
	# p_state = path_g.state
	# r3 = p_state.regs.r3

	# while (satisfiable(p_state,r3)):
	# 	r3_value = p_state.se.any_int(r3)
	# 	r3_values.append(r3_value)
	# 	p_state.se.add(r3 != r3_value)
	

	# for r in r3_values:
	# 	jmp_addr = state.se.any_int(state.memory.load(r + 0x30,endness='Iend_LE'))
	# 	jmp_addrs.append(jmp_addr)
	# 	print hex(jmp_addr)
	# jmp_addrs = list(set(jmp_addrs))
	
	# 0x8046e810:bcm2836_chained_handle_irq ; 0x80173fb4:handle_percpu_devid_irq
	# Try to solve r3
		
	IPython.embed()




	pg_pruned.step(until=until_func, step_func = step_func)
	IPython.embed()

	# step to the next basic block (which in this case we expect to be the
	# interrupt handlers)
	successors = pg_pruned.active

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
	load_options = {'main_opts': {'backend': 'blob', 'custom_arch': 'arm','custom_base_addr':0x80000000,'custom_entry_point':0xFFFF0018}}
	if (len(sys.argv) < 2):
		print "[+]Usage: python map_rpi_handler.py mem_dump;"
		exit(1)
	else:
		project_name = sys.argv[1]

	p = angr.Project(project_name,load_options=load_options)

	state = p.factory.blank_state(
		#add_options={o.BYPASS_UNSUPPORTED_IRCCALL,simuvex.options.SIMPLIFY_CONSTRAINTS,
		#simuvex.options.SYMBOLIC_WRITE_ADDRESSES,simuvex.options.SYMBOLIC,simuvex.options.CONSERVATIVE_READ_STRATEGY},
		add_options={o.BYPASS_UNSUPPORTED_IRCCALL},
		remove_options={o.LAZY_SOLVES},
		addr=0xFFFF0018
		)
	for addr in msr_mrs:
		p.hook(addr, cpsr_hook, length=4)
	return p,state



# main routine


p,state = setup()
def main():
	# get project and state

	# get mapping of interupt numbers and handlers
	mapping = get_handler_mapping(p,state)
	# print results
	print("Found the following interupt number and handler mappings:\n")
	for key in mapping:
		print("%s: %s" % (key,", ".join([str(x) for x in mapping[key]])))

if __name__ == '__main__':
	main()
