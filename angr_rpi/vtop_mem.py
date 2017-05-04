import struct,IPython

mem = open('mem','r')
# system_map = open("./System.map-4.9.11-v7+",'r')

"""
get pgdir
for line in open('pgdirs.txt'):
	p = int(line,16)
	pa = p - 0x80000000
	mem.seek(pa)
	print hex(pa), len(set(mem.read(4964*4)))

0x39210000
0x38d7c000
...
"""

"""
VAs for test:
0x800081ac Section
0x80121c60 Super section 0x00121c60
"""

def va_to_pa(va):
	mem.seek(0x39210000)
	pgdir = struct.unpack("<4096I", mem.read(4096*4))
	# assert(pgdir[0xfff] == 0x3a7fac61)

	# parse va
	# va = 0xffff0000
	mask_descriptor_bits = 0b11
	mask_18 = 0x20000

	index_1 = (va & ~0x000fffff) >> (4*5)
	index_2 = (va & 0x000ff000) >> (4*3)
	pte_1 = pgdir[index_1]
	# print "index_1" , hex(index_1)
	# pte_1 = pgdir[index_1 << 4*2]
	# print "pte_1",hex(pte_1)
	descriptor_bits = pte_1 & mask_descriptor_bits

	pa = 0
	if (descriptor_bits == 0):
		#print hex(va), "00: Invalid VA!", "pa: ", hex(pa)
		return -1
	elif(descriptor_bits == 1): 
		# page table
		pte_1 = pgdir[index_1] & 0xfffffc00
		# print hex(pte_1)

		mem.seek(0,0)
		mem.seek(pte_1)
		page_table_2 = struct.unpack("<256I", mem.read(256*4))

		pte_2 = page_table_2[index_2]

		descriptor_bits_2 = pte_2 & mask_descriptor_bits
		#print bin(descriptor_bits_2)
		if (descriptor_bits_2 == 0):
			#print "Invalid pte_2"
			return -1
		elif (descriptor_bits_2 == 1):
			pa = pte_2 & (0xffff0000)
			#print "Large page"
		else:
			pa = pte_2 & (0xfffff000)
			#print "Small page"

		# pa = pte_2 & (0xfffff000)
		# print "[+]", hex(va), "01: PAGE TABLE."
		#IPython.embed()
		return pa

	else:
		bit_18 = va & mask_18
		if(bit_18):
			#print "[+]", hex(va), "Super section"
			section_base = pte_1 & (0xff000000)
			#print "section_base",section_base
			pa = (section_base ) | (va & 0x00ffffff)

			return pa
		else:
			#print "[+]", hex(va), "Section"
			section_base = pte_1 & (0xfff00000)
			#print "section_base",section_base
			pa = (section_base ) | (va & 0x000fffff)

			return pa

if __name__ == '__main__':
	# lines = system_map.readlines()

	# va = 0xffff0000
	# va = 0xbb800000
	# pa = va_to_pa(va)
	# print "PA:", hex(pa)

	outfile = open('mem_hack','w')
	# # log = open('log','w')
	for addr in xrange(0x80000000, 0x100000000, 0x1000):
		pa = va_to_pa(addr)

		if (pa == -1 or pa > 0x3affffe0): # not available
			outfile.write('\0' * 0x1000)
			#continue
		else:
			mem.seek(pa)
			data = mem.read(0x1000)
			if (len(data) != 0x1000):
				print hex(addr),hex(pa)
				IPython.embed()
				break
			outfile.write(data)




