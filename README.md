# Automatic interrupt analyzing
## Objectives
The goal of our project is to build a tool that can automatically analyse Peripheral Interupts for ARM embeded system. 

## Testcases
### Econotag
The Econotag is an open source and exceptionally simple example of an embedded system which makes it easier for us to testing our approach.

---

#### Approaches:
**Symbolic Execution**([angr](http://angr.io/))

We start our project based on [Isomano](https://github.com/fmaymi/Isomano) project, which used angr to implement a guided symbolic execution on econotag firmware. In this project, we optimized the program and make it automatic.			
					
In order to make angr works on the econotag firmware we dumped, we did several hooks for those instructions that angr doesn’t support. Besides that,  angr cannot to add constraints when it meets [some arm branch case](https://github.com/angr/angr/issues/365), in order to make our test case work, we also modified and patched the binary (econotag\_angr\_solve/econotag\_new).

---

#### Proof of concept:
`Input: python auto_map_handler.py econotag_new econotag_memdump.bin`

`Output: Found the following interupt number and handler mappings:
0x3f35: 3
0x1001d: 6, 0, 9, 10, 2, 4, 5, 8
0x4029d1: 7
0x3275: 1
`

---

### Raspberry pi 3

After making success on econotag system, we moved forward to a more complicated embedded device: raspberry pi 3. Unlike the previous test case, we are trying to test on a actual device ([Raspberry pi 3, Model B, 1GB RAM](https://en.wikipedia.org/wiki/Raspberry_Pi)). 

---

#### Initial Setup
##### kernel build
We first [cross compile](https://www.raspberrypi.org/documentation/linux/kernel/building.md) and build kernel for raspberry pi 3:

`pi@raspberrypi:~ $ uname -ar`

`Linux raspberrypi 4.9.11-v7+ #1 SMP Tue Feb 21 16:51:15 EST 2017 armv7l GNU/Linux`

---

##### Memory Dump
The next step was trying to dump the memory out of raspberry pi, we tried to use LiME to extract the memory but it didn’t work out. Then we turned to another way: since we know we can
recompile the kernel, we can just re-enable access to **/dev/mem**. The way to do this is before building the kernel, do make menuconfig and
set the **CONFIG\_STRICT\_DEVMEM** option to **"no"**. Then we were able to just use dd on **/dev/mem** to create a memory dump. 

---

#### Approaches
##### 1. Symbolic Execution


_**Address translation**_

The memory dump we had was all based on physical address. In order to make angr work on the mem dump we just had, we need to figure out a way to let angr understand [virtual address translation](https://armv8-ref.codingbelief.com/en/chapter_d4/d42_1_about_the_vmsav8-64_address_translation_syste.html), and we did that using python (vtop_mem.py). After running our script on the original memory dump, now we have an address-translated version of memory dump.

---


_**Angr It!**_

Like I mentioned before, angr met a lot incompatible bugs while trying to map the econotag interrupt handler, while econotag was an exceptionally simple example of an embedded system. In the raspberry pi case, it wasn’t easy to get angr work as well. We did cpsr_hook to handle incompatible instructions in angr, e.g. msr, mrs, etc. We did find a correct path when we were trying to symbolic execute from address **0xffff0018**, which is the virtual address of **vector\_irq**.



```
The path:

dereference handle_arch_irq  	 
bcm2836_arm_irqchip_handle_irq : 80101464. 
handle_domain_irq. 
__handle_domain_irq : 8016f340. 
generic_handle_irq : 8016ed34.  
radix_tree_lookup : 0x8044bfa8.  
__radix_tree_lookup : 0x8044bed0.   
etc.
```

---

##### 2. Fuzzing

After poking around with angr for a couple of weeks, we found the raspberry memory may be too complicate for angr to solve, and there are too many bugs(e.g. Incompatible instructions, symbolic read issues, etc.) we need to fix in order to make angr work. We decided to try the fuzzing way using [qemu/panda](https://github.com/panda-re/panda)。

- Load memory and CPU state in a blank machine definition. 
- Trigger interrupt using `cpu_interrupt(cpu, CPU_INTERRUPT_HARD)`. 
- Return random values from memory mapped I/O devices. 
- Trace what code gets executed as a result.
- Repeat until no new code traced.

Because the **time** is limited (_**graduation**_), I have to stop at **step 2**. 

---



_**Load memory and CPU state**_

Because we want qemu load our own memory file, we decided to use a customized machine definition: [Rehosting machine](https://github.com/H4oK3/auto-emulation2-runner/blob/master/hw/arm/rehosting.c).

Dumping the CPU state was a tricky part:
In order to dump the CPU state(basically the value that each register holds), we build our own kernel module to do that. Check kernel\_module\_build/rpi for details.

`export PATH=${PATH}:$(PWD)/rpi/tools/arm-bcm2708/gcc-linaro-arm-linux-  gnueabihf-raspbian-x64/bin`

`cd path_to_rpi/rpi/LiME/src`

`./mcmd.sh	# will compile main.c and create an kernel module`

Then on raspberry pi:
`sudo dmesg -C	# clear kernel message`

`sudo insmod lime.ko`

`dmesg		# now we have the cpu state`

**NOTE:** using `show_regs` wasn't the best way of dumping the cpu state, because we may be missing lots of values of cpu states such as: ttbr, banked registers values, etc. In our test case, the sp register value wasn't quite right because `show_regs` didn't load **irq\_svc** mode stack address; and we did a hacky way to [work around] (need a link here!) that.

---


_**Trigger interrupt using and trace the execution**_

After acquiring the cpu state, then we [load](link to loadcpu.c) them in, and [trace ](link to bbtrace.c) the block execution.

---

## Future Work



- Figure out a better way to dump the cpu state.
- Continue working on the fuzzing approach.
- Fix angr bugs, **make symbolic execution great again**.





