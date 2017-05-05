# Automatic interrupt analyzing
## Objectives
The goal of our project is to build a tool that can automatically analyze Peripheral Interupts for ARM embedded system. 

## Testcases
### Econotag
The Econotag is an open source and exceptionally simple example of an embedded system which makes it easier for us to testing our approach.

---

#### Approaches:
**Symbolic Execution**([angr](http://angr.io/))

We start our project based on [Isomano](https://github.com/fmaymi/Isomano) project, which used angr to implement a guided symbolic execution on econotag firmware. In this project, we optimized the program and made it automatic.            
                    
To make angr works on the econotag firmware we dumped, we did several hooks for those instructions that angr doesn’t support. Besides that,  angr cannot to add constraints when it meets [some arm branch case](https://github.com/angr/angr/issues/365), to make our test case work, we also modified and patched the binary (econotag\_angr\_solve/econotag\_new).

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

After making success on the econotag system, we moved forward to a more complicated embedded device: raspberry pi 3. Unlike the previous test case, we are trying to test on an actual device ([Raspberry Pi 3, Model B, 1GB RAM](https://en.wikipedia.org/wiki/Raspberry_Pi)). 

---

#### Initial Setup
##### kernel build
We first [cross compile](https://www.raspberrypi.org/documentation/linux/kernel/building.md) and build kernel for raspberry pi 3:

`pi@raspberrypi:~ $ uname -ar`

`Linux raspberrypi 4.9.11-v7+ #1 SMP Tue Feb 21 16:51:15 EST 2017 armv7l GNU/Linux`

---

##### Memory Dump
The next step was trying to dump the memory out of raspberry pi, we tried to use LiME to extract the memory, but it didn’t work out. Then we turned to another way: since we know we can
recompile the kernel, we can just re-enable access to **/dev/mem**. The way to do this is before building the kernel, do make menuconfig and
set the **CONFIG\_STRICT\_DEVMEM** option to **"no"**. Then we were able to just use dd on **/dev/mem** to create the [memory dump](http://107.170.178.208/mem_dump/mem). 



---

#### Approaches
##### 1. Symbolic Execution


_**Address translation**_

The memory dump we had was all based on physical address. To make angr work on the mem dump we just had, we need to figure out a way to let angr understand [virtual address translation](https://armv8-ref.codingbelief.com/en/chapter_d4/d42_1_about_the_vmsav8-64_address_translation_syste.html), and we did that using python (vtop_mem.py). After running our script on the original memory dump, now we have an [address-translated version of memory dump](http://107.170.178.208/mem_dump/mem_hack).

---


_**Angr It!**_

Like I mentioned before, angr met a lot of incompatible bugs while trying to map the econotag interrupt handler, while econotag was an exceptionally simple example of an embedded system. In the raspberry pi case, it wasn’t easy to get angr work as well. We did cpsr_hook to handle incompatible instructions in angr, e.g. msr, mrs, etc. We did find a correct path when we were trying to symbolic execute from address **0xffff0018**, which is the virtual address of **vector\_irq**.



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

After poking around with angr for a couple of weeks, we found the raspberry memory may be too complicate for angr to solve, and there are too many bugs(e.g. Incompatible instructions, symbolic read issues, etc.) we need to fix to make angr work. We decided to try the fuzzing way using [qemu/panda](https://github.com/panda-re/panda)。

- Load memory and CPU state in a blank machine definition. 
- Trigger interrupt using `cpu_interrupt(cpu, CPU_INTERRUPT_HARD)`. 
- Return random values from memory mapped I/O devices. 
- Trace what code gets executed as a result.
- Repeat until no new code traced.

Because of the **time** is limited (_**graduation**_), I have to stop at **step 2**. 

---



_**Load memory and CPU state**_

Because we want qemu load our memory file, we decided to use a customized machine definition: [Rehosting machine](https://github.com/H4oK3/auto-emulation2-runner/blob/master/hw/arm/rehosting.c).

Dumping the CPU state was a tricky part:
To dump the CPU state(basically the value that each register holds), we build our own kernel module to do that. Check **kernel\_module\_build/** for details.

You can just grab the kernel build module tool kit [here](http://panda.moyix.net/~moyix/rpi_lkm_build.tgz), and replace the `rpi/LiME/src` folder with `kernel_module_build` folder in the repo.

`export PATH=${PATH}:$(PWD)/rpi/tools/arm-bcm2708/gcc-linaro-arm-linux-  gnueabihf-raspbian-x64/bin`

`cd path_to_rpi/rpi/LiME/src`

`./mcmd.sh    # will compile main.c and create an kernel module`

Then on raspberry pi:
`sudo dmesg -C    # clear kernel message`

`sudo insmod lime.ko`

`dmesg        # now we have the cpu state`

**NOTE:** using `show_regs` wasn't the best way of dumping the cpu state, because we may be missing lots of values of cpu states such as ttbr, banked registers values, etc. In our test case, the sp register value wasn't quite right because `show_regs` didn't load **irq\_svc** mode stack address; and we did a hacky way to [work around](https://github.com/H4oK3/interrupt_analysis/blob/master/kernel_module_build/main.c#L83) that.

---


_**Trigger interrupt using and trace the execution**_

After acquiring the cpu state, then we [load](https://github.com/H4oK3/interrupt_analysis/blob/master/qemu_rpi/loadcpu/loadcpu.c) them in, and [trace](https://github.com/H4oK3/interrupt_analysis/blob/master/qemu_rpi/bbtrace/bbtrace.c) the block execution.

`arm-softmmu/qemu-system-arm -machine rehosting,mem-map="MEM 0x00000000-0x3b000000" -panda loadcpu -d in_asm -D qemu.log`    # will save trace to [qemu.log](https://github.com/H4oK3/interrupt_analysis/blob/master/qemu_rpi/qemu.log).


---

## Future Work



### Figure out a better way to dump the cpu state.
In our project, we used `show_regs` to dump the current cpu_state, which may miss lots of useful registers, hence one of our future work is to figure out a better way of dumping cpu state, one possible approach is to take a snap shot using qemu/raspberry pi machine definition.
### Continue working on the fuzzing approach.
Because the limited time, we didn't get to move forward to next step on our fuzzing approach, since we have already successfully loaded the cpu state and make qemu run on the correct path, we should move forward on our fuzzing approach in the future.

### Fix angr bugs, _make symbolic execution great again_.
Symbolic execution is **1337** (when it works), while angr is still on developing stage, in the future we probably can help fixing some angr issues and make it work on our arm architecture.





