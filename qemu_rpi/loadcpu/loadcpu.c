/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
//TODO: SET SCTLR,TTBR,MMU,LOAD RAM FROM MEM_DUMP 

#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#define RAM_SIZE 0x3b000000

bool init_plugin(void *);
void uninit_plugin(void *);
bool cpu_init_done = false;
int before_block_exec(CPUState *env, TranslationBlock *tb);

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (!cpu_init_done){
        CPUArchState *envp = (CPUArchState *)env->env_ptr;
    envp->regs[0] = 0x00000003;
    envp->regs[1] = 0x54b113b0;
    envp->regs[2] = 0x00000000;
    envp->regs[3] = 0x00000002;
    envp->regs[4] = 0x8edbfb00;
    envp->regs[5] = 0x54b23000;
    envp->regs[6] = 0x7ece2838;
    envp->regs[7] = 0x0000017b;
    envp->regs[8] = 0x54b113b0;
    envp->regs[9] = 0x00000002;
    envp->regs[10] =0x54b0d20c;
    envp->regs[11] =0x00000000;
    envp->regs[12] =0x7ece2670;
    //envp->regs[13] =0x7ece2660;
    envp->regs[13] =0xae573dac;
    envp->regs[14] =0x54b060ac;
    envp->regs[15] =0x76ef9c40;
    envp->daif = 0x340;
    envp->cp15.dacr_ns = 0x17 | (3 << (3*2));
    for(int i=0; i<4; i++){
        envp->cp15.ttbr0_el[i] = 0x3921006a;
        envp->cp15.ttbr1_el[i] = 0x0000406a;
        envp->cp15.sctlr_el[i] = 0x2001;
    }
    // TTBR[0] = 2e07c06a TTBR[1] = 0000406a TTBR_Control = 00000000
    // SCTLR = '0b10000000000001' = 0x2001
    
    //LOAD MEM
    FILE *fp_mem;
	char buf[0x1000];
    fp_mem = fopen("/mnt/hgfs/shared_folder/mem","r");
	for (hwaddr a = 0; a < RAM_SIZE; a += 0x1000) {
	fread(buf,1,0x1000,fp_mem);
    panda_physical_memory_rw(a, (uint8_t *)buf, 0x1000, 1);
	}

    cpu_interrupt(env,CPU_INTERRUPT_HARD);

    cpu_init_done= true;
    }
    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) { }
