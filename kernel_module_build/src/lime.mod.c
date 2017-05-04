#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xc2e59015, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x7dd2b510, __VMLINUX_SYMBOL_STR(sock_setsockopt) },
	{ 0xbb49129e, __VMLINUX_SYMBOL_STR(kernel_sendmsg) },
	{ 0xf5c96ab5, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0x2e5810c6, __VMLINUX_SYMBOL_STR(__aeabi_unwind_cpp_pr1) },
	{ 0xb55c37b2, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0xb1ad28e0, __VMLINUX_SYMBOL_STR(__gnu_mcount_nc) },
	{ 0x71951430, __VMLINUX_SYMBOL_STR(sock_create_kern) },
	{ 0x4779e706, __VMLINUX_SYMBOL_STR(param_ops_charp) },
	{ 0xfa2a45e, __VMLINUX_SYMBOL_STR(__memzero) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x751c7fa, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0x8c47565d, __VMLINUX_SYMBOL_STR(param_ops_long) },
	{ 0xa88121ec, __VMLINUX_SYMBOL_STR(vfs_write) },
	{ 0xd050380f, __VMLINUX_SYMBOL_STR(filp_open) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "3CC7667090B48062A5C20D8");
