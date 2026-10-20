.section .boot, "ax"
.global _start
.extern strawman_ingress_entry

.align 12
_start:
    msr     daifset, #0xf
    isb

    adrp    x0, _early_kernel_stack_top
    add     sp, x0, :lo12:_early_kernel_stack_top

    bl      setup_dataport_security_attributes

    /* Zero general purpose registers */
    mov     x0,  xzr
    mov     x1,  xzr
    mov     x2,  xzr
    mov     x3,  xzr
    mov     x4,  xzr
    mov     x5,  xzr
    mov     x6,  xzr
    mov     x7,  xzr
    mov     x8,  xzr
    mov     x9,  xzr
    mov     x10, xzr
    mov     x11, xzr
    mov     x12, xzr
    mov     x13, xzr
    mov     x14, xzr
    mov     x15, xzr

    bl      strawman_ingress_entry

.halt_loop:
    wfi
    b       .halt_loop

setup_dataport_security_attributes:
    adrp    x0, _dataport_pte
    add     x0, x0, :lo12:_dataport_pte
    ldr     x1, [x0]
    orr     x1, x1, #(1 << 7)   /* AP[2] = 1 (Read-only) */
    str     x1, [x0]
    ret

.section .data
.align 12
.global _dataport_pte
_dataport_pte:
    .quad _sovr_shared_dataport + 0x401  /* Valid, Inner-shareable */

.section .bss
.align 12
.global _sovr_shared_dataport
_sovr_shared_dataport:
    .skip 4096

.align 4
_early_kernel_stack_bottom:
    .skip 16384
_early_kernel_stack_top:
