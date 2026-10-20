.intel_syntax noprefix
.section .boot, "ax"
.global _start
.extern strawman_ingress_entry

.set PAGE_PRESENT,      (1 << 0)
.set PAGE_WRITE,        (1 << 1)
.set PAGE_USER,         (1 << 2)

.align 4096
_start:
    cli
    cld

    lea     rsp, [rip + _early_kernel_stack_top]
    call    setup_dataport_security_attributes

    /* Scrub general-purpose registers */
    xor     rax, rax
    xor     rbx, rbx
    xor     rcx, rcx
    xor     rdx, rdx
    xor     rsi, rsi
    xor     rdi, rdi
    xor     r8,  r8
    xor     r9,  r9
    xor     r10, r10
    xor     r11, r11
    xor     r12, r12
    xor     r13, r13
    xor     r14, r14
    xor     r15, r15

    call    strawman_ingress_entry

.halt_loop:
    hlt
    jmp     .halt_loop

setup_dataport_security_attributes:
    lea     rdi, [rip + _dataport_pte]
    mov     rax, [rdi]
    and     rax, ~(PAGE_WRITE)
    or      rax, (PAGE_PRESENT | PAGE_USER)
    mov     [rdi], rax
    ret

.section .data
.align 4096
.global _dataport_pte
_dataport_pte:
    .quad _sovr_shared_dataport + (PAGE_PRESENT | PAGE_USER)

.section .bss
.align 4096
.global _sovr_shared_dataport
_sovr_shared_dataport:
    .skip 4096

.align 16
_early_kernel_stack_bottom:
    .skip 16384
_early_kernel_stack_top:
