.intel_syntax noprefix
.section .text
.global sovr_fastpath_call
.type sovr_fastpath_call, @function

sovr_fastpath_call:
    mov     rax, rdi
    mov     rbx, rsi
    mov     rsi, rdx
    mov     rdx, rcx
    mov     r10, r8
    mov     r8,  r9
    syscall
    ret
.size sovr_fastpath_call, .-sovr_fastpath_call
