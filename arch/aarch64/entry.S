/* arch/aarch64/entry.S - Zero-CRT Freestanding Bootstrap */
.section .text._start, "ax", @progbits
.global _start
.type _start, @function

_start:
    /* 1. Mask Debug, SError, IRQ, and FIQ (DAIF = 0b1111) */
    msr daifset, #0xf

    /* 2. Enforce strict alignment and initialize stack pointer */
    ldr x0, =0x000000004001FFF0
    mov sp, x0

    /* 3. In-register BSS zeroing using 64-bit word stores */
    ldr x1, =__bss_start
    ldr x2, =__bss_end

.L_ZERO_BSS_LOOP:
    cmp x1, x2
    b.ge .L_SETUP_RUNTIME_REGS
    str xzr, [x1], #8
    b .L_ZERO_BSS_LOOP

.L_SETUP_RUNTIME_REGS:
    /* 4. Seed system context structures placed in FAST_DATA */
    /* x0: SlideVector64 pointer           */
    /* x1: SovereignKernelContext pointer   */
    /* x2: tick_stride (2400 cycles)       */
    /* x3: runtime_cycles (0xFFFFFFFFFFFFFFFF) */
    ldr x0, =0x0000000040010000
    ldr x1, =0x0000000040010040
    movz x2, #0x0960
    mov x3, #0xFFFFFFFFFFFFFFFF

    /* Branch directly to the pinned C execution engine */
    bl execute_sovereign_runtime

.L_CORE_HALT:
    /* Fail-safe trap: park core on unrecoverable loop exit */
    wfe
    b .L_CORE_HALT

.size _start, . - _start
