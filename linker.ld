ENTRY(_start)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x40000000, LENGTH = 64K
    SRAM (rwx)  : ORIGIN = 0x40010000, LENGTH = 64K
    RING (rw)   : ORIGIN = 0x40020000, LENGTH = 64K
}

SECTIONS
{
    .text : {
        *(.text._start)
        *(.text*)
        *(.rodata*)
    } > FLASH

    .data : {
        *(.data*)
    } > SRAM AT > FLASH

    .bss (NOLOAD) : {
        . = ALIGN(8);
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    } > SRAM

    .ring_frame (NOLOAD) : {
        . = ALIGN(4096);
        *(.ring_frame)
    } > RING

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
