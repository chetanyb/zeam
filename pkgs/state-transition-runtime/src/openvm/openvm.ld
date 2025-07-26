ENTRY(_start)

MEMORY
{
    RAM : ORIGIN = 0x00000000, LENGTH = 0x10000000
}

SECTIONS
{
    PROVIDE(STACK_TOP = 0x00200400);
    . = 0x00200800;
    
    .text : ALIGN(4)
    {
        *(.text .text.*)
        *(.rodata .rodata.*)
    } > RAM

    .data : ALIGN(4)
    {
        *(.data .data.*)
    }
    
    .bss : ALIGN(4)
    {
        *(.bss .bss.*)
    }

    PROVIDE(_heap_start = . );
}
