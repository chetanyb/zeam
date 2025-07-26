.section .text._start
.globl _start

_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, STACK_TOP
    lw sp, 0(sp)
    call main
