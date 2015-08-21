.arm

.global _start

_start:
mov r5, lr
ldr r0, =0x1ffffff8
ldr r1, =0x54524241 @ "ABRT"
ldr r2, =0x544f4f42 @ "BOOT"

waitlp:
ldr r3, [r0]
cmp r3, r1
beq abort
cmp r3, r2
bne waitlp

ldr r4, [r0, #4]
mov r0, #1
bl writeaxiwram
blx r4

abort:
mov r0, #2
bl writeaxiwram
bx r5
.pool

writeaxiwram:
mov r2, r0
ldr r0, =0x1ffffff8
mov r3, #0
stm r0, {r2, r3}
bx lr
.pool

