; @file    bignum_normalize.asm
; @brief   Нормализация bignum_t и очистка хвоста на x86-64 YASM.
; @details System V ABI: rdi = x.
; -----------------------------------------------------------------------------
; SPDX-License-Identifier: MIT
; -----------------------------------------------------------------------------

default rel
section .text
    align 16
    global bignum_normalize

BIGNUM_CAPACITY                 equ 32
BIGNUM_WORD_SIZE                equ 8
BIGNUM_OFFSET_LEN               equ BIGNUM_CAPACITY * BIGNUM_WORD_SIZE
BIGNUM_NORMALIZE_SUCCESS        equ 0
BIGNUM_NORMALIZE_ERROR_NULL_ARG equ -1

; bignum_normalize_status_t bignum_normalize(bignum_t *x)
bignum_normalize:
    mov     eax, BIGNUM_NORMALIZE_ERROR_NULL_ARG
    test    rdi, rdi
    jz      .ret

    mov     rcx, [rdi + BIGNUM_OFFSET_LEN]
    mov     r8, BIGNUM_CAPACITY
    cmp     rcx, r8
    cmova   rcx, r8
    test    rcx, rcx
    jz      .update_len
.scan_loop:
    cmp     qword [rdi + rcx * BIGNUM_WORD_SIZE - BIGNUM_WORD_SIZE], 0
    jne     .update_len
    dec     rcx
    jnz     .scan_loop


.update_len:
    mov     [rdi + BIGNUM_OFFSET_LEN], rcx
    mov     r8, BIGNUM_CAPACITY
    sub     r8, rcx
    jz      .success

    lea     rdi, [rdi + rcx * BIGNUM_WORD_SIZE]
    mov     rcx, r8
    xor     eax, eax
    cld
    rep     stosq

.success:
    mov     eax, BIGNUM_NORMALIZE_SUCCESS
.ret:
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
