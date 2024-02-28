CMP_EQ = 0
CMP_LT = 1
CMP_LE = 2
CMP_FALSE = 3
CMP_NEQ = 4
CMP_GE = 5
CMP_GT = 6
CMP_TRUE = 7

C_LINE_END = 0ffh
C_LENGTH_PREFIX = 0C0h
.data
LINE_END db 0ffh
LENGTH_PREFIX db 0C0h

TOKEN_VARIANT_MASK dd 0F00000h
TOKEN_LINE_MASK dd 00FFFC0h
TOKEN_INDEX_MASK dd 03Fh

VARIANT_LINE_MASK DQ 0FFC0h
VARIANT_INDEX_MASK DQ 0003Fh
VARIANT_VALUE_MASK DQ 07FFF0000h OR (07FFFFFFFh SHL 32)

VARIANT_PREFIX DQ 1 SHL 31

NUM1 DQ 1
NUM2 DQ 2
NUM0 DQ 0
NEG1 DQ -1
NUM64 DQ 64

.code 

EXTERN ASCII_VOWEL: QWORD
EXTERN ASCII_TOLOWER: QWORD
EXTERN PERMUTE0: QWORD

PUSHR MACRO
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
ENDM

POPR MACRO
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
ENDM

BUFFER STRUCT
    _start DWORD ?
    _end DWORD ?
    _data QWORD ?
BUFFER ends

STREAM STRUCT
    _address	QWORD ?
    _length DWORD	?
    _size	DWORD	?
    _width DWORD 1
STREAM ENDS

DICT STRUCT
    lineData QWORD ?
    variantData QWORD ?
DICT ENDS

LOAD_REGISTER MACRO buf, zReg, kReg
    mov ecx, 64
    mov eax, [buf.BUFFER._end]
    sub eax, [buf.BUFFER._start]

    cmp eax, ecx
    cmovb ecx, eax

    mov rdx, [buf.BUFFER._data]
    mov eax, [buf.BUFFER._start]
    lea rdx, [rdx + rax]
    add [buf.BUFFER._start], ecx

    mov rax, 1 ; (1 << cl) - 1, get mask
    shl rax, cl
    dec rax

    kmovq kReg, rax
    vmovdqu8 zReg{kReg}, zmmword ptr [rdx]
ENDM

WriteLine MACRO ZNAME, KNAME, ZLINE, ADDR_
    LOCAL WriteLine_END

    mov r11, -1

    vmovdqu8	ZLINE, zmmword ptr [ADDR_]
    mov rax, 0ffh
    vpbroadcastb	zmm0, rax
    vpcmpub		k1, ZLINE, zmm0, CMP_EQ

    kmovq rax, KNAME
    popcnt rcx, rax
    ror rax, cl

    kmovq rdx, k1
    dec rdx

    test rax, rdx
    jnz WriteLine_END

    popcnt rcx, rdx
    kmovq rax, KNAME
    shl rax, cl
    mov r11, rcx
    kmovq k1, rax

    vpexpandb	ZLINE{k1}, ZNAME
    vmovdqu8	zmmword ptr [ADDR_], ZLINE

WriteLine_END:
    nop
ENDM

WriteLineVariant MACRO ZVAR, KVAR, ZLINE, KLINE, ADDR_
    LOCAL WriteLineVar_ERR
    vmovdqu32 ZLINE, zmmword ptr [ADDR_]
    vptestmd KLINE, ZLINE, ZLINE

    kmovq rax, KVAR
    popcnt rcx, rax
    ror ax, cl

    kmovq rdx, KLINE
    and rax, rdx
    jnz WriteLineVar_ERR

    popcnt rcx, rdx
    kmovq rax, KVAR
    shl rax, cl

    kmovq k1, rax
    vpexpandd	ZLINE{k1}, ZVAR
    vmovdqu32	zmmword ptr [ADDR_], ZLINE

WriteLineVar_ERR:
    nop
ENDM

FindLineVariant MACRO VARIANT, ADDR_
    LOCAL END
    vmovdqu32 zmm1, zmmword ptr [ADDR_]
    vptestmd k1, zmm1, zmm1
    vptestmd k2{k1}, zmm1, DWORD BCST VARIANT_PREFIX
    int 3
    mov rax, VARIANT
    not rax
    vpbroadcastd zmm2, rax
    vptestnmd k3{k2}, zmm1, zmm2

    kandnd k5, k2, k1 ; variant mask - offset 3+

    kmovq rax, k3
    blsi rax, rax

    mov rcx, rax

    shl rcx, 1
    kmovq rdx, k5
    and rdx, rcx
    or rax, rdx

    shl rcx, 1
    kmovq rdx, k5
    and rdx, rcx
    or rax, rdx

    kmovq k4, rax
    vpcompressd	 zmm2{k4}, zmm1

END:
    nop
ENDM

ProcessVariant MACRO LINE_, INDEX_, MASK_
    pdep r9, LINE_, VARIANT_LINE_MASK
    pdep rcx, INDEX_, VARIANT_INDEX_MASK
    or r9, rcx
    pdep rcx, MASK_, VARIANT_VALUE_MASK
    or r9, rcx
    or r9, VARIANT_PREFIX

    kmovq k1, NUM1
    vpbroadcastq	zmm7{k1}, r9

    shr MASK_, 46
    kmovq k1, NUM2
    vpbroadcastq zmm7{k1}, MASK_
    vptestmd k7, zmm7, zmm7
ENDM

WriteVariant MACRO LINE_, INDEX_, MASK_
    ProcessVariant LINE_, INDEX_, MASK_
    mov rbx, [rbp.DICT.variantData]
    WriteLineVariant zmm7, k7, zmm0, k1, rbx
ENDM

FindVariant MACRO LINE_, INDEX_, MASK_
    ProcessVariant LINE_, INDEX_, MASK_
    mov rbx, [rbp.DICT.variantData]
    FindLineVariant r9, rbx
ENDM

FindLine MACRO ZNAME, XNAME, KNAME, ZLINE, ADDR_
    LOCAL FindLine_END, FindLine_SUCCESS, FindLine_LOOP
    mov r11, -1
    vmovdqu8	ZLINE, zmmword ptr [ADDR_]
    mov rax, 0ffh
    vpbroadcastb	zmm0, rax
    vpcmpub k1, ZLINE, zmm0, CMP_EQ

    kmovq rcx, KNAME
    popcnt rcx, rcx
    dec rcx

    kmovq rax, k1
    dec rax
    shr rax, cl
    jz FindLine_END
    kmovq k1, rax

    vmovq rax, XNAME
    vpbroadcastb	zmm0, rax
    vpcmpub	k2{k1}, ZLINE, zmm0, CMP_EQ

    kmovq r10, k2
    cmp r10, 0
    jz FindLine_END


FindLine_LOOP:
    kmovq rax, KNAME
    tzcnt rcx, r10
    shl rax, cl
    kmovq k1, rax
    vpexpandb	zmm0{k1}, ZNAME
    vpcmpub k2{k1}, zmm0, ZNAME, CMP_EQ

    ktestq k1, k2
    jc FindLine_SUCCESS

    blsr r10, r10
    jz FindLine_END
    jmp FindLine_LOOP

FindLine_SUCCESS:
    kmovq r11, k1
    tzcnt r11, r11
    and r11, 03fh


FindLine_END:
    nop
ENDM

ProcessName MACRO
    mov rbx, rdx
    LOAD_REGISTER rbx, zmm17, k7

    ; convert to lower case
    vmovdqu8 zmm0, zmmword ptr [ASCII_TOLOWER]
    vpermt2b zmm0{k7}{z}, zmm17, zmmword ptr [ASCII_TOLOWER + 64]
    vpcmpb k1{k7}, zmm0, zmm17, CMP_NEQ
    vmovdqu8	zmm17, zmm0
    kmovq r15, k1; r15 -> uppercase mask

    vmovdqu8 zmm11, zmmword ptr [ASCII_VOWEL]
    vpermt2b	zmm11{k7}{z}, zmm17, zmmword ptr [ASCII_VOWEL + 64]
    vptestmb	k1{k7}, zmm11, zmm11

    kmovq rax, k7 ; pattern = name length + vowels count - 3
    popcnt rax, rax
    kmovq rcx, k1
    popcnt rcx, rcx
    add rax, rcx
    sub rax, 3
    cmovl rax, NUM0

    mov r14, rax

    mov rax, 080h
    vpbroadcastb	zmm0, rax
    mov rdx, 1
    kmovq k1, rdx
    vpaddb zmm17{k1}, zmm17, zmm0
ENDM

WriteName PROC
    PUSHR
    mov rbp, rcx

    ProcessName

    kmovq rax, k7
    inc rax
    kmovq k1, rax
    mov rax, 0ffh
    vpbroadcastb	zmm17{k1}, rax
    korq k7, k1, k7

    shl r14, 10
    mov rbx, [rbp.DICT.lineData]
    add rbx, r14
    WriteLine zmm17, k7, zmm21, rbx

    cmp r11, 0
    ja WriteName_SUCCESS

WriteName_SUCCESS:
    mov r10, [rbp.DICT.lineData]
    sub rbx, r10
    shr rbx, 6

    pdep eax, ebx, TOKEN_LINE_MASK
    pdep ecx, r11d, TOKEN_INDEX_MASK
    or eax, ecx

    cmp r15, 0
    jz WriteName_END

    WriteVariant rbx, r11, r15
WriteName_END:
    POPR
    ret
WriteName ENDP

FindName PROC
    PUSHR
    mov rbp, rcx

    ProcessName

    shl r14, 10
    mov rbx, [rbp.DICT.lineData]
    add rbx, r14
    FindLine zmm17, xmm17, k7, zmm21, rbx

    mov r10, [rbp.DICT.lineData]
    sub rbx, r10
    shr rbx, 6
    FindVariant rbx, r11, r15
FindName_END:
    POPR
    ret
FindName ENDP

AVX512Test proc

    vmovdqu8 zmm0, zmmword ptr [rcx]
    mov rax, 4
    vpbroadcastb zmm1, rax
    mov rax, 0ffh
    kmovq k1, rax
    vpaddb zmm0 {k1}, zmm0, zmm1 ;byte bcst 5
    vmovdqu8 zmmword ptr [rdx], zmm0

    ret
AVX512Test endp

end
