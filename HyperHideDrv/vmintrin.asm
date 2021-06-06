.CODE                                                                                                                                                                            
__vm_call proc
    mov rax,0CDAEFAEDBBAEBEEFh
    vmcall
    ret
__vm_call endp

__vm_call_ex proc
        mov  rax,0CDAEFAEDBBAEBEEFh ; Our vmcall indentitifer

        sub rsp, 30h
        mov qword ptr [rsp],       r10
        mov qword ptr [rsp + 8h],  r11
        mov qword ptr [rsp + 10h], r12
        mov qword ptr [rsp + 18h], r13
        mov qword ptr [rsp + 20h], r14
        mov qword ptr [rsp + 28h], r15

        mov r10, qword ptr [rsp + 58h]
        mov r11, qword ptr [rsp + 60h]
        mov r12, qword ptr [rsp + 68h]
        mov r13, qword ptr [rsp + 70h]
        mov r14, qword ptr [rsp + 78h]
        mov r15, qword ptr [rsp + 80h]

        vmcall
        mov r10, qword ptr [rsp]
        mov r11, qword ptr [rsp + 8h]
        mov r12, qword ptr [rsp + 10h]
        mov r13, qword ptr [rsp + 18h]
        mov r14, qword ptr [rsp + 20h]
        mov r15, qword ptr [rsp + 28h]
        add rsp, 30h

        ret
__vm_call_ex endp

END