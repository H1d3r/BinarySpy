# -*- coding: utf-8 -*-
"""
sgn_wrapper.py —— sgn.exe 编码器封装（M2）

职责：
  - 定位 sgn.exe（项目根目录 / sgn_path 参数 / PATH）
  - 自动补齐其动态依赖 keystone.dll（pip keystone-engine 自带同名 DLL）
  - encode(arch) -> bytes：调用 sgn 对 shellcode 编码，返回编码后字节
  - 失败时抛 SGNError，由调用方决定降级策略（如使用原始 shellcode）

sgn v2.0.1 CLI（实测）：
  sgn -i <in> -o <out> -a <32|64> [-c N] [-M N] [--plain] [--ascii] [-S] [--badchars=...]
"""
import os
import shutil
import subprocess
import tempfile

SGN_TIMEOUT = 60


class SGNError(Exception):
    pass


def find_sgn(sgn_path=None):
    """定位 sgn.exe：显式路径 > tools/ > 项目根目录 > PATH。返回绝对路径或 None"""
    candidates = []
    if sgn_path:
        candidates.append(sgn_path)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "tools", "sgn.exe"))
    candidates.append(os.path.join(here, "sgn.exe"))
    which = shutil.which("sgn")
    if which:
        candidates.append(which)
    for c in candidates:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    return None


def ensure_keystone_dll(sgn_exe):
    """sgn.exe 动态依赖 keystone.dll；若旁边没有则从 pip keystone-engine 包复制一份"""
    sgn_dir = os.path.dirname(sgn_exe)
    if os.path.isfile(os.path.join(sgn_dir, "keystone.dll")):
        return True
    try:
        import keystone as ks_mod
        pkg_dir = os.path.dirname(os.path.abspath(ks_mod.__file__))
        src = os.path.join(pkg_dir, "keystone.dll")
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(sgn_dir, "keystone.dll"))
            return True
    except Exception:
        pass
    return False


def encode(shellcode, arch_bits, sgn_path=None, iterations=1, max_obfuscate=0, safe_mode=True):
    """
    用 sgn 编码 shellcode。
    默认 max_obfuscate=0：实测 sgn -M>0 的混淆 pass 会间歇性产出坏解码器
    （M=10 约 30% 崩溃、M=0 约 7%，raw 对照 0%）——见 todo.md M2 记录。
    :param shellcode: bytes 原始 shellcode
    :param arch_bits: 32 或 64
    :return: bytes 编码后（解码 stub + 编码体，自解码需 RWX 内存）
    :raises SGNError: sgn 不可用或编码失败
    """
    if arch_bits not in (32, 64):
        raise SGNError(f"无效架构位宽: {arch_bits}")

    sgn_exe = find_sgn(sgn_path)
    if not sgn_exe:
        raise SGNError("未找到 sgn.exe（放在项目根目录或用 sgn_path 指定）")
    ensure_keystone_dll(sgn_exe)

    with tempfile.TemporaryDirectory(prefix="sgn_") as td:
        inp = os.path.join(td, "in.bin")
        outp = os.path.join(td, "out.bin")
        with open(inp, "wb") as f:
            f.write(shellcode)

        cmd = [sgn_exe, "-i", inp, "-o", outp, "-a", str(arch_bits),
               "-c", str(iterations), "-M", str(max_obfuscate)]
        if safe_mode:
            cmd.append("-S")
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=SGN_TIMEOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW)
        except subprocess.TimeoutExpired:
            raise SGNError("sgn 编码超时")
        if r.returncode != 0:
            tail = (r.stdout or b"").decode(errors="ignore").strip().splitlines()[-3:]
            raise SGNError(f"sgn 退出码 {r.returncode}: " + " | ".join(tail))
        if not os.path.isfile(outp):
            raise SGNError("sgn 未产出输出文件")

        with open(outp, "rb") as f:
            data = f.read()
    if not data:
        raise SGNError("sgn 输出为空")
    return data


if __name__ == "__main__":
    # 冒烟测试
    with open("testfile/calc64.bin", "rb") as f:
        sc = f.read()
    out = encode(sc, 64)
    print(f"[+] calc64: {len(sc)}B -> sgn -> {len(out)}B")
    with open("testfile/calc32.bin", "rb") as f:
        sc32 = f.read()
    out32 = encode(sc32, 32)
    print(f"[+] calc32: {len(sc32)}B -> sgn -> {len(out32)}B")
