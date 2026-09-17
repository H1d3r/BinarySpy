import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
try:  # ttkbootstrap >=1.10 迁移至 widgets.scrolled，旧版回退
    from ttkbootstrap.widgets.scrolled import ScrolledText
except ImportError:
    from ttkbootstrap.scrolled import ScrolledText
from tkinter import filedialog, messagebox
import tkinter as tk
import pefile
import angr
import threading
import os
import logging
import shutil
import hashlib
import pickle
import time
import psutil
import subprocess
from datetime import datetime
from queue import Queue
from core.zeroeye_python import ZeroEyeWindow
from core.sigflip_python import SigFlipWindow

# --- 语言配置字典 ---
LANG_CONFIG = {
    "zh": {
        "title": "BinarySpy",
        "path_group": "文件配置",
        "target_label": "目标 PE:",
        "patch_label": "补丁源:",
        "loader_label": "加载器 EXE:",
        "loader_hint": "(DLL 需要 EXE 加载)",
        "remove_sig_btn": "去除签名",
        "opt_group": "Fuzz & 自动化设置",
        "test_patch_cb": "使用内置测试补丁 (testfile/calc32/64.bin)",
        "auto_delete_cb": "自动删除无效的测试文件",
        "mode_label": "Fuzz 模式:",
        "mode_auto": "自动分析 (CFG+调用链+符号执行)",
        "mode_all": "全部 Fuzz (直接测试所有大函数)",
        "mode_sgn": "SGN Loader",
        "sgn_encode_cb": "sgn 编码 (关闭=原始 shellcode)",
        "survival_cb": "存活判定 (C2 shellcode：目标常驻即成功)",
        "sym_exec_cb": "启用符号执行验证",
        "va_label": "手动 VA (Hex):",
        "size_label": "最小函数大小:",
        "depth_label": "最大调用深度:",
        "steps_label": "符号执行步数:",
        "delay_label": "测试延迟(秒):",
        "process_label": "监控进程名:",
        "stop_btn": "⏹ 停止并保存结果",
        "start_btn": "🚀 开始 Fuzz",
        "lang_label": "语言/Language:",
        "theme_label": "主题:",
        "browse": "浏览",
        "msg_error": "错误",
        "msg_success": "成功",
        "log_loading": "[*] 正在分析: ",
        "log_cfg": "[*] 正在构建 CFG (首次分析耗时较长)...",
        "log_cache": "[*] 发现缓存，快速加载中...",
        "log_sym_exec": "[*] 开始符号执行验证...",
        "log_sym_done": "[+] 符号执行完成，确认 {} 个函数可达",
        "log_auto_depth": "[+] 自动设置调用深度: {} (覆盖 {}% 函数)",
        "log_auto_steps": "[+] 自动设置符号执行步数: {}",
        "log_fuzz_start": "[+] 发现 {} 个可达函数，开始 Fuzz 测试...",
        "log_hit": " [!!!] 命中成功! 地址 {} 触发了目标进程",
        "log_fail": " [.] 未触发",
        "dll_mode": "[*] 检测到 DLL 目标，使用加载器 EXE 测试模式",
        "need_loader": "DLL 需要选择加载器 EXE"
    },
    "en": {
        "title": "BinarySpy",
        "path_group": "Path Configuration",
        "target_label": "Target PE:",
        "patch_label": "Patch Source:",
        "loader_label": "Loader EXE:",
        "loader_hint": "(DLL needs EXE loader)",
        "remove_sig_btn": "Remove Signature",
        "opt_group": "Fuzz & Automation Settings",
        "test_patch_cb": "Use Internal Test Patch (testfile/calc32/64.bin)",
        "auto_delete_cb": "Auto delete failed test files",
        "mode_label": "Fuzz Mode:",
        "mode_auto": "Auto Analysis (CFG+CallChain+SymExec)",
        "mode_all": "Fuzz All (Test all large functions)",
        "mode_sgn": "SGN Loader",
        "sgn_encode_cb": "sgn encode (off = raw shellcode)",
        "survival_cb": "Survival check (C2 shellcode: host stays alive = success)",
        "sym_exec_cb": "Enable Symbolic Execution",
        "va_label": "Manual VA (Hex):",
        "size_label": "Min Func Size:",
        "depth_label": "Max Call Depth:",
        "steps_label": "Sym Exec Steps:",
        "delay_label": "Test Delay(s):",
        "process_label": "Monitor Process:",
        "stop_btn": "⏹ Stop & Save Results",
        "start_btn": "🚀 Start Fuzz",
        "lang_label": "Language:",
        "theme_label": "Theme:",
        "browse": "Browse",
        "msg_error": "Error",
        "msg_success": "Success",
        "log_loading": "[*] Analyzing: ",
        "log_cfg": "[*] Building CFG (First run may take time)...",
        "log_cache": "[*] Cache found, loading functions...",
        "log_sym_exec": "[*] Starting symbolic execution verification...",
        "log_sym_done": "[+] Symbolic execution done, {} functions confirmed reachable",
        "log_auto_depth": "[+] Auto set call depth: {} (covers {}% functions)",
        "log_auto_steps": "[+] Auto set symbolic execution steps: {}",
        "log_fuzz_start": "[+] Found {} reachable functions, starting Fuzz...",
        "log_hit": " [!!!] HIT SUCCESS! Addr {} triggered target process",
        "log_fail": " [.] No Trigger",
        "dll_mode": "[*] DLL target detected, using loader EXE test mode",
        "need_loader": "DLL requires a loader EXE"
    }
}

class BinarySpy:
    def __init__(self, root):
        self.root = root
        self.root.title("BinarySpy")

        # 自适应窗口大小（宽度 46%、高度 82%，保证底部按钮可见）
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = int(screen_width * 0.46)
        window_height = int(screen_height * 0.82)
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        self.current_lang = "zh"
        
        # 日志相关属性
        self.file_logger = None
        self.detail_logger = None

        # 符号执行控制
        self.stop_requested = False
        self.sym_exec_state = None  # 保存当前符号执行状态

        # 最近一次 fuzz 命中（同目标可复用为 SGN Loader 候选）
        self.fuzz_hits = None

        # 加载 Logo
        try:
            if os.path.exists("logo.ico"): self.root.iconbitmap("logo.ico")
        except: pass

        self.msg_queue = Queue()
        self.cache_dir = ".spy_cache"
        if not os.path.exists(self.cache_dir): os.makedirs(self.cache_dir)

        self.init_ui()
        self.check_queue()

    def update_ui_text(self):
        """动态更新界面语言"""
        l = LANG_CONFIG[self.current_lang]
        self.path_group.config(text=l["path_group"])
        self.target_lbl.config(text=l["target_label"])
        self.patch_lbl.config(text=l["patch_label"])
        self.loader_lbl.config(text=l["loader_label"])
        self.loader_hint_lbl.config(text=l["loader_hint"])
        self.opt_group.config(text=l["opt_group"])
        # 模式选择
        self.mode_lbl.config(text=l["mode_label"])
        self.rb_auto.config(text=l["mode_auto"])
        self.rb_all.config(text=l["mode_all"])
        self.rb_sgn.config(text=l["mode_sgn"])
        self.cb_sgn_encode.config(text=l["sgn_encode_cb"])
        self.cb_survival.config(text=l["survival_cb"])
        # 复选框
        self.cb_test.config(text=l["test_patch_cb"])
        self.cb_auto_delete.config(text=l["auto_delete_cb"])
        self.cb_sym_exec.config(text=l["sym_exec_cb"])
        # 参数标签
        self.delay_lbl.config(text=l["delay_label"])
        self.process_lbl.config(text=l["process_label"])
        self.depth_lbl.config(text=l["depth_label"])
        self.size_lbl.config(text=l["size_label"])
        self.steps_lbl.config(text=l["steps_label"])
        self.va_lbl.config(text=l["va_label"])
        # 按钮
        self.start_btn.config(text=l["start_btn"])
        self.stop_btn.config(text=l["stop_btn"])
        self.remove_sig_btn.config(text=l["remove_sig_btn"])
        self.lang_lbl.config(text=l["lang_label"])
        self.theme_lbl.config(text=l["theme_label"])
        for btn in self.browse_btns: btn.config(text=l["browse"])

    def init_ui(self):
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- 语言和主题切换 ---
        lang_frame = ttk.Frame(main_frame)
        lang_frame.pack(fill=tk.X, pady=5)
        self.lang_lbl = ttk.Label(lang_frame, text="")
        self.lang_lbl.pack(side=tk.LEFT)
        self.lang_combo = ttk.Combobox(lang_frame, values=["zh", "en"], width=5, state="readonly")
        self.lang_combo.set("zh")
        self.lang_combo.pack(side=tk.LEFT, padx=5)
        self.lang_combo.bind("<<ComboboxSelected>>", lambda e: self.change_lang())

        # 主题切换
        self.theme_lbl = ttk.Label(lang_frame, text="")
        self.theme_lbl.pack(side=tk.LEFT, padx=(20, 0))
        self.theme_combo = ttk.Combobox(lang_frame, values=["cyborg", "darkly", "vapor", "superhero", "pulse"], width=10, state="readonly")
        self.theme_combo.set("cyborg")
        self.theme_combo.pack(side=tk.LEFT, padx=5)
        self.theme_combo.bind("<<ComboboxSelected>>", lambda e: self.change_theme())

        # --- 路径配置 ---
        self.path_group = ttk.LabelFrame(main_frame, text="")
        self.path_group.pack(fill=tk.X, pady=5)
        self.browse_btns = []

        self.target_lbl = ttk.Label(self.path_group, text="")
        self.target_lbl.grid(row=0, column=0, sticky=tk.W)
        self.target_entry = ttk.Entry(self.path_group, width=50)
        self.target_entry.grid(row=0, column=1, padx=5, pady=2)
        btn1 = ttk.Button(self.path_group, text="", command=self.load_target)
        btn1.grid(row=0, column=2); self.browse_btns.append(btn1)
        self.remove_sig_btn = ttk.Button(self.path_group, text="", command=self.remove_signature)
        self.remove_sig_btn.grid(row=0, column=3, padx=5)

        self.patch_lbl = ttk.Label(self.path_group, text="")
        self.patch_lbl.grid(row=1, column=0, sticky=tk.W)
        self.patch_entry = ttk.Entry(self.path_group, width=50)
        self.patch_entry.grid(row=1, column=1, padx=5, pady=2)
        btn2 = ttk.Button(self.path_group, text="", command=self.load_patch)
        btn2.grid(row=1, column=2); self.browse_btns.append(btn2)

        # DLL 加载器 EXE 选择（初始隐藏）
        self.loader_frame = ttk.Frame(self.path_group)
        self.loader_frame.grid(row=2, column=0, columnspan=3, sticky=tk.EW, pady=2)
        self.loader_lbl = ttk.Label(self.loader_frame, text="")
        self.loader_lbl.pack(side=tk.LEFT)
        self.loader_entry = ttk.Entry(self.loader_frame, width=47)
        self.loader_entry.pack(side=tk.LEFT, padx=5)
        btn3 = ttk.Button(self.loader_frame, text="", command=self.load_loader)
        btn3.pack(side=tk.LEFT); self.browse_btns.append(btn3)
        self.loader_hint_lbl = ttk.Label(self.loader_frame, text="", foreground="orange")
        self.loader_hint_lbl.pack(side=tk.LEFT, padx=5)
        
        # 初始隐藏 loader 选择框
        self.loader_frame.grid_remove()
        
        # DLL 目标标志
        self.is_dll_target = False

        # --- 自动化选项 ---
        self.opt_group = ttk.LabelFrame(main_frame, text="")
        self.opt_group.pack(fill=tk.X, pady=5)

        # 模式选择
        self.mode_var = tk.StringVar(value="auto")
        self.mode_lbl = ttk.Label(self.opt_group, text="")
        self.mode_lbl.grid(row=0, column=0, sticky=tk.W)
        self.rb_auto = ttk.Radiobutton(self.opt_group, text="", variable=self.mode_var, value="auto", command=self.on_mode_change)
        self.rb_auto.grid(row=0, column=1, columnspan=3, sticky=tk.W)
        self.rb_all = ttk.Radiobutton(self.opt_group, text="", variable=self.mode_var, value="all", command=self.on_mode_change)
        self.rb_all.grid(row=1, column=1, columnspan=3, sticky=tk.W)
        self.rb_sgn = ttk.Radiobutton(self.opt_group, text="", variable=self.mode_var, value="sgn", command=self.on_mode_change)
        self.rb_sgn.grid(row=2, column=1, columnspan=3, sticky=tk.W)

        # SGN Loader 模式：sgn 编码开关（shellcode 复用上方"补丁源"字段）
        self.sgn_encode_var = tk.BooleanVar(value=True)
        self.cb_sgn_encode = ttk.Checkbutton(self.opt_group, text="", variable=self.sgn_encode_var)
        self.cb_sgn_encode.grid(row=3, column=0, columnspan=2, sticky=tk.W)

        # 存活判定：C2 等不弹新进程的 shellcode，目标常驻窗口期即算成功
        self.survival_var = tk.BooleanVar(value=False)
        self.cb_survival = ttk.Checkbutton(self.opt_group, text="", variable=self.survival_var)
        self.cb_survival.grid(row=3, column=2, columnspan=2, sticky=tk.W)

        # 测试补丁选项
        self.test_patched_var = tk.BooleanVar(value=False)
        self.cb_test = ttk.Checkbutton(self.opt_group, text="", variable=self.test_patched_var)
        self.cb_test.grid(row=4, column=0, columnspan=4, sticky=tk.W)

        # 自动删除无效文件
        self.auto_delete_var = tk.BooleanVar(value=True)
        self.cb_auto_delete = ttk.Checkbutton(self.opt_group, text="", variable=self.auto_delete_var)
        self.cb_auto_delete.grid(row=5, column=0, columnspan=4, sticky=tk.W)

        # 符号执行选项 (自动分析模式专用)
        self.sym_exec_var = tk.BooleanVar(value=False)
        self.cb_sym_exec = ttk.Checkbutton(self.opt_group, text="", variable=self.sym_exec_var, command=self.on_mode_change)
        self.cb_sym_exec.grid(row=6, column=0, columnspan=4, sticky=tk.W)

        # 通用参数：测试延迟和监控进程
        self.delay_lbl = ttk.Label(self.opt_group, text="")
        self.delay_lbl.grid(row=7, column=0, sticky=tk.W)
        self.delay_entry = ttk.Entry(self.opt_group, width=8)
        self.delay_entry.insert(0, "3.5")
        self.delay_entry.grid(row=7, column=1, padx=5, sticky=tk.W)

        self.process_lbl = ttk.Label(self.opt_group, text="")
        self.process_lbl.grid(row=7, column=2, sticky=tk.W)
        self.process_entry = ttk.Entry(self.opt_group, width=20)
        self.process_entry.insert(0, "calc.exe,CalculatorApp.exe")
        self.process_entry.grid(row=7, column=3, padx=5, sticky=tk.W)

        # 深度和最小大小
        self.depth_lbl = ttk.Label(self.opt_group, text="")
        self.depth_lbl.grid(row=8, column=0, sticky=tk.W)
        self.depth_entry = ttk.Entry(self.opt_group, width=10)
        self.depth_entry.grid(row=8, column=1, padx=5, sticky=tk.W)

        self.size_lbl = ttk.Label(self.opt_group, text="")
        self.size_lbl.grid(row=8, column=2, sticky=tk.W)
        self.size_entry = ttk.Entry(self.opt_group, width=10)
        self.size_entry.grid(row=8, column=3, padx=5, sticky=tk.W)

        # 符号执行步数 (自动分析模式专用)
        self.steps_lbl = ttk.Label(self.opt_group, text="")
        self.steps_lbl.grid(row=9, column=0, sticky=tk.W)
        self.steps_entry = ttk.Entry(self.opt_group, width=10)
        self.steps_entry.grid(row=9, column=1, padx=5, sticky=tk.W)

        # 手动 VA
        self.va_lbl = ttk.Label(self.opt_group, text="")
        self.va_lbl.grid(row=9, column=2, sticky=tk.W)
        self.va_entry = ttk.Entry(self.opt_group, width=15)
        self.va_entry.grid(row=9, column=3, padx=5, sticky=tk.W)

        # --- 日志终端 ---
        self.log_text = tk.Text(main_frame, height=9, state=tk.DISABLED, bg="#1a1a2e", fg="#00ff88", font=("Consolas", 10), insertbackground="#00ff88")
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=10)

        # --- 控制区 ---
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        self.stop_btn = ttk.Button(main_frame, text="", command=self.stop_sym_exec)
        self.stop_btn.pack(side=tk.RIGHT, pady=5, padx=5)
        self.stop_btn.config(state=tk.DISABLED)  # 初始禁用
        self.start_btn = ttk.Button(main_frame, text="", command=self.start_task)
        self.start_btn.pack(side=tk.RIGHT, pady=5)
        self.zeroeye_btn = ttk.Button(main_frame, text="ZeroEye Tools", command=self.open_zeroeye)
        self.zeroeye_btn.pack(side=tk.LEFT, pady=5)
        self.sigflip_btn = ttk.Button(main_frame, text="SigFlip Tools", command=self.open_sigflip)
        self.sigflip_btn.pack(side=tk.LEFT, pady=5, padx=5)

        self.update_ui_text()
        self.on_mode_change()  # 初始化参数状态

    def open_zeroeye(self):
        ZeroEyeWindow(self.root)

    def open_sigflip(self):
        SigFlipWindow(self.root)

    def on_mode_change(self):
        """根据模式和符号执行复选框状态切换启用/禁用参数"""
        mode = self.mode_var.get()
        is_auto = mode == "auto"
        is_sgn = mode == "sgn"

        # SGN Loader 专用控件（shellcode 复用补丁源字段）
        sgn_state = tk.NORMAL if is_sgn else tk.DISABLED
        self.cb_sgn_encode.config(state=sgn_state)
        self.cb_survival.config(state=sgn_state)

        # 符号执行复选框只在自动分析模式下可用
        cb_state = tk.NORMAL if is_auto else tk.DISABLED
        self.cb_sym_exec.config(state=cb_state)

        # 步数输入框需要：自动分析模式 + 符号执行验证启用
        sym_enabled = self.sym_exec_var.get()
        steps_state = tk.NORMAL if (is_auto and sym_enabled) else tk.DISABLED
        self.steps_entry.config(state=steps_state)
        self.steps_lbl.config(state=steps_state)

        # 调用深度只在自动分析模式下有用（全部Fuzz模式不计算深度）
        depth_state = tk.NORMAL if is_auto else tk.DISABLED
        self.depth_entry.config(state=depth_state)
        self.depth_lbl.config(state=depth_state)

    def change_lang(self):
        self.current_lang = self.lang_combo.get()
        self.update_ui_text()

    def change_theme(self):
        """切换主题"""
        theme = self.theme_combo.get()
        self.root.style.theme_use(theme)

    def log(self, key_or_msg, *args, level="INFO", detail_only=False):
        """
        记录日志到界面和文件
        :param key_or_msg: 消息键或消息文本
        :param args: 格式化参数
        :param level: 日志级别 (DEBUG, INFO, WARNING, ERROR)
        :param detail_only: 仅记录到详细日志文件，不显示在界面
        """
        l = LANG_CONFIG[self.current_lang]
        # B4 修复：仅当 key 命中语言表才做 format，避免消息文本含 {} 时抛 IndexError
        template = l.get(key_or_msg)
        if template is not None:
            try:
                msg = template.format(*args)
            except (IndexError, KeyError, ValueError):
                msg = template
        else:
            msg = str(key_or_msg)
        timestamp = datetime.now().strftime("[%H:%M:%S] ")
        
        # 界面日志（非 detail_only）
        if not detail_only:
            self.msg_queue.put(timestamp + msg)
        
        # 文件日志
        if hasattr(self, 'file_logger') and self.file_logger:
            self.file_logger.info(msg)
        
        # 详细日志（包含更多调试信息）
        if detail_only and hasattr(self, 'detail_logger') and self.detail_logger:
            self.detail_logger.debug(msg)
        elif hasattr(self, 'detail_logger') and self.detail_logger:
            self.detail_logger.info(f"[{level}] {msg}")

    def check_queue(self):
        while not self.msg_queue.empty():
            msg = self.msg_queue.get()
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, msg + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        self.root.after(100, self.check_queue)

    def stop_sym_exec(self):
        """停止当前任务（符号执行 / SGN Loader 等）并保留当前结果"""
        self.stop_requested = True
        self.log("[*] 正在停止当前任务...")

    def _test_manual_va(self, ui):
        """手动 VA 模式：直接对指定 VA 进行补丁
        DLL 模式：只生成文件，不运行测试
        EXE 模式：生成文件并运行测试
        B1：全部输入来自主线程 UI 快照 ui
        """
        target_path = ui["target"]
        patch_path = ui["patch"]
        manual_va = ui["manual_va"]
        loader_path = ui["loader"]
        l = LANG_CONFIG[self.current_lang]

        try:
            # 解析 VA
            try:
                va = int(manual_va, 16)
            except ValueError:
                self._ui_messagebox("showerror", l["msg_error"],
                    "无效的 VA 地址，请输入十六进制格式" if self.current_lang == "zh" else "Invalid VA address, please use hex format")
                return
            
            # 初始化日志
            log_file, detail_log_file = self.setup_logging(target_path)
            
            self.log("=" * 60)
            self.log(f"[*] 手动 VA 补丁模式")
            self.log(f"[*] 目标文件: {target_path}")
            self.log(f"[*] 补丁 VA: {hex(va)}")
            
            if self.is_dll_target:
                self.log(f"[*] DLL 模式：仅生成补丁文件，不运行测试")
                if loader_path:
                    self.log(f"[*] 加载器: {loader_path}")
            
            self.log("=" * 60)
            
            # 加载 PE 获取架构信息
            proj = angr.Project(target_path, auto_load_libs=False)
            self.log(f"[+] PE 架构: {proj.arch.name}, 位宽: {proj.arch.bits}")
            
            # 获取补丁数据
            if ui["test_patch"]:
                p_file = "testfile/calc64.bin" if proj.arch.bits == 64 else "testfile/calc32.bin"
                if not os.path.exists(p_file):
                    raise Exception(f"Missing {p_file}")
                with open(p_file, 'rb') as f:
                    p_data = f.read()
                self.log(f"[+] 使用内置测试补丁: {p_file}, 大小={len(p_data)} bytes")
            elif patch_path:
                p_data = self.get_patch_data(patch_path)
                self.log(f"[+] 补丁数据来源: {patch_path}, 大小={len(p_data)} bytes")
            else:
                self._ui_messagebox("showwarning",
                    "警告" if self.current_lang == "zh" else "Warning",
                    "请选择补丁源文件或勾选使用内置测试补丁" if self.current_lang == "zh" else "Please select a patch source or enable test patch")
                return
            
            # 应用补丁
            patched_file = self.apply_patch(target_path, va, p_data, "manual")
            if not patched_file:
                self.log(f"[!] 补丁失败!")
                return
            
            self.log(f"[+] 补丁文件已生成: {patched_file}")
            
            # DLL 模式：只生成文件，不运行测试
            if self.is_dll_target:
                test_dir = os.path.dirname(patched_file)
                
                # 如果有 loader，也复制到测试目录
                if loader_path:
                    loader_name = os.path.basename(loader_path)
                    test_loader = os.path.join(test_dir, loader_name)
                    shutil.copy2(loader_path, test_loader)
                    self.log(f"[+] 加载器已复制: {test_loader}")
                
                self.log("=" * 60)
                self.log(f"[+] DLL 补丁完成!")
                self.log(f"[+] 补丁文件: {patched_file}")
                if loader_path:
                    self.log(f"[+] 加载器: {test_loader}")
                self.log(f"[*] 请手动运行加载器测试")
                self.log("=" * 60)
                
                self._ui_messagebox("showinfo", l["msg_success"],
                    f"补丁文件已生成:\n{patched_file}\n\n请手动运行加载器测试" if self.current_lang == "zh" else f"Patched file generated:\n{patched_file}\n\nRun loader manually to test")
                return
            
            # EXE 模式：运行测试（B2：列表 spawn + 轮询 diff 检测）
            self.log(f"[*] 开始运行测试...")
            delay = float(ui["delay"] or "3.5")
            monitor_names = self._monitor_names(ui["process"])

            hit, new_procs = self._run_spawn_test(patched_file, delay, monitor_names)

            if hit:
                triggered = ", ".join(sorted(set(new_procs.values())))
                self.log(f"[!!!] 命中成功! VA {hex(va)} 触发了目标进程 ({triggered})")
                self.log(f"[+] 测试成功!")
            else:
                self.log(f"[.] 未触发目标进程")
                if ui["auto_delete"]:
                    try:
                        if self.is_dll_target and os.path.exists(os.path.dirname(patched_file)):
                            shutil.rmtree(os.path.dirname(patched_file))
                            self.log(f"[-] 已删除测试目录")
                        elif os.path.exists(patched_file):
                            os.remove(patched_file)
                            self.log(f"[-] 已删除补丁文件")
                    except: pass
            
            self.log("=" * 60)
            self.log(f"[*] 测试完成")
            self.log(f"[*] 日志文件: {log_file}")
            
        except Exception as e:
            self.log(f"[X] Error: {str(e)}")
        finally:
            self.progress.stop()
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))

    def load_target(self):
        p = filedialog.askopenfilename(filetypes=[("PE files", "*.exe *.dll *.sys"), ("All files", "*.*")])
        if not p:
            return
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, p)
        
        # 检测是否为 DLL
        try:
            pe = pefile.PE(p)
            is_dll = pe.FILE_HEADER.Characteristics & 0x2000 != 0  # IMAGE_FILE_DLL
            pe.close()
            
            self.is_dll_target = is_dll
            
            if is_dll:
                self.loader_frame.grid()
                # DLL 目标：弹出对话框让用户选择模式
                l = LANG_CONFIG[self.current_lang]
                result = messagebox.askyesno(
                    "DLL 目标检测" if self.current_lang == "zh" else "DLL Target Detected",
                    "检测到 DLL 目标文件！\n\n是否进入全部 Fuzz 模式？\n\n点击【是】使用全部 Fuzz 模式\n点击【否】保留当前模式（与 EXE 相同逻辑）"
                    if self.current_lang == "zh" else
                    "DLL target file detected!\n\nEnter full fuzz mode?\n\nClick [Yes] for full fuzz mode\nClick [No] to keep current mode (same as EXE)",
                    icon='question'
                )
                
                if result:  # 用户选择全部 Fuzz 模式
                    self.mode_var.set("all")
                    self.rb_auto.config(state=tk.DISABLED)
                    self.log(f"[*] 检测到 DLL 目标，使用全部 Fuzz 模式")
                else:  # 用户选择保留当前模式
                    self.rb_auto.config(state=tk.NORMAL)
                    self.log(f"[*] 检测到 DLL 目标，保留当前模式（与 EXE 相同逻辑）")
                
                self.on_mode_change()
            else:
                self.loader_frame.grid_remove()
                # EXE 目标：恢复自动分析模式
                self.rb_auto.config(state=tk.NORMAL)
        except:
            self.is_dll_target = False
            self.loader_frame.grid_remove()
            self.rb_auto.config(state=tk.NORMAL)
    
    def load_patch(self):
        p = filedialog.askopenfilename(); self.patch_entry.delete(0, tk.END); self.patch_entry.insert(0, p)
    
    def load_loader(self):
        p = filedialog.askopenfilename(filetypes=[("EXE files", "*.exe"), ("All files", "*.*")])
        if p:
            self.loader_entry.delete(0, tk.END)
            self.loader_entry.insert(0, p)

    def get_file_hash(self, path):
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
        return h.hexdigest()

    def remove_signature(self):
        """去除 PE 文件的数字签名，并备份原文件"""
        target_path = self.target_entry.get().strip()
        if not target_path:
            messagebox.showwarning(self.current_lang == "zh" and "警告" or "Warning",
                                   self.current_lang == "zh" and "请先选择目标 PE 文件" or "Please select a target PE file first")
            return

        if not os.path.exists(target_path):
            messagebox.showerror(self.current_lang == "zh" and "错误" or "Error",
                                 self.current_lang == "zh" and "目标文件不存在" or "Target file does not exist")
            return

        try:
            pe = pefile.PE(target_path)

            # 检查是否有签名
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            if security_dir.VirtualAddress == 0 or security_dir.Size == 0:
                messagebox.showinfo(self.current_lang == "zh" and "提示" or "Info",
                                    self.current_lang == "zh" and "该文件没有数字签名" or "This file has no digital signature")
                pe.close()
                return

            # 备份原文件
            bak_path = target_path + ".bak"
            if os.path.exists(bak_path):
                result = messagebox.askyesno(self.current_lang == "zh" and "确认" or "Confirm",
                                             self.current_lang == "zh" and f"备份文件已存在: {bak_path}\n是否覆盖？" or f"Backup file exists: {bak_path}\nOverwrite?")
                if not result:
                    pe.close()
                    return

            # 清除签名目录
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0

            # 写入新文件
            new_data = pe.write()
            pe.close()

            # 先备份原文件
            shutil.copy2(target_path, bak_path)

            # 写入去除签名后的文件
            with open(target_path, 'wb') as f:
                f.write(new_data)

            messagebox.showinfo(self.current_lang == "zh" and "成功" or "Success",
                                self.current_lang == "zh" and f"签名已去除!\n备份文件: {bak_path}" or f"Signature removed!\nBackup: {bak_path}")

        except Exception as e:
            messagebox.showerror(self.current_lang == "zh" and "错误" or "Error",
                                 f"去除签名失败: {str(e)}")

    def kill_calc_processes(self, process_name=None):
        """终止指定的进程，返回是否找到并终止"""
        if process_name is None:
            process_name = self.process_entry.get().strip() or "calc.exe"
        # 支持多个进程名（逗号分隔）
        targets = [p.strip().lower() for p in process_name.split(',')]
        found = False
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() in targets:
                    proc.kill()
                    found = True
            except: continue
        return found

    # --- B2 进程管理辅助：列表 spawn / 轮询 diff 检测 / 静置清理 / 进程树整杀 ---
    @staticmethod
    def _monitor_names(process_str):
        """解析逗号分隔的监控进程名，统一小写"""
        names = [n.strip().lower() for n in (process_str or "calc.exe").split(',') if n.strip()]
        return names or ["calc.exe"]

    def _monitor_snapshot(self, names):
        """返回当前监控进程快照 {pid: name}"""
        targets = set(names)
        out = {}
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.info['name'] and proc.info['name'].lower() in targets:
                    out[proc.info['pid']] = proc.info['name']
            except Exception:
                continue
        return out

    def _wait_monitor_clean(self, names, timeout=8.0):
        """循环击杀监控进程直至快照为空（处理 calc.exe 存根 -> CalculatorApp 延迟重启链）"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            snap = self._monitor_snapshot(names)
            if not snap:
                return True
            for pid in snap:
                try:
                    psutil.Process(pid).kill()
                except Exception:
                    continue
            time.sleep(0.7)
        return not self._monitor_snapshot(names)

    def _kill_process_tree(self, pid):
        """递归整杀进程树（含子进程）"""
        try:
            parent = psutil.Process(pid)
        except Exception:
            return
        try:
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except Exception:
                    pass
        except Exception:
            pass
        try:
            parent.kill()
        except Exception:
            pass

    def _run_spawn_test(self, exe_path, delay, monitor_names):
        """
        B2 修复后的单次 spawn 测试：
        - 列表参数 Popen：不经 cmd 解析（元字符免疫），文件缺失立刻抛 FileNotFoundError，
          proc.pid 即目标进程本身（不再被 cmd 包装）；
        - 检测：spawn 前快照，窗口内轮询 diff 新增监控进程（UWP calc 激活延迟下不漏检）；
        - 清理：杀掉新增监控进程 + 递归整杀测试进程树。
        返回 (hit: bool, new_procs: {pid: name})
        """
        self._wait_monitor_clean(monitor_names)
        before = set(self._monitor_snapshot(monitor_names))
        new_procs = {}
        proc = None
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            proc = subprocess.Popen([exe_path], startupinfo=startupinfo,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            self.log(f"[!] 启动测试进程失败: {exe_path} ({e})")
            return False, {}

        t0 = time.time()
        while time.time() - t0 < delay:
            snap = self._monitor_snapshot(monitor_names)
            for pid, nm in snap.items():
                if pid not in before and pid not in new_procs:
                    new_procs[pid] = nm
            if new_procs:
                break  # 命中即提前收兵
            time.sleep(0.3)

        hit = len(new_procs) > 0
        for pid in new_procs:
            try:
                psutil.Process(pid).kill()
            except Exception:
                pass
        if proc is not None:
            self._kill_process_tree(proc.pid)
        return hit, new_procs

    # --- B1 UI 线程安全辅助 ---
    def _snapshot_ui(self):
        """主线程调用：一次性抓取全部 UI 输入值，工作线程只使用这份快照"""
        return {
            "target": self.target_entry.get().strip(),
            "patch": self.patch_entry.get().strip(),
            "loader": self.loader_entry.get().strip(),
            "sgn_encode": self.sgn_encode_var.get(),
            "survival": self.survival_var.get(),
            "manual_va": self.va_entry.get().strip(),
            "min_size": self.size_entry.get().strip(),
            "depth": self.depth_entry.get().strip(),
            "steps": self.steps_entry.get().strip(),
            "delay": self.delay_entry.get().strip(),
            "process": self.process_entry.get().strip(),
            "test_patch": self.test_patched_var.get(),
            "auto_delete": self.auto_delete_var.get(),
            "sym_exec": self.sym_exec_var.get(),
        }

    def _ui_messagebox(self, kind, title, message):
        """工作线程弹窗：marshal 到主线程执行（tkinter 非线程安全）"""
        self.root.after(0, lambda: getattr(messagebox, kind)(title, message))

    def start_task(self):
        self.start_btn.config(state=tk.DISABLED)
        self.progress.start()
        # B1：主线程先抓取 UI 快照再启动工作线程
        ui = self._snapshot_ui()
        # 根据模式选择工作线程
        if self.mode_var.get() == "auto":
            threading.Thread(target=self.worker_thread, args=(ui,), daemon=True).start()
        elif self.mode_var.get() == "sgn":
            threading.Thread(target=self.sgn_loader_worker_thread, args=(ui,), daemon=True).start()
        else:
            threading.Thread(target=self.fuzz_all_worker_thread, args=(ui,), daemon=True).start()

    def setup_logging(self, target_path):
        """初始化日志系统"""
        base_name = os.path.basename(target_path)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 主日志文件
        log_file = f"{base_name}_{timestamp}.log"
        handler = logging.FileHandler(log_file, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.file_logger = logging.getLogger(f"main_{timestamp}")
        self.file_logger.handlers.clear()
        self.file_logger.addHandler(handler)
        self.file_logger.setLevel(logging.INFO)
        
        # 详细日志文件（包含 angr 分析过程）
        detail_log_file = f"{base_name}_{timestamp}_detail.log"
        detail_handler = logging.FileHandler(detail_log_file, encoding='utf-8')
        detail_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        self.detail_logger = logging.getLogger(f"detail_{timestamp}")
        self.detail_logger.handlers.clear()
        self.detail_logger.addHandler(detail_handler)
        self.detail_logger.setLevel(logging.DEBUG)
        
        # 配置 angr 日志输出到详细日志文件
        angr_log = logging.getLogger('angr')
        angr_log.handlers.clear()
        angr_handler = logging.FileHandler(detail_log_file, encoding='utf-8')
        angr_handler.setFormatter(logging.Formatter('%(asctime)s [angr] %(message)s'))
        angr_log.addHandler(angr_handler)
        angr_log.setLevel(logging.DEBUG)  # 记录 angr 详细日志
        
        # 配置其他相关库的日志
        for lib_name in ['cle', 'pyvex', 'archinfo', 'claripy']:
            lib_logger = logging.getLogger(lib_name)
            lib_logger.handlers.clear()
            lib_logger.addHandler(angr_handler)
            lib_logger.setLevel(logging.DEBUG)
        
        return log_file, detail_log_file

    def analyze_call_chain(self, cfg, proj):
        """
        基于 CFG 调用链分析，找出从入口点可达的函数并排序
        返回按调用深度和重要性排序的函数列表
        """
        entry_point = proj.entry
        functions_info = {}
        
        # 收集所有函数信息
        for addr, fn in cfg.functions.items():
            if fn.is_simprocedure:
                continue
            functions_info[addr] = {
                'addr': addr,
                'size': fn.size,
                'name': fn.name,
                'callers': set(),  # 调用者
                'callees': set(),  # 被调用者
                'depth': -1,       # 调用深度（从入口点到该函数的最短路径）
                'call_count': 0    # 被调用次数
            }
        
        # 通过 CFG 图的边构建调用关系
        # 遍历所有边，判断是否为跨函数调用
        for src_node, dst_node in cfg.graph.edges():
            src_func = getattr(src_node, 'function_address', None)
            dst_func = getattr(dst_node, 'function_address', None)
            
            # 只关心跨函数调用（call/jump 到其他函数）
            if src_func and dst_func and src_func != dst_func:
                if src_func in functions_info and dst_func in functions_info:
                    functions_info[src_func]['callees'].add(dst_func)
                    functions_info[dst_func]['callers'].add(src_func)
                    functions_info[dst_func]['call_count'] += 1
        
        # BFS 计算调用深度（从入口点开始）
        from collections import deque
        queue = deque()
        
        # 找到入口函数
        entry_fn_addr = None
        for addr, info in functions_info.items():
            # 检查是否包含入口点
            fn = cfg.functions[addr]
            if fn.addr <= entry_point < fn.addr + fn.size:
                entry_fn_addr = addr
                break
        
        if entry_fn_addr:
            functions_info[entry_fn_addr]['depth'] = 0
            queue.append(entry_fn_addr)
            self.log(f"[+] 入口函数: {hex(entry_fn_addr)} ({functions_info[entry_fn_addr]['name']})", detail_only=True)
        else:
            # 如果找不到，使用入口点附近最近的函数
            closest_addr = min(functions_info.keys(), key=lambda a: abs(a - entry_point))
            functions_info[closest_addr]['depth'] = 0
            queue.append(closest_addr)
            self.log(f"[+] 使用最近入口: {hex(closest_addr)} ({functions_info[closest_addr]['name']})", detail_only=True)
        
        # BFS 遍历计算深度
        while queue:
            current = queue.popleft()
            current_depth = functions_info[current]['depth']
            
            for callee in functions_info[current]['callees']:
                if functions_info[callee]['depth'] == -1 or functions_info[callee]['depth'] > current_depth + 1:
                    functions_info[callee]['depth'] = current_depth + 1
                    queue.append(callee)
        
        # 过滤：只保留从入口点可达的函数
        reachable = [info for info in functions_info.values() if info['depth'] >= 0]
        
        self.log(f"[+] 从入口点可达的函数: {len(reachable)} 个", detail_only=True)
        self.log(f"[+] 不可达函数: {len(functions_info) - len(reachable)} 个", detail_only=True)
        
        # 排序策略：按调用深度优先，其次按被调用次数（热点函数优先）
        reachable.sort(key=lambda x: (x['depth'], -x['call_count'], x['addr']))
        
        return reachable, functions_info

    def symbolic_execution_verify(self, proj, all_functions, targets, max_steps=1000, sym_path=None):
        """
        使用符号执行验证函数是否真的可达
        返回实际执行到的函数地址集合
        """
        self.log("log_sym_exec")
        self.log(f"[*] 符号执行最大步数: {max_steps}")

        # 重置停止标志，启用停止按钮
        self.stop_requested = False
        self.root.after(0, lambda: self.stop_btn.config(state=tk.NORMAL))

        visited_functions = set()
        all_func_addrs = {f['addr'] for f in targets}
        step_count = [0]  # 用列表包装以便在闭包中修改
        was_stopped = False

        try:
            # 创建初始状态，从入口点开始
            self.log("[*] 创建初始状态...", detail_only=True)
            state = proj.factory.entry_state(
                args=[proj.filename],
                add_options={
                    angr.options.TRACK_ACTION_HISTORY,
                    angr.options.LAZY_SOLVES,  # 延迟约束检查，避免状态过早死亡
                    angr.options.SYMBOLIC_INITIALIZE_RESOLUTION,  # 符号化初始化
                }
            )
            self.log("[+] 初始状态创建完成", detail_only=True)

            # 创建模拟管理器
            self.log("[*] 创建模拟管理器...", detail_only=True)
            simgr = proj.factory.simulation_manager(state)
            self.log("[+] 模拟管理器创建完成", detail_only=True)

            start_time = time.time()

            # 手动步进执行，避免死循环
            while len(simgr.active) > 0 and step_count[0] < max_steps:
                # 检查是否请求停止
                if self.stop_requested:
                    was_stopped = True
                    self.log(f"[!] 用户请求停止，正在保存当前结果...")
                    break

                # 记录当前活跃状态访问的函数
                for active_state in simgr.active:
                    try:
                        addr = active_state.addr
                        # 查找该地址所属的函数（使用缓存的函数列表）
                        for fn_addr, fn in all_functions.items():
                            if fn['addr'] <= addr < fn['addr'] + fn['size']:
                                if fn_addr in all_func_addrs:
                                    visited_functions.add(fn_addr)
                                break
                    except:
                        pass

                # 单步执行
                simgr.step()
                step_count[0] += 1

                # 每10步输出进度（更频繁）
                if step_count[0] % 10 == 0:
                    self.log(f"[*] 已执行 {step_count[0]} 步, 活跃状态: {len(simgr.active)}, 已访问函数: {len(visited_functions)}")

            exec_time = time.time() - start_time

            # 收集结果
            if was_stopped:
                self.log(f"[!] 符号执行被用户中断，耗时: {exec_time:.2f}秒, 共 {step_count[0]} 步")
            else:
                self.log(f"[+] 符号执行耗时: {exec_time:.2f}秒, 共 {step_count[0]} 步", detail_only=True)
            self.log(f"[+] 活跃状态数: {len(simgr.active)}", detail_only=True)
            self.log(f"[+] 死锁状态数: {len(simgr.deadended)}", detail_only=True)

            # 从活跃状态中收集访问过的函数（遍历执行历史）
            for active_state in simgr.active:
                try:
                    if hasattr(active_state, 'history'):
                        for addr in active_state.history.bbl_addrs:
                            for fn_addr, fn in all_functions.items():
                                if fn['addr'] <= addr < fn['addr'] + fn['size']:
                                    if fn_addr in all_func_addrs:
                                        visited_functions.add(fn_addr)
                                    break
                except:
                    pass

            # 从死锁状态中收集访问过的函数（遍历执行历史）
            for dead_state in simgr.deadended:
                try:
                    # 遍历整个执行历史记录
                    if hasattr(dead_state, 'history'):
                        for addr in dead_state.history.bbl_addrs:
                            for fn_addr, fn in all_functions.items():
                                if fn['addr'] <= addr < fn['addr'] + fn['size']:
                                    if fn_addr in all_func_addrs:
                                        visited_functions.add(fn_addr)
                                    break
                    else:
                        # 回退：只检查最后地址
                        addr = dead_state.addr
                        for fn_addr, fn in all_functions.items():
                            if fn['addr'] <= addr < fn['addr'] + fn['size']:
                                if fn_addr in all_func_addrs:
                                    visited_functions.add(fn_addr)
                                break
                except:
                    pass

            self.log(f"[+] 符号执行验证通过: {len(visited_functions)} 个函数", detail_only=True)

            # 保存结果到缓存（无论是正常结束还是被中断）
            if sym_path:
                with open(sym_path, 'wb') as f: pickle.dump(visited_functions, f)
                self.log(f"[+] 结果已保存到缓存: {sym_path}")

        except Exception as e:
            self.log(f"[!] 符号执行错误: {str(e)}", detail_only=True)
            # 出错时返回所有目标
            return all_func_addrs
        finally:
            # 禁用停止按钮
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))

        return visited_functions

    def sgn_loader_worker_thread(self, ui):
        """SGN Loader 模式工作线程：补丁源(shellcode) → (sgn) → 新增节补丁 → 验证重试"""
        l = LANG_CONFIG[self.current_lang]
        target_path = ui["target"]

        def _fail(msg):
            self._ui_messagebox("showwarning",
                                "警告" if self.current_lang == "zh" else "Warning", msg)
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            self.root.after(0, self.progress.stop)

        if not target_path:
            _fail("请选择目标 PE 文件" if self.current_lang == "zh" else "Please select a target PE file")
            return
        try:
            from core import sgn_loader as sl
            from core import sgn_wrapper
            if ui["sgn_encode"] and not sgn_wrapper.find_sgn():
                raise RuntimeError("未找到 sgn.exe (sgn.exe not found)" if
                                   self.current_lang == "zh" else "sgn.exe not found")
        except Exception as e:
            _fail(f"SGN 环境不可用: {e}" if self.current_lang == "zh"
                  else f"SGN environment unavailable: {e}")
            return

        try:
            arch = sl.detect_arch(target_path)
            # 停止按钮可用（build_verified 在每次尝试/监控窗口内响应）
            self.stop_requested = False
            self.root.after(0, lambda: self.stop_btn.config(state=tk.NORMAL))
            # shellcode 来源：勾选"内置测试补丁"→ testfile/calc*.bin；否则用补丁源字段
            if ui["test_patch"]:
                sc_path = "testfile/calc64.bin" if arch == 64 else "testfile/calc32.bin"
                if not os.path.isfile(sc_path):
                    raise FileNotFoundError(f"内置测试补丁缺失: {sc_path}")
            else:
                sc_path = ui["patch"]
                if not sc_path or not os.path.isfile(sc_path):
                    _fail("请在补丁源选择 shellcode .bin 文件（或勾选内置测试补丁）"
                          if self.current_lang == "zh" else
                          "Select a shellcode .bin as patch source (or enable the internal test patch)")
                    return
            with open(sc_path, "rb") as f:
                shellcode = f.read()
            self.log(f"[*] SGN Loader: target={os.path.basename(target_path)} "
                     f"arch={arch} shellcode={os.path.basename(sc_path)} ({len(shellcode)}B)")
            if not shellcode:
                _fail("shellcode 文件为空" if self.current_lang == "zh" else "Shellcode file is empty")
                return

            # 候选来源优先级：手动 VA > 同目标 fuzz 命中 > 自动扫描
            if ui["manual_va"]:
                cand_vas = [int(ui["manual_va"], 16)]
                self.log(f"[*] 手动 VA: {cand_vas[0]:#x}")
            else:
                if (self.fuzz_hits and self.fuzz_hits["vas"] and
                        os.path.abspath(self.fuzz_hits["target"]) == os.path.abspath(target_path)):
                    cand_vas = self.fuzz_hits["vas"]
                    cand_note = f"fuzz 命中"
                else:
                    cands = sl.auto_candidates(target_path, arch)
                    cand_vas = [c[0] for c in cands]
                    cand_note = "自动扫描"
                self.log(f"[*] 候选来源: {cand_note}，共 {len(cand_vas)} 个: "
                         + ", ".join(f"{v:#x}" for v in cand_vas[:4])
                         + (" …" if len(cand_vas) > 4 else ""))

            triggers = None
            if not ui["survival"]:
                triggers = [s.strip() for s in ui["process"].split(",") if s.strip()] or None
            else:
                self.log(f"[*] 判定模式: 存活 —— 目标常驻 {max(4.0, float(ui['delay'] or 6)):.0f}s "
                         "即成功（C2/无新进程 shellcode 适用），忽略监控进程名")
            try:
                watch = max(4.0, float(ui["delay"] or 6))
            except ValueError:
                watch = 6.0

            out_dir = os.path.join(os.path.dirname(os.path.abspath(target_path)), "sgn_out")
            # 每个候选都有机会（无硬上限；崩溃同候选重编码、无 HIT 才换下一个）
            # sgn_iterations=2：双层编码，sgn 原生防模拟手段（模拟器需连续解码两层）
            r = sl.build_verified(target_path, cand_vas[0], shellcode, arch, out_dir,
                                  sgn=ui["sgn_encode"], watch_secs=watch,
                                  trigger_names=triggers, candidates=cand_vas,
                                  should_stop=lambda: self.stop_requested,
                                  sgn_iterations=2, log=self.log)
            ok = r["ok"]
            self.log(f"[{'+' if ok else '!'}] SGN Loader 完成: attempts={r['attempts']} "
                     f"VA={r.get('va', 0):#x} HIT={r['hit']} exit={r['exit']} -> {r['out_path']}")
            self._ui_messagebox(
                "showinfo" if ok else "showwarning",
                l["msg_success"] if ok else l["msg_error"],
                (f"HIT! 尝试 {r['attempts']} 次 @ {r.get('va', 0):#x}，产物: {r['out_path']}" if ok else
                 (f"已停止，尝试 {r['attempts']} 次。当前产物: {r['out_path']}"
                  if self.stop_requested else
                  f"未达成验证 (HIT={r['hit']}, exit={r['exit']})，尝试 {r['attempts']} 次。\n"
                  "可关闭 sgn 编码重试，或手动填一个启动早期会被调用的函数 VA。"))
                if self.current_lang == "zh" else
                (f"HIT! attempts={r['attempts']} @ {r.get('va', 0):#x}, output: {r['out_path']}" if ok else
                 (f"Stopped after {r['attempts']} attempts. Last output: {r['out_path']}"
                  if self.stop_requested else
                  f"Verification failed (HIT={r['hit']}, exit={r['exit']}), attempts={r['attempts']}.\n"
                  "Try disabling sgn encode or set a manual VA of a startup-called function.")))
        except Exception as e:
            self.log(f"[!] SGN Loader 异常: {e}", level="ERROR")
            self._ui_messagebox("showerror", l["msg_error"], str(e))
        finally:
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            self.root.after(0, self.progress.stop)

    def worker_thread(self, ui):
        """B1：输入全部来自主线程 UI 快照 ui，线程内不再读 tkinter 变量"""
        target_path = ui["target"]
        patch_path = ui["patch"]
        loader_path = ui["loader"]

        if not target_path:
            self._ui_messagebox("showwarning",
                                "警告" if self.current_lang == "zh" else "Warning",
                                "请选择目标 PE 文件" if self.current_lang == "zh" else "Please select a target PE file")
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            return

        # DLL 模式需要 loader exe（除非填写了手动 VA）
        l = LANG_CONFIG[self.current_lang]
        manual_va = ui["manual_va"]
        if self.is_dll_target and not loader_path and not manual_va:
            self._ui_messagebox("showwarning",
                                "警告" if self.current_lang == "zh" else "Warning",
                                l["need_loader"])
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            return

        # 手动 VA 模式：直接测试指定地址
        if manual_va:
            self._test_manual_va(ui)
            return

        if not ui["test_patch"] and not patch_path:
            self._ui_messagebox("showwarning",
                                "警告" if self.current_lang == "zh" else "Warning",
                                "请选择补丁源文件或勾选使用内置测试补丁" if self.current_lang == "zh" else "Please select a patch source or enable test patch")
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            return

        log_file = None
        detail_log_file = None
        cfg = None
        
        try:
            # 初始化日志系统
            log_file, detail_log_file = self.setup_logging(target_path)
            
            self.log("=" * 60)
            self.log(f"[*] 开始分析目标文件: {target_path}")
            self.log(f"[*] 主日志: {log_file}")
            self.log(f"[*] 详细日志: {detail_log_file}")
            
            # DLL 模式提示
            if self.is_dll_target:
                self.log(l["dll_mode"])
                self.log(f"[*] 加载器 EXE: {loader_path}")
            
            self.log("=" * 60, detail_only=True)
            
            self.log("[*] 正在加载 PE 文件...", detail_only=True)
            proj = angr.Project(target_path, auto_load_libs=False)
            self.log(f"[+] PE 加载成功: 架构={proj.arch.name}, 位宽={proj.arch.bits}, 入口点={hex(proj.entry)}", detail_only=True)
            
            # 获取补丁数据
            if ui["test_patch"]:
                p_file = "testfile/calc64.bin" if proj.arch.bits == 64 else "testfile/calc32.bin"
                if not os.path.exists(p_file): raise Exception(f"Missing {p_file}")
                with open(p_file, 'rb') as f: p_data = f.read()
                self.log(f"[+] 使用内置测试补丁: {p_file}, 大小={len(p_data)} bytes", detail_only=True)
            else:
                p_data = self.get_patch_data(patch_path)
                self.log(f"[+] 补丁数据来源: {patch_path}, 大小={len(p_data)} bytes", detail_only=True)
            
            min_sz = int(ui["min_size"] or len(p_data))
            use_sym_exec = ui["sym_exec"]
            f_hash = self.get_file_hash(target_path)
            c_path = os.path.join(self.cache_dir, f"{f_hash}.cache")
            cfg_path = os.path.join(self.cache_dir, f"{f_hash}_cfg.cache")
            # sym_path 延迟到步数确定后再设置（步数影响缓存）
            
            self.log(f"[*] 文件 SHA256: {f_hash}", detail_only=True)
            self.log(f"[*] 最小函数大小过滤: {min_sz} bytes", detail_only=True)
            self.log(f"[*] 符号执行: {'启用' if use_sym_exec else '禁用'}", detail_only=True)
            
            # 检查缓存
            if os.path.exists(c_path) and os.path.exists(cfg_path):
                self.log("log_cache")
                self.log(f"[+] 从缓存加载分析结果...", detail_only=True)
                with open(c_path, 'rb') as f: targets = pickle.load(f)
                with open(cfg_path, 'rb') as f: all_functions = pickle.load(f)
                self.log(f"[+] 缓存中共有 {len(targets)} 个目标函数", detail_only=True)
            else:
                self.log("log_cfg")
                self.log("[*] 开始 CFG 分析和调用链追踪...", detail_only=True)
                start_time = time.time()
                
                # 构建 CFG
                cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True)
                cfg_time = time.time() - start_time
                self.log(f"[+] CFG 构建完成, 耗时: {cfg_time:.2f}秒", detail_only=True)
                
                # 分析调用链
                self.log("[*] 分析调用链关系...", detail_only=True)
                targets, all_functions = self.analyze_call_chain(cfg, proj)
                
                # 记录调用链详情
                self.log("=" * 60, detail_only=True)
                self.log("[*] 调用链分析结果 (前50个):", detail_only=True)
                for i, fn in enumerate(targets[:50]):
                    self.log(f"    [depth={fn['depth']}] {hex(fn['addr'])}: {fn['name']} "
                            f"(size={fn['size']}, callers={len(fn['callers'])}, "
                            f"callees={len(fn['callees'])})", detail_only=True)
                self.log("=" * 60, detail_only=True)
                
                # 缓存结果
                with open(c_path, 'wb') as f: pickle.dump(targets, f)
                with open(cfg_path, 'wb') as f: pickle.dump(all_functions, f)
                self.log(f"[+] 分析结果已缓存", detail_only=True)

            # 打印函数统计信息
            self.log("=" * 60)
            self.log(f"[*] 函数统计信息:")
            total_funcs = len(targets)
            if targets:
                depths = [f['depth'] for f in targets]
                max_possible_depth = max(depths) if depths else 0
                self.log(f"    总函数数: {total_funcs}")
                self.log(f"    最大深度: {max_possible_depth}")
                # 深度分布统计
                from collections import Counter
                depth_dist = Counter(depths)
                self.log(f"    深度分布:")
                for d in sorted(depth_dist.keys()):
                    count = depth_dist[d]
                    pct = count / total_funcs * 100
                    bar = "█" * int(pct / 2)
                    self.log(f"      depth={d:2d}: {count:5d} ({pct:5.1f}%) {bar}")
            else:
                self.log("    无可达函数")
            self.log("=" * 60)

            # 深度设置：手动优先，否则自动计算
            manual_depth = ui["depth"]
            if manual_depth:
                try:
                    auto_depth = int(manual_depth)
                    self.log(f"[+] 使用手动设置深度: {auto_depth}")
                except ValueError:
                    self.log("[!] 深度输入无效，使用自动计算")
                    manual_depth = ""

            if not manual_depth and targets:
                depths = [f['depth'] for f in targets]
                max_possible_depth = max(depths) if depths else 0
                # 计算覆盖 50% 函数的深度阈值（减小深度以减少待测试函数）
                sorted_depths = sorted(depths)
                threshold_idx = int(len(sorted_depths) * 0.5)
                auto_depth = sorted_depths[threshold_idx] if threshold_idx < len(sorted_depths) else max_possible_depth
                # 确保至少有 depth=0 和 depth=1
                auto_depth = max(auto_depth, 1)
            elif not manual_depth:
                auto_depth = 2

            coverage = len([f for f in targets if f['depth'] <= auto_depth]) / len(targets) * 100 if targets else 0
            self.log("log_auto_depth", auto_depth, f"{coverage:.1f}")

            # 智能筛选：按深度 + 大小过滤
            valid_targets = [f for f in targets
                           if f['size'] >= min_sz and f['depth'] <= auto_depth]
            self.log(f"[+] CFG 分析得到候选函数: {len(valid_targets)} 个", detail_only=True)
            
            # 符号执行验证（如果启用）
            if use_sym_exec and valid_targets:
                # 步数设置：用户输入优先，否则默认100步
                manual_steps = ui["steps"]
                if manual_steps:
                    try:
                        auto_steps = int(manual_steps)
                        self.log(f"[+] 使用手动设置步数: {auto_steps}")
                    except ValueError:
                        self.log("[!] 步数输入无效，使用默认值 100")
                        auto_steps = 100
                else:
                    auto_steps = 100
                    self.log(f"[+] 使用默认步数: {auto_steps}")

                # 符号执行缓存路径包含深度和步数参数
                sym_path = os.path.join(self.cache_dir, f"{f_hash}_sym_d{auto_depth}_s{auto_steps}.cache")

                # 检查符号执行缓存
                if os.path.exists(sym_path):
                    self.log("[*] 发现符号执行缓存，加载中...", detail_only=True)
                    with open(sym_path, 'rb') as f: verified_addrs = pickle.load(f)
                    self.log(f"[+] 缓存中已验证函数: {len(verified_addrs)} 个", detail_only=True)
                else:
                    # 执行符号执行验证（传入缓存路径，函数内部会保存结果）
                    verified_addrs = self.symbolic_execution_verify(proj, all_functions, valid_targets, auto_steps, sym_path)
                
                # 过滤出验证通过的函数
                verified_targets = [f for f in valid_targets if f['addr'] in verified_addrs]
                self.log("log_sym_done", len(verified_targets))
                
                # 记录被过滤掉的函数
                filtered_out = [f for f in valid_targets if f['addr'] not in verified_addrs]
                if filtered_out:
                    self.log(f"[!] 符号执行过滤掉 {len(filtered_out)} 个不可达函数:", detail_only=True)
                    for fn in filtered_out[:10]:
                        self.log(f"    {hex(fn['addr'])}: {fn['name']}", detail_only=True)
                
                valid_targets = verified_targets
            
            if not valid_targets:
                self.log("[!] 没有符合条件的函数可供测试!")
                return
            
            # 记录目标函数详情
            self.log("=" * 60)
            self.log(f"[*] 目标函数列表 (depth<={auto_depth}):")
            for i, fn in enumerate(valid_targets):
                self.log(f"    [{i}] depth={fn['depth']}, {hex(fn['addr'])}: {fn['name']} (size={fn['size']}, callers={fn['call_count']})")
            self.log("=" * 60)

            # 开始 fuzz - 测试所有符合条件的函数（不再限制15个）
            self.log("[*] 开始 Fuzz 测试...", detail_only=True)
            hits = []
            test_count = len(valid_targets)

            # 启用停止按钮
            self.stop_requested = False
            self.root.after(0, lambda: self.stop_btn.config(state=tk.NORMAL))

            for i, item in enumerate(valid_targets):
                # 检查是否请求停止
                if self.stop_requested:
                    self.log(f"[!] 用户请求停止，已保存当前结果...")
                    break

                addr = item['addr']
                depth = item['depth']
                name = item['name']
                size = item['size']

                self.log(f"[#{i+1}/{test_count}] depth={depth} | {hex(addr)}: {name} (size={size})", detail_only=True)

                patched_file = self.apply_patch(target_path, addr, p_data, f"fuzz_{i}")
                if not patched_file:
                    self.log(f"[!] 补丁失败: {hex(addr)}", detail_only=True)
                    continue
                
                self.log(f"[+] 已生成补丁文件: {patched_file}", detail_only=True)
                self.log(f"[#{i+1}/{test_count}] Testing {name} @ {hex(addr)}")

                delay = float(ui["delay"] or "3.5")
                monitor_names = self._monitor_names(ui["process"])
                try:
                    # DLL 模式：复制 loader exe 到测试目录，测试加载器；EXE 模式直接测补丁文件
                    exe_to_run = patched_file
                    if self.is_dll_target:
                        test_dir = os.path.dirname(patched_file)
                        loader_name = os.path.basename(loader_path)
                        test_loader = os.path.join(test_dir, loader_name)
                        shutil.copy2(loader_path, test_loader)
                        exe_to_run = test_loader

                    # B2：列表 spawn + 轮询 diff 检测 + 进程树整杀
                    hit, new_procs = self._run_spawn_test(exe_to_run, delay, monitor_names)

                    if hit:
                        triggered = ", ".join(sorted(set(new_procs.values())))
                        self.log("log_hit", hex(addr))
                        self.log(f"[!] 触发进程: {triggered}", detail_only=True)
                        hits.append((addr, name, depth, size))
                        self.log(f"[!!!] 命中! 地址={hex(addr)}, 函数={name}, 大小={size}, 深度={depth}", detail_only=True)
                    else:
                        self.log("log_fail")
                        # 删除测试失败的 fuzz 文件（如果启用）
                        if ui["auto_delete"]:
                            try:
                                # DLL 模式删除整个测试目录
                                if self.is_dll_target and os.path.exists(os.path.dirname(patched_file)):
                                    shutil.rmtree(os.path.dirname(patched_file))
                                    self.log(f"[-] 已删除测试目录: {os.path.dirname(patched_file)}", detail_only=True)
                                elif os.path.exists(patched_file):
                                    os.remove(patched_file)
                                    self.log(f"[-] 已删除失败文件: {patched_file}", detail_only=True)
                            except Exception as del_e:
                                self.log(f"[!] 删除失败: {str(del_e)}", detail_only=True)
                except Exception as e:
                    self.log(f"[!] 执行错误: {str(e)}", detail_only=True)
                    if ui["auto_delete"]:
                        try:
                            if self.is_dll_target and os.path.exists(os.path.dirname(patched_file)):
                                shutil.rmtree(os.path.dirname(patched_file))
                            elif os.path.exists(patched_file):
                                os.remove(patched_file)
                        except: pass

            # 总结
            self.log("=" * 60)
            self.log(f"[*] 分析完成!")
            self.log(f"[*] 总共测试: {test_count} 个函数")
            self.log(f"[*] 命中数量: {len(hits)}")
            if hits:
                self.log("[+] 命中详情:")
                for addr, name, depth, size in hits:
                    self.log(f"    depth={depth}, size={size} | {hex(addr)}: {name}")
                # 供 SGN Loader 复用：这些函数已验证"会被调用且可安全切分"
                self.fuzz_hits = {"target": target_path, "vas": [h[0] for h in hits]}
                self.log("[+] 命中候选已记录：切到 SGN Loader 模式（VA 留空）即可复用")
            self.log(f"[*] 主日志文件: {log_file}")
            self.log(f"[*] 详细日志文件: {detail_log_file}")
            self.log("=" * 60)
            
        except Exception as e:
            self.log(f"[X] Error: {str(e)}")
            if hasattr(self, 'detail_logger') and self.detail_logger:
                import traceback
                self.detail_logger.error(f"异常详情:\n{traceback.format_exc()}")
        finally:
            self.progress.stop()
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))

    def fuzz_all_worker_thread(self, ui):
        """全部 Fuzz 工作线程 - 直接测试所有大于补丁大小的函数
        B1：输入全部来自主线程 UI 快照 ui"""
        target_path = ui["target"]
        patch_path = ui["patch"]
        loader_path = ui["loader"]

        if not target_path:
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            return

        # DLL 模式需要 loader exe（除非填写了手动 VA）
        l = LANG_CONFIG[self.current_lang]
        manual_va = ui["manual_va"]
        if self.is_dll_target and not loader_path and not manual_va:
            self._ui_messagebox("showwarning",
                                "警告" if self.current_lang == "zh" else "Warning",
                                l["need_loader"])
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            return

        # 手动 VA 模式：直接测试指定地址
        if manual_va:
            self._test_manual_va(ui)
            return

        log_file = None
        detail_log_file = None

        try:
            # 初始化日志系统
            log_file, detail_log_file = self.setup_logging(target_path)

            self.log("=" * 60)
            self.log(f"[*] 全部 Fuzz 模式: {target_path}")
            self.log(f"[*] 主日志: {log_file}")
            
            # DLL 模式提示
            if self.is_dll_target:
                self.log(l["dll_mode"])
                self.log(f"[*] 加载器 EXE: {loader_path}")
            
            self.log("=" * 60, detail_only=True)

            self.log("[*] 正在加载 PE 文件...", detail_only=True)
            proj = angr.Project(target_path, auto_load_libs=False)
            self.log(f"[+] PE 加载成功: 架构={proj.arch.name}, 位宽={proj.arch.bits}, 入口点={hex(proj.entry)}", detail_only=True)

            # 获取补丁数据
            if ui["test_patch"]:
                p_file = "testfile/calc64.bin" if proj.arch.bits == 64 else "testfile/calc32.bin"
                if not os.path.exists(p_file):
                    raise Exception(f"Missing {p_file}")
                with open(p_file, 'rb') as f:
                    p_data = f.read()
                self.log(f"[+] 使用内置测试补丁: {p_file}, 大小={len(p_data)} bytes", detail_only=True)
            else:
                p_data = self.get_patch_data(patch_path)
                self.log(f"[+] 补丁数据来源: {patch_path}, 大小={len(p_data)} bytes", detail_only=True)

            patch_size = len(p_data)

            # 用户定义的最小函数大小优先，否则使用补丁大小
            min_sz_input = ui["min_size"]
            min_sz = int(min_sz_input) if min_sz_input else patch_size
            self.log(f"[*] 最小函数大小过滤: {min_sz} bytes")

            # 缓存路径
            f_hash = self.get_file_hash(target_path)
            fuzz_cache_path = os.path.join(self.cache_dir, f"{f_hash}_fuzz_s{min_sz}.cache")

            # 检查缓存
            if os.path.exists(fuzz_cache_path):
                self.log("[*] 发现快速 Fuzz 缓存，加载中...")
                with open(fuzz_cache_path, 'rb') as f:
                    targets = pickle.load(f)
                self.log(f"[+] 缓存中共有 {len(targets)} 个目标函数")
            else:
                # 快速获取所有函数（不构建完整 CFG）
                self.log("[*] 正在枚举所有函数...")
                cfg = proj.analyses.CFGFast()
                all_functions = {}
                for func in cfg.functions.values():
                    if func.size and func.size >= min_sz:  # 使用用户定义的最小函数大小
                        all_functions[func.addr] = {
                            'addr': func.addr,
                            'name': func.name,
                            'size': func.size
                        }

                targets = list(all_functions.values())
                targets.sort(key=lambda x: x['size'])  # 按大小排序

                # DLL 目标：优先导出函数，然后是导出函数调用的内部函数
                if self.is_dll_target:
                    try:
                        pe = pefile.PE(target_path)
                        export_addrs = set()
                        export_names = {}
                        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                                if exp.address:
                                    # 导出地址是 RVA，需要转换为 VA
                                    export_va = exp.address + pe.OPTIONAL_HEADER.ImageBase
                                    export_addrs.add(export_va)
                                    name = exp.name.decode() if exp.name else f"ordinal_{exp.ordinal}"
                                    export_names[export_va] = name
                        pe.close()
                        
                        if export_addrs:
                            # 分析导出函数的调用链
                            self.log("[*] 分析导出函数调用链...", detail_only=True)
                            called_funcs = set()
                            
                            # 遍历 CFG 找出导出函数调用的内部函数
                            for node in cfg.graph.nodes():
                                func_addr = getattr(node, 'function_address', None)
                                if func_addr and func_addr in export_addrs:
                                    # 这是导出函数的节点，找出它调用的函数
                                    for src, dst in cfg.graph.out_edges(node):
                                        dst_func = getattr(dst, 'function_address', None)
                                        if dst_func and dst_func not in export_addrs and dst_func in all_functions:
                                            called_funcs.add(dst_func)
                            
                            # 三级排序：导出函数 → 导出函数调用的函数 → 其他函数
                            export_funcs = [f for f in targets if f['addr'] in export_addrs]
                            called_targets = [f for f in targets if f['addr'] in called_funcs]
                            other_funcs = [f for f in targets if f['addr'] not in export_addrs and f['addr'] not in called_funcs]
                            
                            targets = export_funcs + called_targets + other_funcs
                            
                            self.log(f"[+] 导出函数: {len(export_funcs)} 个 (优先测试)")
                            self.log(f"[+] 导出函数调用的内部函数: {len(called_targets)} 个 (次优先)")
                            self.log(f"[+] 其他函数: {len(other_funcs)} 个", detail_only=True)
                        else:
                            self.log("[!] 未找到导出函数", detail_only=True)
                    except Exception as e:
                        self.log(f"[!] 分析导出函数失败: {e}", detail_only=True)

                # 保存缓存
                with open(fuzz_cache_path, 'wb') as f:
                    pickle.dump(targets, f)
                self.log(f"[+] 已保存函数列表到缓存")

            self.log(f"[+] 找到 {len(targets)} 个函数 (大小 >= {patch_size} bytes)")

            if not targets:
                self.log("[!] 没有符合大小条件的函数可供测试!")
                return

            # 记录目标函数详情
            self.log("=" * 60)
            self.log(f"[*] 目标函数列表 (共 {len(targets)} 个):")
            for i, fn in enumerate(targets):
                self.log(f"    [{i}] {hex(fn['addr'])}: {fn['name']} (size={fn['size']})")
            self.log("=" * 60)

            # 开始 fuzz
            self.log("[*] 开始快速 Fuzz 测试...")
            hits = []
            test_count = len(targets)

            # 启用停止按钮
            self.stop_requested = False
            self.root.after(0, lambda: self.stop_btn.config(state=tk.NORMAL))

            for i, item in enumerate(targets):
                # 检查是否请求停止
                if self.stop_requested:
                    self.log(f"[!] 用户请求停止，已保存当前结果...")
                    break

                addr = item['addr']
                name = item['name']
                size = item['size']

                self.log(f"[#{i+1}/{test_count}] {hex(addr)}: {name} (size={size})")

                patched_file = self.apply_patch(target_path, addr, p_data, f"fuzz_{i}")
                if not patched_file:
                    self.log(f"[!] 补丁失败: {hex(addr)}")
                    continue
                
                self.log(f"[#{i+1}/{test_count}] Testing {name} @ {hex(addr)}")

                delay = float(ui["delay"] or "3.5")
                monitor_names = self._monitor_names(ui["process"])
                try:
                    # DLL 模式：复制 loader exe 到测试目录，测试加载器；EXE 模式直接测补丁文件
                    exe_to_run = patched_file
                    if self.is_dll_target:
                        test_dir = os.path.dirname(patched_file)
                        loader_name = os.path.basename(loader_path)
                        test_loader = os.path.join(test_dir, loader_name)
                        shutil.copy2(loader_path, test_loader)
                        exe_to_run = test_loader

                    # B2：列表 spawn + 轮询 diff 检测 + 进程树整杀
                    hit, new_procs = self._run_spawn_test(exe_to_run, delay, monitor_names)

                    if hit:
                        triggered = ", ".join(sorted(set(new_procs.values())))
                        self.log("log_hit", hex(addr))
                        self.log(f"[!] 触发进程: {triggered}", detail_only=True)
                        hits.append((addr, name, size))
                        self.log(f"[!!!] 命中! 地址={hex(addr)}, 函数={name}, 大小={size}", detail_only=True)
                    else:
                        self.log("log_fail")
                        if ui["auto_delete"]:
                            try:
                                if self.is_dll_target and os.path.exists(os.path.dirname(patched_file)):
                                    shutil.rmtree(os.path.dirname(patched_file))
                                    self.log(f"[-] 已删除测试目录: {os.path.dirname(patched_file)}", detail_only=True)
                                elif os.path.exists(patched_file):
                                    os.remove(patched_file)
                                    self.log(f"[-] 已删除失败文件: {patched_file}", detail_only=True)
                            except Exception as del_e:
                                self.log(f"[!] 删除失败: {str(del_e)}", detail_only=True)
                except Exception as e:
                    self.log(f"[!] 执行错误: {str(e)}", detail_only=True)
                    if ui["auto_delete"]:
                        try:
                            if self.is_dll_target and os.path.exists(os.path.dirname(patched_file)):
                                shutil.rmtree(os.path.dirname(patched_file))
                            elif os.path.exists(patched_file):
                                os.remove(patched_file)
                        except:
                            pass

            # 总结
            self.log("=" * 60)
            self.log(f"[*] 快速 Fuzz 完成!")
            self.log(f"[*] 总共测试: {test_count} 个函数")
            self.log(f"[*] 命中数量: {len(hits)}")
            if hits:
                self.log("[+] 命中详情:")
                for addr, name, size in hits:
                    self.log(f"    size={size} | {hex(addr)}: {name}")
                # 供 SGN Loader 复用：这些函数已验证"会被调用且可安全切分"
                self.fuzz_hits = {"target": target_path, "vas": [h[0] for h in hits]}
                self.log("[+] 命中候选已记录：切到 SGN Loader 模式（VA 留空）即可复用")
            self.log(f"[*] 主日志文件: {log_file}")
            self.log("=" * 60)

        except Exception as e:
            self.log(f"[X] Error: {str(e)}")
            if hasattr(self, 'detail_logger') and self.detail_logger:
                import traceback
                self.detail_logger.error(f"异常详情:\n{traceback.format_exc()}")
        finally:
            self.progress.stop()
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))

    def get_patch_data(self, path):
        if not path or not os.path.exists(path):
            raise Exception("补丁源文件路径无效或不存在")

        if path.lower().endswith(('.exe', '.dll')):
            pe = pefile.PE(path)
            for s in pe.sections:
                if b'.text' in s.Name:
                    data = s.get_data()
                    pe.close()
                    return data
            pe.close()
            raise Exception("无法从 PE 文件中提取 .text 节区")

        with open(path, 'rb') as f:
            return f.read()

    def apply_patch(self, pe_path, va, data, suffix):
        """应用补丁到 PE 文件
        对于 DLL 目标：使用原始文件名，放在测试目录中
        对于 EXE 目标：使用后缀命名
        """
        try:
            pe = pefile.PE(pe_path)
            rva = va - pe.OPTIONAL_HEADER.ImageBase
            offset = None
            section_name = None
            
            for s in pe.sections:
                if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                    offset = rva - s.VirtualAddress + s.PointerToRawData
                    section_name = s.Name.decode().strip('\x00')
                    break

            if offset is None:
                self.log(f"[!] 无法找到 VA {hex(va)} 对应的文件偏移", detail_only=True)
                return None

            # --- B3 边界校验：拒绝越界/不可执行节补丁，避免写坏 PE ---
            IMAGE_SCN_MEM_EXECUTE = 0x20000000
            virt_end = s.VirtualAddress + s.Misc_VirtualSize
            raw_end = s.PointerToRawData + s.SizeOfRawData
            file_size = os.path.getsize(pe_path)
            reasons = []
            if not (s.Characteristics & IMAGE_SCN_MEM_EXECUTE):
                reasons.append(f"目标 VA 所在节 [{section_name}] 不可执行")
            if rva + len(data) > virt_end:
                reasons.append(f"补丁越过节虚拟边界 (需 {len(data)}B, 节内剩余 {virt_end - rva}B)")
            if offset + len(data) > raw_end:
                reasons.append(f"补丁越过节原始数据边界 (offset+{len(data)} > raw_end {hex(raw_end)})")
            if offset + len(data) > file_size:
                reasons.append("补丁越过文件末尾")
            if reasons:
                self.log(f"[!] 补丁被拒绝 @ VA {hex(va)} [{section_name}]: " + "; ".join(reasons))
                pe.close()
                return None

            pe.close()
            
            # DLL 模式：使用原始文件名，放在测试子目录
            if self.is_dll_target:
                test_dir = os.path.join(os.path.dirname(pe_path), f"spy_test_{suffix}")
                os.makedirs(test_dir, exist_ok=True)
                out_name = os.path.join(test_dir, os.path.basename(pe_path))
            else:
                # EXE 模式：使用后缀命名
                out_name = f"{os.path.splitext(pe_path)[0]}_{suffix}{os.path.splitext(pe_path)[1]}"
            
            shutil.copy(pe_path, out_name)
            
            with open(out_name, 'r+b') as f:
                f.seek(offset)
                original_data = f.read(len(data))
                f.seek(offset)
                f.write(data)
            
            self.log(f"[+] 补丁详情: VA={hex(va)}, RVA={hex(rva)}, FileOffset={hex(offset)}, Section={section_name}", detail_only=True)
            self.log(f"[+] 原始数据: {original_data[:32].hex()}...", detail_only=True)
            self.log(f"[+] 补丁数据: {data[:32].hex()}...", detail_only=True)
            
            return out_name
        except Exception as e:
            self.log(f"[!] apply_patch 异常: {str(e)}", detail_only=True)
            return None

if __name__ == "__main__":
    root = ttk.Window(themename="cyborg")  # 使用 cyborg 主题（黑色主体）
    app = BinarySpy(root)
    root.mainloop()
