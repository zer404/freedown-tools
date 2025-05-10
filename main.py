#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
主程序 - 反监控保护系统
集成所有模块，提供用户友好的GUI界面
"""

import os
import sys
import time
import logging
import threading
import ctypes
from typing import Dict, List, Any, Optional

# 确保以管理员权限运行
def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_system():
    """检查是否以System权限运行"""
    try:
        import win32security
        import win32process
        
        # 获取当前进程的令牌
        process_token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32security.TOKEN_QUERY
        )
        
        # 获取令牌用户SID
        user_sid = win32security.GetTokenInformation(
            process_token, 
            win32security.TokenUser
        )[0]
        
        # 获取系统SID
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
        
        # 比较SID
        return user_sid == system_sid
    except Exception as e:
        logger.error(f"检查System权限时出错: {e}")
        return False

def run_as_admin():
    """以管理员权限重启程序"""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )

# 如果不是以管理员权限运行，请求提升
if not is_admin():
    print("此程序需要管理员权限才能完全发挥功能，正在请求提升...")
    run_as_admin()
    sys.exit(0)

# 导入GUI库
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from tkinter.font import Font
import threading

# 导入项目模块
from src.integrated_countermeasure import IntegratedCountermeasure
from src.nsudo_handler import NsudoHandler

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('freedom.log', encoding='utf-8')
    ]
)
logger = logging.getLogger("FreedomProtector")

class LogHandler(logging.Handler):
    """日志处理器，将日志输出到GUI界面"""
    
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget
        
    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.see(tk.END)
            self.text_widget.configure(state='disabled')
        # 在主线程中执行，避免线程问题
        self.text_widget.after(0, append)

class FreedomProtectorApp:
    """自由保护者应用程序类"""
    
    def __init__(self, root):
        """初始化应用程序"""
        self.root = root
        self.root.title("自由保护者 - 反监控系统")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # 设置窗口图标
        try:
            self.root.iconbitmap("resources/icons/shield.ico")
        except:
            pass
        
        # 始终保持在顶层
        self.root.attributes('-topmost', True)
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建样式
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Arial", 10))
        self.style.configure("TLabel", font=("Arial", 10))
        self.style.configure("Header.TLabel", font=("Arial", 12, "bold"))
        self.style.configure("Status.TLabel", font=("Arial", 10, "bold"))
        self.style.configure("Success.TLabel", foreground="green")
        self.style.configure("Warning.TLabel", foreground="orange")
        self.style.configure("Error.TLabel", foreground="red")
        self.style.configure("System.TLabel", foreground="blue", font=("Arial", 10, "bold"))
        
        # 创建标题
        title_frame = ttk.Frame(self.main_frame)
        title_frame.pack(fill=tk.X, pady=10)
        
        title_label = ttk.Label(
            title_frame, 
            text="自由保护者 - 反监控系统", 
            style="Header.TLabel", 
            font=("Arial", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        # 创建状态标签
        self.status_label = ttk.Label(
            title_frame, 
            text="准备就绪", 
            style="Status.TLabel"
        )
        self.status_label.pack(side=tk.RIGHT)
        
        # 创建权限标签和提权按钮框架
        privilege_frame = ttk.Frame(self.main_frame)
        privilege_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 检查当前权限
        self.is_admin = is_admin()
        self.is_system = is_system()
        
        # 添加权限标签
        ttk.Label(
            privilege_frame, 
            text="当前权限:"
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        self.privilege_label = ttk.Label(
            privilege_frame, 
            text=self._get_privilege_text(),
            style=self._get_privilege_style()
        )
        self.privilege_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # 添加提权按钮
        self.elevate_button = ttk.Button(
            privilege_frame, 
            text="提升至System权限",
            command=self.elevate_to_system,
            width=20
        )
        self.elevate_button.pack(side=tk.RIGHT)
        
        # 如果已经是System权限，禁用提权按钮
        if self.is_system:
            self.elevate_button.config(state=tk.DISABLED)
        
        # 创建选项卡
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # 主要功能选项卡
        self.main_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.main_tab, text="主要功能")
        
        # 进程管理选项卡
        self.process_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.process_tab, text="进程管理")
        
        # 窗口管理选项卡
        self.window_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.window_tab, text="窗口管理")
        
        # 高级设置选项卡
        self.settings_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.settings_tab, text="高级设置")
        
        # 日志选项卡
        self.log_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.log_tab, text="日志")
        
        # 创建日志区域
        log_frame = ttk.LabelFrame(self.log_tab, text="程序日志")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(state='disabled')
        
        # 设置日志处理器
        log_handler = LogHandler(self.log_text)
        log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(log_handler)
        
        # 底部区域
        bottom_frame = ttk.Frame(self.main_frame)
        bottom_frame.pack(fill=tk.X, pady=10)
        
        # 初始化反制系统
        try:
            self.countermeasure = IntegratedCountermeasure()
            logger.info("IntegratedCountermeasure 初始化成功")
        except Exception as e:
            logger.error(f"初始化IntegratedCountermeasure时出错: {e}")
            self.countermeasure = None
        
        # 初始化NsudoHandler
        self.nsudo_handler = NsudoHandler()
        
        # 检查当前权限并设置标记
        self.is_admin = is_admin()
        self.is_system = is_system()
        
        logger.info(f"当前权限 - 管理员: {'是' if self.is_admin else '否'}, System: {'是' if self.is_system else '否'}")
        
        # 检查NsudoLC可用性
        nsudo_available = self.nsudo_handler.is_nsudo_available()
        logger.info(f"NSudoLC可用: {'是' if nsudo_available else '否'}")
        if nsudo_available:
            logger.info(f"NSudoLC路径: {self.nsudo_handler.nsudo_path}")
        
        # 注册窗口句柄
        self.root.after(1000, self.register_window_handle)
        
        # 启动状态更新线程
        self.status_thread = threading.Thread(target=self.update_status_loop)
        self.status_thread.daemon = True
        self.status_thread.start()
        
        # 初始化各选项卡的内容
        self.init_main_tab()
        self.init_process_tab()
        self.init_window_tab()
        self.init_settings_tab()
        
        # 退出时清理
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # 打印初始化信息
        logger.info("自由保护者 - 反监控系统已启动")
        logger.info(f"管理员权限: {'是' if self.is_admin else '否'}")
        logger.info(f"System权限: {'是' if self.is_system else '否'}")
        
        # 添加UI状态更新定时器
        self.ui_update_timer = None
        
        # 启动UI状态更新定时器
        self.start_ui_update_timer()
    
    def _get_privilege_text(self):
        """获取权限文本"""
        if self.is_system:
            return "System (最高)"
        elif self.is_admin:
            return "管理员"
        else:
            return "普通用户"
    
    def _get_privilege_style(self):
        """获取权限样式"""
        if self.is_system:
            return "System.TLabel"
        elif self.is_admin:
            return "Success.TLabel"
        else:
            return "Error.TLabel"
    
    def elevate_to_system(self):
        """提升至System权限"""
        try:
            logger.info("开始提升至System权限...")
            
            # 禁用提权按钮
            self.elevate_button.configure(state=tk.DISABLED)
            
            # 如果已经是System权限，直接返回
            if self.is_system:
                messagebox.showinfo("提示", "当前已经以System权限运行，无需提升。")
                self.elevate_button.configure(state=tk.DISABLED)
                return
            
            # 显示提示消息
            messagebox.showinfo(
                "提升权限", 
                "即将使用NsudoLC提升程序至System权限。\n" +
                "提升权限后，当前程序会关闭，新的程序窗口会以System权限启动。\n" +
                "如果NSudoLC尚未下载，程序会先下载它。"
            )
            
            # 检查NsudoLC是否可用
            if not self.nsudo_handler.is_nsudo_available():
                logger.info("NSudoLC不可用，开始下载...")
                
                # 尝试在程序目录中查找NSudoLC
                program_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
                nsudo_path = os.path.join(program_dir, "NSudoLC.exe")
                
                if os.path.exists(nsudo_path) and os.path.isfile(nsudo_path):
                    logger.info(f"在程序目录找到NSudoLC: {nsudo_path}")
                    self.nsudo_handler.nsudo_path = nsudo_path
                else:
                    # 下载NSudoLC
                    download_result = self.nsudo_handler.download_nsudo()
                    if not download_result:
                        messagebox.showerror("错误", "无法下载NSudoLC，提权失败。")
                        self.elevate_button.configure(state=tk.NORMAL)
                        return
                    logger.info("NSudoLC下载成功")
            
            # 使用NsudoLC提升权限
            logger.info(f"使用NSudoLC提升权限，路径: {self.nsudo_handler.nsudo_path}")
            
            # 获取当前脚本参数
            python_exe = sys.executable
            script_path = os.path.abspath(sys.argv[0])
            cmd = f'"{python_exe}" "{script_path}"'
            
            # 提升权限
            self.nsudo_handler.async_elevate_and_exit(cmd)
            
            logger.info("已启动System权限进程，当前程序将自动退出...")
            
            # 提示用户
            messagebox.showinfo(
                "权限提升", 
                "System权限进程已启动，当前程序将退出。"
            )
            
            # 3秒后退出程序
            self.root.after(3000, self.root.destroy)
            
        except Exception as e:
            logger.error(f"提升权限时出错: {e}")
            messagebox.showerror("错误", f"提升权限时出错: {e}")
            self.elevate_button.configure(state=tk.NORMAL)
    
    def register_window_handle(self):
        """注册窗口句柄"""
        try:
            hwnd = self.root.winfo_id()
            if hasattr(self, 'countermeasure') and self.countermeasure is not None:
                self.countermeasure.register_window(hwnd)
                logger.info(f"已注册主窗口句柄: {hwnd}")
            else:
                logger.error("无法注册窗口句柄: countermeasure未初始化")
        except Exception as e:
            logger.error(f"注册窗口句柄时出错: {e}")
    
    def init_main_tab(self):
        """初始化主要功能选项卡"""
        # 状态框架
        status_frame = ttk.LabelFrame(self.main_tab, text="系统状态")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 状态网格
        status_grid = ttk.Frame(status_frame)
        status_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # 添加状态项
        ttk.Label(status_grid, text="运行状态:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.running_status = ttk.Label(status_grid, text="未运行")
        self.running_status.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(status_grid, text="保护状态:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.protection_status = ttk.Label(status_grid, text="未激活")
        self.protection_status.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(status_grid, text="发现目标:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.targets_found = ttk.Label(status_grid, text="0个")
        self.targets_found.grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(status_grid, text="鼠标限制:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.mouse_restricted = ttk.Label(status_grid, text="无")
        self.mouse_restricted.grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        
        # 操作框架
        action_frame = ttk.LabelFrame(self.main_tab, text="操作")
        action_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 按钮框架
        button_frame = ttk.Frame(action_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # 添加主要按钮
        self.start_button = ttk.Button(
            button_frame, 
            text="启动保护", 
            command=self.toggle_protection,
            width=15
        )
        self.start_button.grid(row=0, column=0, padx=5, pady=5)
        
        self.stop_button = ttk.Button(
            button_frame, 
            text="停止保护", 
            command=self.toggle_protection,
            width=15,
            state=tk.DISABLED
        )
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)
        
        self.emergency_button = ttk.Button(
            button_frame, 
            text="紧急解锁", 
            command=self.emergency_unlock,
            width=15
        )
        self.emergency_button.grid(row=0, column=2, padx=5, pady=5)
        
        # 功能框架
        feature_frame = ttk.LabelFrame(self.main_tab, text="功能")
        feature_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 功能列表
        features_list = ttk.Frame(feature_frame)
        features_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 功能列表标题
        ttk.Label(features_list, text="功能", style="Header.TLabel").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(features_list, text="状态", style="Header.TLabel").grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(features_list, text="描述", style="Header.TLabel").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        
        # 添加功能列表项
        features = [
            ("随机进程检测", "已启用", "检测随机命名的进程"),
            ("窗口限制解除", "已启用", "防止窗口锁定和鼠标限制"),
            ("自我复制防护", "已启用", "防止程序自我复制"),
            ("互相监控终止", "已启用", "终止互相监控的进程"),
            ("注册表保护", "已启用", "防止修改注册表限制")
        ]
        
        for i, (feature, status, desc) in enumerate(features, 1):
            ttk.Label(features_list, text=feature).grid(row=i, column=0, sticky=tk.W, padx=5, pady=2)
            ttk.Label(features_list, text=status, style="Success.TLabel").grid(row=i, column=1, sticky=tk.W, padx=5, pady=2)
            ttk.Label(features_list, text=desc).grid(row=i, column=2, sticky=tk.W, padx=5, pady=2)
    
    def init_process_tab(self):
        """初始化进程管理选项卡"""
        # 进程列表框架
        process_frame = ttk.LabelFrame(self.process_tab, text="可疑进程")
        process_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 创建进程表格
        process_frame_inner = ttk.Frame(process_frame)
        process_frame_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建表格
        columns = ("pid", "name", "type", "status", "path")
        self.process_tree = ttk.Treeview(process_frame_inner, columns=columns, show="headings")
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(process_frame_inner, orient=tk.VERTICAL, command=self.process_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        # 设置列标题
        self.process_tree.heading("pid", text="PID")
        self.process_tree.heading("name", text="进程名")
        self.process_tree.heading("type", text="类型")
        self.process_tree.heading("status", text="状态")
        self.process_tree.heading("path", text="路径")
        
        # 设置列宽
        self.process_tree.column("pid", width=50)
        self.process_tree.column("name", width=100)
        self.process_tree.column("type", width=100)
        self.process_tree.column("status", width=80)
        self.process_tree.column("path", width=300)
        
        # 进程操作框架
        process_action_frame = ttk.Frame(self.process_tab)
        process_action_frame.pack(fill=tk.X, pady=5)
        
        # 添加进程操作按钮
        self.terminate_button = ttk.Button(
            process_action_frame, 
            text="终止选中进程", 
            command=self.terminate_selected_process,
            width=15
        )
        self.terminate_button.pack(side=tk.LEFT, padx=5)
        
        self.lower_button = ttk.Button(
            process_action_frame, 
            text="降低进程权限", 
            command=self.lower_selected_process,
            width=15
        )
        self.lower_button.pack(side=tk.LEFT, padx=5)
        
        self.refresh_button = ttk.Button(
            process_action_frame, 
            text="刷新进程列表", 
            command=self.refresh_process_list,
            width=15
        )
        self.refresh_button.pack(side=tk.LEFT, padx=5)
        
        # 关联右键菜单
        self.process_context_menu = tk.Menu(self.root, tearoff=0)
        self.process_context_menu.add_command(label="终止进程", command=self.terminate_selected_process)
        self.process_context_menu.add_command(label="降低权限", command=self.lower_selected_process)
        self.process_context_menu.add_separator()
        self.process_context_menu.add_command(label="刷新", command=self.refresh_process_list)
        
        self.process_tree.bind("<Button-3>", self.show_process_context_menu)

    def show_process_context_menu(self, event):
        """显示进程右键菜单"""
        item = self.process_tree.identify_row(event.y)
        if item:
            self.process_tree.selection_set(item)
            self.process_context_menu.post(event.x_root, event.y_root)
    
    def init_window_tab(self):
        """初始化窗口管理选项卡"""
        # 窗口列表框架
        window_frame = ttk.LabelFrame(self.window_tab, text="可疑窗口")
        window_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 创建窗口表格
        window_frame_inner = ttk.Frame(window_frame)
        window_frame_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建表格
        columns = ("hwnd", "title", "class", "pid", "status")
        self.window_tree = ttk.Treeview(window_frame_inner, columns=columns, show="headings")
        self.window_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(window_frame_inner, orient=tk.VERTICAL, command=self.window_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.window_tree.configure(yscrollcommand=scrollbar.set)
        
        # 设置列标题
        self.window_tree.heading("hwnd", text="句柄")
        self.window_tree.heading("title", text="标题")
        self.window_tree.heading("class", text="类名")
        self.window_tree.heading("pid", text="PID")
        self.window_tree.heading("status", text="状态")
        
        # 设置列宽
        self.window_tree.column("hwnd", width=80)
        self.window_tree.column("title", width=200)
        self.window_tree.column("class", width=150)
        self.window_tree.column("pid", width=50)
        self.window_tree.column("status", width=80)
        
        # 窗口操作框架
        window_action_frame = ttk.Frame(self.window_tab)
        window_action_frame.pack(fill=tk.X, pady=5)
        
        # 添加窗口操作按钮
        self.close_button = ttk.Button(
            window_action_frame, 
            text="关闭选中窗口", 
            command=self.close_selected_window,
            width=15
        )
        self.close_button.pack(side=tk.LEFT, padx=5)
        
        self.hide_button = ttk.Button(
            window_action_frame, 
            text="隐藏选中窗口", 
            command=self.hide_selected_window,
            width=15
        )
        self.hide_button.pack(side=tk.LEFT, padx=5)
        
        self.remove_topmost_button = ttk.Button(
            window_action_frame, 
            text="移除置顶", 
            command=self.remove_topmost_selected_window,
            width=15
        )
        self.remove_topmost_button.pack(side=tk.LEFT, padx=5)
        
        self.refresh_windows_button = ttk.Button(
            window_action_frame, 
            text="刷新窗口列表", 
            command=self.refresh_window_list,
            width=15
        )
        self.refresh_windows_button.pack(side=tk.LEFT, padx=5)
        
        # 关联右键菜单
        self.window_context_menu = tk.Menu(self.root, tearoff=0)
        self.window_context_menu.add_command(label="关闭窗口", command=self.close_selected_window)
        self.window_context_menu.add_command(label="隐藏窗口", command=self.hide_selected_window)
        self.window_context_menu.add_command(label="移除置顶", command=self.remove_topmost_selected_window)
        self.window_context_menu.add_separator()
        self.window_context_menu.add_command(label="刷新", command=self.refresh_window_list)
        
        self.window_tree.bind("<Button-3>", self.show_window_context_menu)
    
    def show_window_context_menu(self, event):
        """显示窗口右键菜单"""
        item = self.window_tree.identify_row(event.y)
        if item:
            self.window_tree.selection_set(item)
            self.window_context_menu.post(event.x_root, event.y_root)
    
    def init_settings_tab(self):
        """初始化高级设置选项卡"""
        # 设置框架
        settings_frame = ttk.Frame(self.settings_tab)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 高级设置
        advanced_frame = ttk.LabelFrame(settings_frame, text="高级设置")
        advanced_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 检查频率设置
        check_frame = ttk.Frame(advanced_frame)
        check_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(check_frame, text="检查频率(秒):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.check_frequency = ttk.Spinbox(check_frame, from_=1, to=60, width=5)
        self.check_frequency.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.check_frequency.set(5)
        
        # 保护选项
        protection_frame = ttk.LabelFrame(settings_frame, text="保护选项")
        protection_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 创建复选框变量
        self.enable_process_check = tk.BooleanVar(value=True)
        self.enable_window_check = tk.BooleanVar(value=True)
        self.enable_registry_check = tk.BooleanVar(value=True)
        self.enable_process_relationships = tk.BooleanVar(value=True)
        self.enable_self_replication = tk.BooleanVar(value=True)
        
        # 添加复选框
        ttk.Checkbutton(
            protection_frame, 
            text="启用随机进程检测", 
            variable=self.enable_process_check
        ).pack(anchor=tk.W, padx=10, pady=2)
        
        ttk.Checkbutton(
            protection_frame, 
            text="启用窗口限制检测", 
            variable=self.enable_window_check
        ).pack(anchor=tk.W, padx=10, pady=2)
        
        ttk.Checkbutton(
            protection_frame, 
            text="启用注册表保护", 
            variable=self.enable_registry_check
        ).pack(anchor=tk.W, padx=10, pady=2)
        
        ttk.Checkbutton(
            protection_frame, 
            text="启用进程关系分析", 
            variable=self.enable_process_relationships
        ).pack(anchor=tk.W, padx=10, pady=2)
        
        ttk.Checkbutton(
            protection_frame, 
            text="启用自我复制检测", 
            variable=self.enable_self_replication
        ).pack(anchor=tk.W, padx=10, pady=2)
        
        # 应用设置按钮
        apply_button = ttk.Button(
            settings_frame, 
            text="应用设置", 
            command=self.apply_settings,
            width=15
        )
        apply_button.pack(side=tk.RIGHT, padx=5, pady=5)
    
    def apply_settings(self):
        """应用设置"""
        try:
            check_frequency = int(self.check_frequency.get())
            logger.info(f"更新检查频率: {check_frequency}秒")
            
            protection_settings = {
                "enable_process_check": self.enable_process_check.get(),
                "enable_window_check": self.enable_window_check.get(),
                "enable_registry_check": self.enable_registry_check.get(),
                "enable_process_relationships": self.enable_process_relationships.get(),
                "enable_self_replication": self.enable_self_replication.get()
            }
            
            # 更新设置
            logger.info(f"更新保护设置: {protection_settings}")
            
            # 显示消息
            messagebox.showinfo("设置", "设置已更新")
            
        except Exception as e:
            logger.error(f"更新设置时出错: {e}")
            messagebox.showerror("错误", f"更新设置时出错: {e}")
    
    def toggle_protection(self):
        """切换保护状态"""
        try:
            # 检查countermeasure是否初始化
            if not hasattr(self, 'countermeasure') or self.countermeasure is None:
                logger.error("切换保护状态失败：反制度量对象未初始化")
                messagebox.showerror("错误", "保护功能未正确初始化")
                return
            
            # 获取当前状态
            current_status = self.countermeasure.get_status()
            is_running = current_status.get('protection_active', False)
            
            if is_running:
                # 停止保护
                logger.info("正在停止保护...")
                self.status_label.config(text="保护状态: 正在停止...", foreground="orange")
                self.root.update()  # 立即更新UI
                
                if self.countermeasure.stop_protection():
                    # 更新UI状态
                    self.status_label.config(text="保护状态: 已停止", foreground="red")
                    self.start_button.config(text="启动保护")
                    messagebox.showinfo("提示", "保护已停止")
                    logger.info("保护已停止")
                else:
                    self.status_label.config(text="保护状态: 停止失败", foreground="red")
                    messagebox.showerror("错误", "保护停止失败")
                    logger.error("保护停止失败")
            else:
                # 启动保护
                logger.info("正在启动保护...")
                self.status_label.config(text="保护状态: 正在启动...", foreground="orange")
                self.root.update()  # 立即更新UI
                
                if self.countermeasure.start_protection():
                    # 更新UI状态
                    self.status_label.config(text="保护状态: 运行中", foreground="green")
                    self.start_button.config(text="停止保护")
                    messagebox.showinfo("提示", "保护已启动")
                    logger.info("保护已启动")
                else:
                    self.status_label.config(text="保护状态: 启动失败", foreground="red")
                    messagebox.showerror("错误", "保护启动失败")
                    logger.error("保护启动失败")
            
            # 强制立即更新UI状态
            self.update_ui_status()
            
        except Exception as e:
            logger.error(f"切换保护状态时出错: {e}")
            messagebox.showerror("错误", f"切换保护状态时出错: {e}")
            # 尝试恢复UI状态
            self.update_ui_status()
    
    def emergency_unlock(self):
        """紧急解锁"""
        try:
            logger.info("执行紧急解锁...")
            
            if hasattr(self, 'countermeasure') and self.countermeasure is not None:
                result = self.countermeasure.emergency_unlock()
                if result:
                    self.update_status_display("紧急解锁成功")
                    logger.info("紧急解锁成功")
                else:
                    self.update_status_display("紧急解锁失败")
                    logger.error("紧急解锁失败")
            else:
                # 尝试使用备用方法解锁
                logger.warning("countermeasure未初始化，尝试使用备用方法解锁")
                self.update_status_display("使用备用方法解锁")
                
                # 在主线程之外创建窗口Freedom对象并尝试解锁
                self.root.after(0, self._backup_emergency_unlock)
        except Exception as e:
            logger.error(f"紧急解锁时出错: {e}")
            self.update_status_display(f"紧急解锁时出错: {e}")
    
    def _backup_emergency_unlock(self):
        """备用紧急解锁方法"""
        try:
            from src.window_freedom import WindowFreedom
            window_freedom = WindowFreedom()
            window_freedom.free_cursor()
            window_freedom.handle_lock_windows()
            logger.info("备用紧急解锁完成")
        except Exception as e:
            logger.error(f"备用紧急解锁时出错: {e}")
    
    def update_status_loop(self):
        """状态更新循环"""
        try:
            while True:
                try:
                    # 获取状态
                    if hasattr(self, 'countermeasure') and self.countermeasure is not None:
                        status = self.countermeasure.get_status()
                        
                        # 在主线程中更新UI
                        self.root.after(0, lambda: self.update_status_display(status))
                    else:
                        # 在主线程中更新基本状态
                        self.root.after(0, lambda: self.update_status_display(None))
                except Exception as e:
                    logger.error(f"获取状态时出错: {e}")
                
                # 5秒后再检查，加快状态更新频率
                time.sleep(5)
        except Exception as e:
            logger.error(f"状态更新循环出错: {e}")
            # 尝试重新启动状态更新循环
            time.sleep(10)
            try:
                threading.Thread(target=self.update_status_loop, daemon=True).start()
                logger.info("状态更新循环已重新启动")
            except Exception as restart_error:
                logger.error(f"重新启动状态更新循环失败: {restart_error}")
    
    def update_status_display(self, status):
        """更新状态显示"""
        try:
            # 更新权限状态
            privilege_text = self._get_privilege_text()
            privilege_style = self._get_privilege_style()
            
            self.privilege_label.configure(text=f"权限: {privilege_text}")
            self.privilege_label.configure(style=privilege_style)
            
            # 如果不是字典而是字符串，显示为消息
            if isinstance(status, str):
                self.status_label.configure(text=status)
                return
                
            # 如果状态为None，显示基本状态
            if status is None:
                self.running_status.configure(text="未初始化", foreground="red")
                self.protection_status.configure(text="未激活", foreground="red")
                self.targets_found.configure(text="N/A")
                self.mouse_restricted.configure(text="未知")
                return
            
            # 更新其他状态信息
            if 'is_running' in status:
                if status['is_running']:
                    self.running_status.configure(text="运行中", foreground="green")
                else:
                    self.running_status.configure(text="未运行", foreground="red")
            
            if 'protection_active' in status:
                if status['protection_active']:
                    self.protection_status.configure(text="已激活", foreground="green")
                else:
                    self.protection_status.configure(text="未激活", foreground="red")
            
            if 'targets_found' in status:
                self.targets_found.configure(text=f"{status['targets_found']}个")
            
            if 'cursor_restricted' in status:
                if status['cursor_restricted']:
                    self.mouse_restricted.configure(text="鼠标状态: 受限", foreground="red")
                else:
                    self.mouse_restricted.configure(text="鼠标状态: 正常", foreground="green")
            
        except Exception as e:
            logger.error(f"更新状态显示时出错: {e}")
    
    def refresh_process_list(self):
        """刷新进程列表"""
        try:
            # 清空现有项
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
            
            # 确保countermeasure存在
            if not hasattr(self, 'countermeasure') or self.countermeasure is None:
                self.process_tree.insert('', 'end', values=('N/A', '反制度量对象未初始化', 'N/A', '未初始化', 'N/A'), tags=('error',))
                self.process_tree.tag_configure('error', background='#FF8888')
                return
            
            # 获取当前状态，并强制扫描进程以获取最新数据
            try:
                # 先触发一次进程扫描以确保数据最新
                if hasattr(self.countermeasure, 'countermeasure_manager'):
                    # 调用扫描方法获取最新进程
                    self.countermeasure.countermeasure_manager.scan_target_processes()
                
                # 获取状态
                status = self.countermeasure.get_status()
                found_targets = status.get('found_targets', [])
                
                # 如果没有找到目标，显示提示信息
                if not found_targets:
                    self.process_tree.insert('', 'end', values=('N/A', '未发现可疑进程', 'N/A', '正常', 'N/A'), tags=('normal',))
                    self.process_tree.tag_configure('normal', background='#CCFFCC')
                    return
                
                # 添加进程项
                for target in found_targets:
                    pid = target.get('pid', '')
                    name = target.get('name', '')
                    type_name = target.get('type', '')
                    status_text = target.get('status', '')
                    path = target.get('path', '')
                    
                    # 为不同类型设置不同颜色
                    if type_name == 'known_target':
                        tags = ('known',)
                    elif type_name == 'random_name':
                        tags = ('random',)
                    elif type_name == 'self_replication':
                        tags = ('replication',)
                    else:
                        tags = ()
                    
                    self.process_tree.insert('', 'end', values=(pid, name, type_name, status_text, path), tags=tags)
                
                # 设置标签颜色
                self.process_tree.tag_configure('known', background='#FFCCCC')
                self.process_tree.tag_configure('random', background='#FFFFCC')
                self.process_tree.tag_configure('replication', background='#CCFFCC')
            
            except Exception as inner_e:
                logger.error(f"获取进程数据时出错: {inner_e}")
                self.process_tree.insert('', 'end', values=('N/A', f'获取进程数据失败: {inner_e}', 'N/A', '错误', 'N/A'), tags=('error',))
                self.process_tree.tag_configure('error', background='#FF8888')
            
        except Exception as e:
            logger.error(f"刷新进程列表时出错: {e}")
            try:
                self.process_tree.insert('', 'end', values=('N/A', f'刷新进程列表错误: {e}', 'N/A', '错误', 'N/A'), tags=('error',))
                self.process_tree.tag_configure('error', background='#FF8888')
            except:
                pass
    
    def refresh_window_list(self):
        """刷新窗口列表"""
        try:
            # 清空现有项
            for item in self.window_tree.get_children():
                self.window_tree.delete(item)
            
            # 检查countermeasure和window_freedom是否有效
            if not hasattr(self, 'countermeasure') or self.countermeasure is None:
                self.window_tree.insert('', 'end', values=('N/A', '反制度量对象未初始化', 'N/A', 'N/A', '错误'), tags=('error',))
                self.window_tree.tag_configure('error', background='#FF8888')
                logger.warning("刷新窗口列表：反制度量对象未初始化")
                return
            
            # 检查并确保window_freedom有效
            if not hasattr(self.countermeasure, 'window_freedom') or self.countermeasure.window_freedom is None:
                try:
                    logger.info("刷新窗口列表：初始化窗口自由模块...")
                    from src.window_freedom import WindowFreedom
                    self.countermeasure.window_freedom = WindowFreedom()
                except Exception as e:
                    logger.error(f"刷新窗口列表：初始化窗口自由模块失败：{e}")
                    # 显示错误信息
                    self.window_tree.insert('', 'end', values=('N/A', '窗口自由模块未初始化', '初始化失败', 'N/A', '错误'), tags=('error',))
                    self.window_tree.tag_configure('error', background='#FF8888')
                    return
            
            # 尝试获取锁定窗口信息
            try:
                # 先强制刷新窗口列表
                try:
                    self.countermeasure.window_freedom.find_lock_windows(force_refresh=True)
                except:
                    pass
                
                # 再获取锁定窗口
                lock_windows = self.countermeasure.window_freedom.find_lock_windows()
                
                # 检查返回值有效性
                if lock_windows is None:
                    logger.warning("刷新窗口列表：find_lock_windows返回None")
                    lock_windows = []
                
                # 添加窗口项
                if not lock_windows:  # 没有锁定窗口
                    self.window_tree.insert('', 'end', values=('N/A', '未发现锁定窗口', 'N/A', 'N/A', '正常'), tags=('normal',))
                    self.window_tree.tag_configure('normal', background='#CCFFCC')
                else:
                    for window in lock_windows:
                        hwnd = window.get('hwnd', '')
                        title = window.get('title', '')
                        class_name = window.get('class', '')
                        pid = window.get('pid', '')
                        status = window.get('status', 'suspicious')
                        
                        # 检查窗口是否仍然存在
                        try:
                            import win32gui
                            if not win32gui.IsWindow(hwnd):
                                continue
                        except:
                            pass
                        
                        # 为不同状态设置不同颜色
                        if status == 'lock':
                            tags = ('lock',)
                        elif status == 'topmost':
                            tags = ('topmost',)
                        else:
                            tags = ('suspicious',)
                        
                        self.window_tree.insert('', 'end', values=(hwnd, title, class_name, pid, status), tags=tags)
                    
                    # 设置标签颜色
                    self.window_tree.tag_configure('lock', background='#FFCCCC')
                    self.window_tree.tag_configure('topmost', background='#FFFFCC')
                    self.window_tree.tag_configure('suspicious', background='#CCFFCC')
            except Exception as e:
                logger.error(f"获取锁定窗口列表时出错: {e}")
                # 显示错误信息
                self.window_tree.insert('', 'end', values=('N/A', f'获取窗口列表失败: {e}', 'N/A', 'N/A', '错误'), tags=('error',))
                self.window_tree.tag_configure('error', background='#FF8888')
            
        except Exception as e:
            logger.error(f"刷新窗口列表时出错: {e}")
            # 尝试显示错误信息
            try:
                self.window_tree.insert('', 'end', values=('N/A', f'刷新窗口列表错误: {e}', 'N/A', 'N/A', '错误'), tags=('error',))
                self.window_tree.tag_configure('error', background='#FF8888')
            except:
                pass
    
    def terminate_selected_process(self):
        """终止选中的进程"""
        try:
            # 获取选中的项
            selected = self.process_tree.selection()
            if not selected:
                messagebox.showinfo("提示", "请先选择一个进程")
                return
            
            # 获取进程信息
            item = self.process_tree.item(selected[0])
            values = item['values']
            
            if values and values[0]:  # 确保PID存在
                pid = int(values[0])
                name = values[1]
                
                # 确认操作
                if messagebox.askyesno("确认", f"确定要终止进程 {name} (PID: {pid}) 吗？"):
                    # 终止进程
                    result = self.countermeasure.terminate_suspicious_process(pid)
                    
                    if result:
                        messagebox.showinfo("成功", f"进程 {name} (PID: {pid}) 已终止")
                        logger.info(f"进程 {name} (PID: {pid}) 已终止")
                        
                        # 刷新进程列表
                        self.refresh_process_list()
                    else:
                        messagebox.showerror("错误", f"终止进程 {name} (PID: {pid}) 失败")
            else:
                messagebox.showinfo("提示", "所选项目没有有效的PID")
                
        except Exception as e:
            logger.error(f"终止进程时出错: {e}")
            messagebox.showerror("错误", f"终止进程时出错: {e}")
    
    def lower_selected_process(self):
        """降低选中进程的权限"""
        try:
            # 获取选中的项
            selected = self.process_tree.selection()
            if not selected:
                messagebox.showinfo("提示", "请先选择一个进程")
                return
            
            # 获取进程信息
            item = self.process_tree.item(selected[0])
            values = item['values']
            
            if values and values[0]:  # 确保PID存在
                pid = int(values[0])
                name = values[1]
                
                # 确认操作
                if messagebox.askyesno("确认", f"确定要降低进程 {name} (PID: {pid}) 的权限吗？"):
                    # 降低进程权限
                    result = self.countermeasure.random_process_analyzer.lower_process_privilege(pid)
                    
                    if result:
                        messagebox.showinfo("成功", f"进程 {name} (PID: {pid}) 的权限已降低")
                        logger.info(f"进程 {name} (PID: {pid}) 的权限已降低")
                        
                        # 刷新进程列表
                        self.refresh_process_list()
                    else:
                        messagebox.showerror("错误", f"降低进程 {name} (PID: {pid}) 的权限失败")
            else:
                messagebox.showinfo("提示", "所选项目没有有效的PID")
                
        except Exception as e:
            logger.error(f"降低进程权限时出错: {e}")
            messagebox.showerror("错误", f"降低进程权限时出错: {e}")
    
    def close_selected_window(self):
        """关闭选中的窗口"""
        try:
            # 获取选中的项
            selected = self.window_tree.selection()
            if not selected:
                messagebox.showinfo("提示", "请先选择一个窗口")
                return
            
            # 获取窗口信息
            item = self.window_tree.item(selected[0])
            values = item['values']
            
            if values and values[0]:  # 确保句柄存在
                hwnd = int(values[0])
                title = values[1]
                
                # 确认操作
                if messagebox.askyesno("确认", f"确定要关闭窗口 \"{title}\" 吗？"):
                    # 关闭窗口
                    result = self.countermeasure.window_freedom.close_window(hwnd)
                    
                    if result:
                        messagebox.showinfo("成功", f"窗口 \"{title}\" 已关闭")
                        logger.info(f"窗口 \"{title}\" 已关闭")
                        
                        # 刷新窗口列表
                        self.refresh_window_list()
                    else:
                        messagebox.showerror("错误", f"关闭窗口 \"{title}\" 失败")
            else:
                messagebox.showinfo("提示", "所选项目没有有效的窗口句柄")
                
        except Exception as e:
            logger.error(f"关闭窗口时出错: {e}")
            messagebox.showerror("错误", f"关闭窗口时出错: {e}")
    
    def hide_selected_window(self):
        """隐藏选中的窗口"""
        try:
            # 获取选中的项
            selected = self.window_tree.selection()
            if not selected:
                messagebox.showinfo("提示", "请先选择一个窗口")
                return
            
            # 获取窗口信息
            item = self.window_tree.item(selected[0])
            values = item['values']
            
            if values and values[0]:  # 确保句柄存在
                hwnd = int(values[0])
                title = values[1]
                
                # 确认操作
                if messagebox.askyesno("确认", f"确定要隐藏窗口 \"{title}\" 吗？"):
                    # 隐藏窗口
                    result = self.countermeasure.window_freedom.hide_window(hwnd)
                    
                    if result:
                        messagebox.showinfo("成功", f"窗口 \"{title}\" 已隐藏")
                        logger.info(f"窗口 \"{title}\" 已隐藏")
                        
                        # 刷新窗口列表
                        self.refresh_window_list()
                    else:
                        messagebox.showerror("错误", f"隐藏窗口 \"{title}\" 失败")
            else:
                messagebox.showinfo("提示", "所选项目没有有效的窗口句柄")
                
        except Exception as e:
            logger.error(f"隐藏窗口时出错: {e}")
            messagebox.showerror("错误", f"隐藏窗口时出错: {e}")
    
    def remove_topmost_selected_window(self):
        """移除选中窗口的置顶属性"""
        try:
            # 获取选中的项
            selected = self.window_tree.selection()
            if not selected:
                messagebox.showinfo("提示", "请先选择一个窗口")
                return
            
            # 获取窗口信息
            item = self.window_tree.item(selected[0])
            values = item['values']
            
            if values and values[0]:  # 确保句柄存在
                hwnd = int(values[0])
                title = values[1]
                
                # 确认操作
                if messagebox.askyesno("确认", f"确定要移除窗口 \"{title}\" 的置顶属性吗？"):
                    # 移除置顶属性
                    result = self.countermeasure.window_freedom.remove_topmost(hwnd)
                    
                    if result:
                        messagebox.showinfo("成功", f"窗口 \"{title}\" 的置顶属性已移除")
                        logger.info(f"窗口 \"{title}\" 的置顶属性已移除")
                        
                        # 刷新窗口列表
                        self.refresh_window_list()
                    else:
                        messagebox.showerror("错误", f"移除窗口 \"{title}\" 的置顶属性失败")
            else:
                messagebox.showinfo("提示", "所选项目没有有效的窗口句柄")
                
        except Exception as e:
            logger.error(f"移除窗口置顶属性时出错: {e}")
            messagebox.showerror("错误", f"移除窗口置顶属性时出错: {e}")
    
    def on_closing(self):
        """窗口关闭处理"""
        try:
            # 检查protection状态
            protection_active = False
            if hasattr(self, 'countermeasure') and self.countermeasure is not None:
                current_status = self.countermeasure.get_status()
                protection_active = current_status.get('protection_active', False)
            
            if protection_active:
                result = messagebox.askyesnocancel(
                    "确认退出", 
                    "保护功能仍在运行中。您希望如何处理？\n\n"
                    "• 是 - 继续在后台运行并最小化到托盘\n"
                    "• 否 - 停止保护并完全退出\n"
                    "• 取消 - 返回程序",
                    icon=messagebox.WARNING
                )
                
                if result is None:  # 取消退出
                    return
                elif result:  # 是，最小化到托盘
                    self.withdraw()
                    # 显示托盘通知
                    if hasattr(self, 'tray_icon'):
                        self.tray_icon.show_notification(
                            "Freedom Tool 仍在运行", 
                            "应用程序已最小化到系统托盘，保护功能仍在运行中。"
                        )
                    return
                else:  # 否，停止保护并退出
                    # 停止保护
                    self.status_label.config(text="保护状态: 正在停止...", foreground="orange")
                    self.root.update()  # 强制更新UI
                    
                    if self.countermeasure.stop_protection():
                        logger.info("退出前已停止保护")
                    else:
                        logger.warning("退出前停止保护失败")
            else:
                # 直接询问是否退出
                if not messagebox.askokcancel("确认退出", "确定要退出应用程序吗？"):
                    return
            
            # 执行资源清理
            logger.info("开始清理资源...")
            
            # 停止UI更新定时器
            if hasattr(self, 'ui_update_timer') and self.ui_update_timer:
                self.ui_update_timer.cancel()
                logger.debug("UI更新定时器已停止")
            
            # 清理countermeasure资源
            if hasattr(self, 'countermeasure') and self.countermeasure is not None:
                try:
                    self.countermeasure.cleanup()
                    logger.info("countermeasure资源已清理")
                except Exception as e:
                    logger.error(f"清理countermeasure资源时出错: {e}")
            
            # 销毁托盘图标
            if hasattr(self, 'tray_icon'):
                try:
                    self.tray_icon.destroy()
                    logger.debug("托盘图标已销毁")
                except Exception as e:
                    logger.error(f"销毁托盘图标时出错: {e}")
            
            # 退出应用
            logger.info("应用程序正常退出")
            self.root.destroy()
            
        except Exception as e:
            logger.error(f"窗口关闭处理时出错: {e}")
            try:
                # 强制退出
                self.root.destroy()
            except:
                pass
    
    def start_ui_update_timer(self):
        """启动UI状态更新定时器，定期更新UI显示"""
        try:
            # 如果已经有定时器在运行，先停止它
            if hasattr(self, 'ui_update_timer') and self.ui_update_timer:
                self.ui_update_timer.cancel()
            
            # 创建新的定时器，每2秒更新一次UI状态
            self.ui_update_timer = threading.Timer(2.0, self.update_ui_status)
            self.ui_update_timer.daemon = True
            self.ui_update_timer.start()
            logger.debug("UI状态更新定时器已启动")
            
        except Exception as e:
            logger.error(f"启动UI状态更新定时器时出错: {e}")
    
    def update_ui_status(self):
        """更新UI状态显示"""
        try:
            # 检查应用是否仍在运行
            if not hasattr(self, 'root') or not self.root:
                logger.debug("应用已关闭，停止UI状态更新")
                return
            
            # 获取当前countermeasure状态
            if hasattr(self, 'countermeasure') and self.countermeasure is not None:
                current_status = self.countermeasure.get_status()
                
                # 更新状态标签
                is_running = current_status.get('protection_active', False)
                if is_running:
                    self.status_label.config(text="保护状态: 运行中", foreground="green")
                    self.start_button.config(text="停止保护")
                else:
                    self.status_label.config(text="保护状态: 已停止", foreground="red")
                    self.start_button.config(text="启动保护")
                
                # 更新发现的目标数量
                targets_found = current_status.get('targets_found', 0)
                self.targets_found.config(text=f"发现目标: {targets_found}")
                
                # 更新鼠标受限状态
                cursor_restricted = current_status.get('cursor_restricted', False)
                if cursor_restricted:
                    self.mouse_restricted.config(text="鼠标状态: 受限", foreground="red")
                else:
                    self.mouse_restricted.config(text="鼠标状态: 正常", foreground="green")
                
                # 刷新进程列表和窗口列表
                if hasattr(self, 'auto_refresh') and self.auto_refresh.get():
                    self.refresh_process_list()
                    self.refresh_window_list()
            
            # 重新启动定时器，继续更新UI
            self.start_ui_update_timer()
            
        except Exception as e:
            logger.error(f"更新UI状态时出错: {e}")
            # 如果发生错误，尝试重新启动定时器
            try:
                self.start_ui_update_timer()
            except:
                pass

def main():
    """主函数"""
    # 创建主窗口
    root = tk.Tk()
    app = FreedomProtectorApp(root)
    
    # 显示主窗口
    root.mainloop()

if __name__ == "__main__":
    main() 