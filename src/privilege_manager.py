#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
权限管理模块
用于管理系统窗口和进程权限，防止其他程序置顶和限制鼠标
"""

import os
import sys
import time
import logging
import threading
import ctypes
import win32gui
import win32con
import win32process
import win32security
import win32api
import psutil
import re
from ctypes import wintypes
from typing import List, Dict, Set, Tuple, Optional, Any

# 引入windows权限相关常量
PROCESS_ALL_ACCESS = 0x1F0FFF
SE_PRIVILEGE_ENABLED = 0x00000002
TOKEN_ADJUST_PRIVILEGES = 0x00000020
TOKEN_QUERY = 0x00000008

# 定义 TOKEN_PRIVILEGES 结构体
class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]

class PrivilegeManager:
    """权限管理类，用于管理窗口和进程权限"""
    
    # 监控程序的随机进程名特征
    PRZS_PATTERNS = [
        r"^[a-z]{5,6}\.exe$",              # 5-6个小写字母，如"abcde.exe"
        r"^[A-Z]{5,6}\.exe$",              # 5-6个大写字母
        r"^[a-zA-Z]{5,6}\.exe$",           # 5-6个混合大小写字母
        r"^[a-zA-Z]{3,4}[0-9]{2,3}\.exe$", # 3-4个字母后跟2-3个数字
    ]
    
    # 特定程序进程名
    TARGET_PROCESSES = ["jfglzs.exe", "przs.exe", "zmserv.exe", "set.exe"]
    
    def __init__(self):
        """初始化权限管理器"""
        self.logger = logging.getLogger("FreedomTool.PrivilegeManager")
        
        # 检查平台
        if sys.platform != 'win32':
            self.logger.warning("当前不是Windows平台，权限管理功能不可用")
            self.is_windows = False
        else:
            self.is_windows = True
            # 加载Windows API
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
            
            # 设置函数参数和返回类型
            self._setup_win_api()
        
        # 窗口监控相关
        self.window_monitor_thread = None
        self.is_monitoring = False
        self.own_window_handles = set()  # 自己的窗口句柄
        self.topmost_blocked_windows = set()  # 已阻止置顶的窗口
        self.mouse_restriction_blocked = set()  # 已阻止鼠标限制的窗口
        
        # 编译正则表达式
        self.przs_patterns_compiled = [re.compile(pattern) for pattern in self.PRZS_PATTERNS]
        
    def _setup_win_api(self):
        """设置Windows API函数参数和返回类型"""
        if not self.is_windows:
            return
            
        # OpenProcess
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        
        # CloseHandle
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        
        # OpenProcessToken
        self.advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
        ]
        self.advapi32.OpenProcessToken.restype = wintypes.BOOL
        
        # LookupPrivilegeValue
        self.advapi32.LookupPrivilegeValueW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)
        ]
        self.advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
        
        # AdjustTokenPrivileges
        self.advapi32.AdjustTokenPrivileges.argtypes = [
            wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
            wintypes.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD)
        ]
        self.advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
    
    def is_admin(self) -> bool:
        """检查是否具有管理员权限"""
        if not self.is_windows:
            return False
            
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            self.logger.error(f"检查管理员权限时出错: {e}")
            return False
    
    def is_running_as_admin(self) -> bool:
        """检查是否以管理员权限运行（同is_admin，提供兼容性）"""
        return self.is_admin()
    
    def is_running_as_system(self) -> bool:
        """检查是否以System权限运行"""
        if not self.is_windows:
            return False
            
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
            self.logger.error(f"检查System权限时出错: {e}")
            return False
    
    def register_own_window(self, hwnd: int) -> None:
        """注册自己的窗口句柄，以免被误拦截"""
        self.own_window_handles.add(hwnd)
        self.logger.info(f"已注册自己的窗口句柄: {hwnd}")
    
    def enable_privilege(self, privilege_name: str) -> bool:
        """启用特定的系统权限"""
        if not self.is_windows:
            return False
            
        try:
            # 获取当前进程的句柄
            h_process = self.kernel32.OpenProcess(
                PROCESS_ALL_ACCESS, False, win32api.GetCurrentProcessId()
            )
            if not h_process:
                self.logger.error("无法打开当前进程")
                return False
            
            # 获取当前进程的令牌
            h_token = wintypes.HANDLE()
            if not self.advapi32.OpenProcessToken(
                h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)
            ):
                self.logger.error("无法打开进程令牌")
                self.kernel32.CloseHandle(h_process)
                return False
            
            # 查找指定权限的LUID
            luid = LUID()
            if not self.advapi32.LookupPrivilegeValueW(
                None, privilege_name, ctypes.byref(luid)
            ):
                self.logger.error(f"无法查找权限值: {privilege_name}")
                self.kernel32.CloseHandle(h_token)
                self.kernel32.CloseHandle(h_process)
                return False
            
            # 创建TOKEN_PRIVILEGES结构体
            token_privileges = TOKEN_PRIVILEGES()
            token_privileges.PrivilegeCount = 1
            token_privileges.Privileges[0].Luid = luid
            token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            
            # 调整令牌权限
            if not self.advapi32.AdjustTokenPrivileges(
                h_token, False, ctypes.byref(token_privileges), 0, None, None
            ):
                self.logger.error("无法调整令牌权限")
                self.kernel32.CloseHandle(h_token)
                self.kernel32.CloseHandle(h_process)
                return False
            
            # 检查是否有错误（AdjustTokenPrivileges成功不代表权限已经实际启用）
            if ctypes.get_last_error() != 0:
                self.logger.error(f"无法启用权限: {privilege_name}")
                self.kernel32.CloseHandle(h_token)
                self.kernel32.CloseHandle(h_process)
                return False
            
            # 关闭句柄
            self.kernel32.CloseHandle(h_token)
            self.kernel32.CloseHandle(h_process)
            
            self.logger.info(f"成功启用权限: {privilege_name}")
            return True
        except Exception as e:
            self.logger.error(f"启用权限时出错: {e}")
            return False
    
    def is_suspicious_process_name(self, proc_name: str) -> bool:
        """检查进程名是否符合可疑特征"""
        proc_name = proc_name.lower()
        
        # 检查标准目标进程
        for target in self.TARGET_PROCESSES:
            if target.lower() == proc_name:
                return True
        
        # 检查przs随机进程名特征
        for pattern in self.przs_patterns_compiled:
            if pattern.match(proc_name):
                self.logger.info(f"检测到可疑随机名称进程: {proc_name}")
                return True
        
        return False
    
    def get_process_token_info(self, pid: int) -> Dict[str, Any]:
        """获取进程令牌信息"""
        if not self.is_windows:
            return {}
        
        try:
            # 获取进程句柄
            process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            if not process_handle:
                return {}
            
            # 打开进程令牌
            token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_QUERY)
            
            # 获取令牌信息
            token_info = {
                "elevation_type": win32security.GetTokenInformation(token_handle, win32security.TokenElevationType),
                "integrity_level": win32security.GetTokenInformation(token_handle, win32security.TokenIntegrityLevel),
                "groups": win32security.GetTokenInformation(token_handle, win32security.TokenGroups),
                "privileges": win32security.GetTokenInformation(token_handle, win32security.TokenPrivileges),
                "type": win32security.GetTokenInformation(token_handle, win32security.TokenType)
            }
            
            # 关闭句柄
            win32api.CloseHandle(token_handle)
            win32api.CloseHandle(process_handle)
            
            return token_info
        except Exception as e:
            self.logger.error(f"获取进程令牌信息时出错: {e}")
            return {}
    
    def lower_process_privilege(self, pid: int) -> bool:
        """降低进程权限至最低"""
        if not self.is_windows:
            return False
            
        try:
            if not self.enable_privilege("SeDebugPrivilege"):
                self.logger.warning("无法启用SeDebugPrivilege，可能无法降低进程权限")
            
            # 尝试打开进程
            try:
                process_handle = win32api.OpenProcess(
                    win32con.PROCESS_ALL_ACCESS, False, pid
                )
            except Exception as e:
                self.logger.error(f"无法打开进程 {pid}: {e}")
                return False
            
            if not process_handle:
                self.logger.error(f"无法获取进程 {pid} 的句柄")
                return False
            
            # 打开进程令牌
            try:
                token_handle = win32security.OpenProcessToken(
                    process_handle, 
                    win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_ADJUST_GROUPS |
                    win32con.TOKEN_ADJUST_DEFAULT | win32con.TOKEN_QUERY
                )
            except Exception as e:
                self.logger.error(f"无法打开进程令牌: {e}")
                win32api.CloseHandle(process_handle)
                return False
            
            try:
                # 禁用所有权限
                privileges = win32security.GetTokenInformation(
                    token_handle, win32security.TokenPrivileges
                )
                
                for i in range(len(privileges)):
                    # 禁用权限
                    luid = privileges[i][0]
                    win32security.AdjustTokenPrivileges(
                        token_handle, False, [(luid, 0)]
                    )
                
                # 设置低完整性级别
                integrity_sid = win32security.CreateWellKnownSid(
                    win32security.WinLowLabelSid
                )
                win32security.SetTokenInformation(
                    token_handle, 
                    win32security.TokenIntegrityLevel, 
                    integrity_sid
                )
                
                # 关闭句柄
                win32api.CloseHandle(token_handle)
                win32api.CloseHandle(process_handle)
                
                self.logger.info(f"成功降低进程 {pid} 的权限")
                return True
            except Exception as e:
                self.logger.error(f"调整进程权限时出错: {e}")
                win32api.CloseHandle(token_handle)
                win32api.CloseHandle(process_handle)
                return False
        except Exception as e:
            self.logger.error(f"降低进程权限时出错: {e}")
            return False
    
    def prevent_window_topmost(self, hwnd: int) -> bool:
        """阻止窗口置顶"""
        if not self.is_windows:
            return False
            
        try:
            # 检查窗口是否是置顶窗口
            window_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
            is_topmost = (window_style & win32con.WS_EX_TOPMOST) != 0
            
            # 如果是置顶窗口并且不是自己的窗口，取消置顶
            if is_topmost and hwnd not in self.own_window_handles:
                # 取消置顶，设置为非置顶窗口
                win32gui.SetWindowPos(
                    hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0, 
                    win32con.SWP_NOMOVE | win32con.SWP_NOSIZE
                )
                
                # 记录已阻止置顶的窗口
                self.topmost_blocked_windows.add(hwnd)
                window_title = win32gui.GetWindowText(hwnd)
                
                # 获取窗口的进程ID
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                process_name = "未知"
                
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                self.logger.info(f"已阻止窗口置顶: {window_title} (PID: {pid}, 进程: {process_name})")
                return True
                
            return False
        except Exception as e:
            self.logger.error(f"阻止窗口置顶时出错: {e}")
            return False
    
    def free_cursor(self) -> bool:
        """释放鼠标限制"""
        if not self.is_windows:
            return False
            
        try:
            # 调用user32.dll中的ClipCursor函数解除鼠标限制
            user32 = ctypes.WinDLL('user32')
            user32.ClipCursor.argtypes = [ctypes.c_void_p]
            user32.ClipCursor.restype = ctypes.c_bool
            
            # 传入NULL释放鼠标限制
            result = user32.ClipCursor(None)
            
            if result:
                self.logger.info("成功释放鼠标限制")
                return True
            else:
                self.logger.warning("释放鼠标限制失败")
                return False
        except Exception as e:
            self.logger.error(f"释放鼠标限制时出错: {e}")
            return False
    
    def scan_topmost_windows(self) -> List[int]:
        """扫描所有置顶窗口"""
        topmost_windows = []
        
        def enum_windows_callback(hwnd, windows_list):
            # 检查窗口是否可见
            if win32gui.IsWindowVisible(hwnd):
                # 检查窗口是否是置顶窗口
                window_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
                is_topmost = (window_style & win32con.WS_EX_TOPMOST) != 0
                
                if is_topmost:
                    windows_list.append(hwnd)
            return True
        
        try:
            win32gui.EnumWindows(enum_windows_callback, topmost_windows)
            return topmost_windows
        except Exception as e:
            self.logger.error(f"扫描置顶窗口时出错: {e}")
            return []
    
    def scan_target_processes(self) -> Dict[str, List[int]]:
        """扫描目标进程"""
        result = {}
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name']
                    
                    # 检查是否是目标进程
                    if self.is_suspicious_process_name(proc_name):
                        key = proc_name.lower()
                        if key not in result:
                            result[key] = []
                        result[key].append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return result
        except Exception as e:
            self.logger.error(f"扫描目标进程时出错: {e}")
            return {}
    
    def start_window_monitor(self):
        """启动窗口监控线程"""
        if not self.is_windows:
            self.logger.warning("非Windows系统，窗口监控功能不可用")
            return
            
        if self.window_monitor_thread is not None and self.window_monitor_thread.is_alive():
            self.logger.warning("窗口监控线程已经在运行")
            return
        
        self.is_monitoring = True
        self.window_monitor_thread = threading.Thread(target=self._window_monitor_loop, daemon=True)
        self.window_monitor_thread.start()
        self.logger.info("窗口监控线程已启动")
    
    def stop_window_monitor(self):
        """停止窗口监控线程"""
        if self.window_monitor_thread is None or not self.window_monitor_thread.is_alive():
            self.logger.warning("窗口监控线程未运行")
            return
        
        self.is_monitoring = False
        self.window_monitor_thread.join(timeout=2)
        
        if self.window_monitor_thread.is_alive():
            self.logger.warning("窗口监控线程无法正常停止")
        else:
            self.logger.info("窗口监控线程已停止")
    
    def _window_monitor_loop(self):
        """窗口监控循环"""
        while self.is_monitoring:
            try:
                # 扫描置顶窗口并取消置顶
                topmost_windows = self.scan_topmost_windows()
                
                for hwnd in topmost_windows:
                    if hwnd not in self.own_window_handles:
                        self.prevent_window_topmost(hwnd)
                
                # 检查并释放鼠标限制
                self.free_cursor()
                
                # 休眠一段时间
                time.sleep(0.1)  # 100ms
            except Exception as e:
                self.logger.error(f"窗口监控循环时出错: {e}")
                time.sleep(1)  # 出错后等待1秒再继续
    
    def lower_target_processes_privileges(self) -> int:
        """降低所有目标进程的权限"""
        if not self.is_windows:
            return 0
            
        try:
            # 启用调试权限
            self.enable_privilege("SeDebugPrivilege")
            
            # 扫描目标进程
            target_processes = self.scan_target_processes()
            
            # 降低每个目标进程的权限
            processed_count = 0
            
            for proc_name, pid_list in target_processes.items():
                self.logger.info(f"处理目标进程: {proc_name}, 找到 {len(pid_list)} 个实例")
                
                for pid in pid_list:
                    if self.lower_process_privilege(pid):
                        processed_count += 1
            
            return processed_count
        except Exception as e:
            self.logger.error(f"降低目标进程权限时出错: {e}")
            return 0
    
    def analyze_and_handle_przs_process(self) -> Dict[str, Any]:
        """分析并处理przs随机进程名生成逻辑"""
        if not self.is_windows:
            return {"success": False, "error": "非Windows系统"}
            
        try:
            result = {
                "success": True,
                "detected_patterns": [],
                "detected_processes": [],
                "lowered_privileges_count": 0
            }
            
            # 扫描可疑进程
            suspicious_processes = {}
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    proc_name = proc.name().lower()
                    
                    # 检查是否匹配przs随机进程名模式
                    for i, pattern in enumerate(self.przs_patterns_compiled):
                        if pattern.match(proc_name):
                            pattern_info = self.PRZS_PATTERNS[i]
                            if pattern_info not in result["detected_patterns"]:
                                result["detected_patterns"].append(pattern_info)
                            
                            # 收集进程信息
                            proc_info = {
                                "pid": proc.pid,
                                "name": proc.name(),
                                "pattern": pattern_info,
                                "exe": proc.exe() if hasattr(proc, "exe") else "",
                                "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else ""
                            }
                            
                            result["detected_processes"].append(proc_info)
                            
                            # 降低权限
                            if self.lower_process_privilege(proc.pid):
                                result["lowered_privileges_count"] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # 如果发现了przs随机进程，记录并分析它们
            if result["detected_processes"]:
                self.logger.info(f"发现 {len(result['detected_processes'])} 个przs随机名称进程")
                self.logger.info(f"检测到的模式: {', '.join(result['detected_patterns'])}")
                self.logger.info(f"已降低 {result['lowered_privileges_count']} 个进程的权限")
            else:
                self.logger.info("未发现przs随机名称进程")
            
            return result
        except Exception as e:
            self.logger.error(f"分析przs随机进程时出错: {e}")
            return {"success": False, "error": str(e)} 