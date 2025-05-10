#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
窗口自由模块
防止窗口锁定和鼠标限制
"""

import os
import sys
import time
import logging
import threading
import ctypes
from ctypes import wintypes
import win32gui
import win32con
import win32process
import win32api
from typing import List, Dict, Tuple, Optional, Set
import traceback
import re
import psutil

# 为兼容性添加LRESULT类型
if not hasattr(wintypes, 'LRESULT'):
    wintypes.LRESULT = ctypes.c_ssize_t

class WindowFreedom:
    """窗口自由类，专门用于反制全屏锁定和鼠标限制"""
    
    # 可能的锁定窗口标题特征
    LOCK_WINDOW_TITLES = ["Form2", "Form4", "机房管理", "禁止", "警告"]
    
    # 锁定窗口类名特征
    LOCK_WINDOW_CLASSES = ["WindowsForms10.Window", "#32770", "Form"]
    
    # 可疑窗口属性
    SUSPICIOUS_WINDOW_FLAGS = {
        "topmost": win32con.WS_EX_TOPMOST,
        "toolwindow": win32con.WS_EX_TOOLWINDOW,
        "noactivate": win32con.WS_EX_NOACTIVATE,
    }
    
    # 锁屏程序的进程名
    LOCK_PROCESS_NAMES = ["przs", "jfglzs", "zmserv"]
    
    # 矩形结构体
    class RECT(ctypes.Structure):
        _fields_ = [
            ("Left", ctypes.c_long),
            ("Top", ctypes.c_long),
            ("Right", ctypes.c_long),
            ("Bottom", ctypes.c_long)
        ]
    
    def __init__(self):
        """初始化窗口自由模块"""
        try:
            # 设置日志
            self.logger = logging.getLogger("WindowFreedom")
            
            # 初始化状态变量
            self.is_monitoring = False
            self.monitoring_thread = None
            self.consecutive_failures = 0
            self.own_window_hwnd = None
            
            # 初始化计数器
            self.monitor_count = 0
            self.emergency_count = 0
            
            # 初始化钩子相关变量
            self.own_keyboard_hook = None
            self.own_mouse_hook = None
            self.hook_protect_thread = None
            self.hook_protection_active = False
            self.hook_check_interval = 1.0  # 检查间隔(秒)
            
            self.logger.info("窗口自由模块初始化完成")
        except Exception as e:
            self.logger.error(f"初始化窗口自由模块时出错: {e}")
            traceback.print_exc()
        
        # 初始化Windows API
        self._setup_win_api()
        
        # 监控线程
        self.monitoring = False
        self.monitor_thread = None
        
        # 已处理的窗口列表
        self.handled_windows = set()
        
        # 自己的窗口句柄
        self.own_window_handles = set()
        
        # 最后检测到锁屏的时间
        self.last_lock_detected_time = 0
        
        # 锁屏计数器
        self.lock_counter = 0
        
        # 鼠标移动监控
        self.last_mouse_pos = (0, 0)
        self.mouse_locked_time = 0
        
        # 初始化时解除光标限制
        self.free_cursor()
    
    def _setup_win_api(self):
        """设置Windows API函数"""
        # 光标限制相关API
        self.GetClipCursor = ctypes.windll.user32.GetClipCursor
        self.GetClipCursor.argtypes = [ctypes.POINTER(self.RECT)]
        self.GetClipCursor.restype = ctypes.c_bool
        
        self.ClipCursor = ctypes.windll.user32.ClipCursor
        self.ClipCursor.argtypes = [ctypes.POINTER(self.RECT)]
        self.ClipCursor.restype = ctypes.c_bool
        
        # 窗口处理相关API
        self.GetWindowLongPtr = ctypes.windll.user32.GetWindowLongPtrW if sys.maxsize > 2**32 else ctypes.windll.user32.GetWindowLongW
        self.GetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int]
        self.GetWindowLongPtr.restype = ctypes.c_ulong
        
        self.SetWindowLongPtr = ctypes.windll.user32.SetWindowLongPtrW if sys.maxsize > 2**32 else ctypes.windll.user32.SetWindowLongW
        self.SetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ulong]
        self.SetWindowLongPtr.restype = ctypes.c_ulong
        
        self.SetWindowPos = ctypes.windll.user32.SetWindowPos
        self.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
        self.SetWindowPos.restype = ctypes.c_bool
        
        # 新增: 显示窗口API
        self.ShowWindow = ctypes.windll.user32.ShowWindow
        self.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        self.ShowWindow.restype = ctypes.c_bool
        
        # 新增: 发送消息API
        self.SendMessage = ctypes.windll.user32.SendMessageW
        self.SendMessage.argtypes = [wintypes.HWND, ctypes.c_uint, wintypes.WPARAM, wintypes.LPARAM]
        self.SendMessage.restype = wintypes.LRESULT
        
        # 新增: 钩子相关API
        self.SetWindowsHookEx = ctypes.windll.user32.SetWindowsHookExW
        self.SetWindowsHookEx.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.HINSTANCE, wintypes.DWORD]
        self.SetWindowsHookEx.restype = wintypes.HHOOK
        
        self.UnhookWindowsHookEx = ctypes.windll.user32.UnhookWindowsHookEx
        self.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
        self.UnhookWindowsHookEx.restype = ctypes.c_bool
        
        # 新增: 获取钩子函数API
        self.GetHookProc = ctypes.windll.kernel32.GetProcAddress
        self.GetHookProc.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
        self.GetHookProc.restype = ctypes.c_void_p
        
        # 新增: 获取模块句柄API
        self.GetModuleHandle = ctypes.windll.kernel32.GetModuleHandleW
        self.GetModuleHandle.argtypes = [wintypes.LPCWSTR]
        self.GetModuleHandle.restype = wintypes.HMODULE
        
        # 鼠标相关API
        self.GetCursorPos = ctypes.windll.user32.GetCursorPos
        self.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        self.GetCursorPos.restype = ctypes.c_bool
        
        self.SetCursorPos = ctypes.windll.user32.SetCursorPos
        self.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
        self.SetCursorPos.restype = ctypes.c_bool
        
        # 屏幕相关API
        self.GetSystemMetrics = ctypes.windll.user32.GetSystemMetrics
        self.GetSystemMetrics.argtypes = [ctypes.c_int]
        self.GetSystemMetrics.restype = ctypes.c_int
        
        # 键盘输入API
        self.keybd_event = ctypes.windll.user32.keybd_event
        self.keybd_event.argtypes = [ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ulong, ctypes.c_void_p]
        
        # 新增: 获取前台窗口API
        self.GetForegroundWindow = ctypes.windll.user32.GetForegroundWindow
        self.GetForegroundWindow.restype = wintypes.HWND
        
        # 新增: 枚举子窗口API
        self.EnumChildWindows = ctypes.windll.user32.EnumChildWindows
        self.EnumChildWindows.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.LPARAM]
        self.EnumChildWindows.restype = ctypes.c_bool
        
        # 线程API
        self.GetCurrentThreadId = ctypes.windll.kernel32.GetCurrentThreadId
        self.GetCurrentThreadId.argtypes = []
        self.GetCurrentThreadId.restype = wintypes.DWORD
        
        # 新增: Post消息API
        self.PostMessageA = ctypes.windll.user32.PostMessageA
        self.PostMessageA.argtypes = [wintypes.HWND, ctypes.c_uint, wintypes.WPARAM, wintypes.LPARAM]
        self.PostMessageA.restype = ctypes.c_bool
        
        # 钩子常量定义
        self.WH_KEYBOARD = 2
        self.WH_KEYBOARD_LL = 13
        self.WH_MOUSE = 7
        self.WH_MOUSE_LL = 14
    
    def free_cursor(self) -> bool:
        """解除鼠标限制"""
        try:
            # 将限制区域设为整个屏幕 (实质上是取消限制)
            screen_width = self.GetSystemMetrics(0)  # SM_CXSCREEN
            screen_height = self.GetSystemMetrics(1)  # SM_CYSCREEN
            
            rect = self.RECT()
            rect.Left = 0
            rect.Top = 0
            rect.Right = screen_width
            rect.Bottom = screen_height
            
            result = self.ClipCursor(ctypes.byref(rect))
            
            if result:
                self.logger.info(f"成功解除鼠标限制 ({screen_width}x{screen_height})")
            else:
                self.logger.error(f"解除鼠标限制失败，错误码: {ctypes.windll.kernel32.GetLastError()}")
            
            # 额外保证：设置鼠标位置为屏幕中心
            center_x = screen_width // 2
            center_y = screen_height // 2
            self.SetCursorPos(center_x, center_y)
            
            return result
        except Exception as e:
            self.logger.error(f"释放鼠标时出错: {e}")
            return False
    
    def get_cursor_clip_rect(self) -> Optional[Tuple[int, int, int, int]]:
        """获取鼠标限制区域"""
        try:
            rect = self.RECT()
            result = self.GetClipCursor(ctypes.byref(rect))
            
            if result:
                return (rect.Left, rect.Top, rect.Right, rect.Bottom)
            else:
                self.logger.error(f"获取鼠标限制区域失败，错误码: {ctypes.windll.kernel32.GetLastError()}")
                return None
        except Exception as e:
            self.logger.error(f"获取鼠标限制区域时出错: {e}")
            return None
    
    def is_cursor_clipped(self) -> bool:
        """检查鼠标是否被限制在区域内"""
        try:
            clip_rect = self.get_cursor_clip_rect()
            
            if not clip_rect:
                return False
                
            left, top, right, bottom = clip_rect
            
            # 获取屏幕尺寸
            screen_width = self.GetSystemMetrics(0)
            screen_height = self.GetSystemMetrics(1)
            
            # 如果限制区域比屏幕小，说明鼠标被限制了
            if (left > 0 or top > 0 or right < screen_width or bottom < screen_height):
                self.logger.info(f"检测到鼠标被限制在区域: {left},{top},{right},{bottom} (屏幕: {screen_width}x{screen_height})")
                return True
            
            return False
        except Exception as e:
            self.logger.error(f"检查鼠标限制时出错: {e}")
            return False
    
    def register_own_window(self, hwnd: int) -> None:
        """注册自己的窗口句柄，避免关闭自己的窗口"""
        self.own_window_handles.add(hwnd)
    
    def find_lock_windows(self, force_refresh=False) -> List[dict]:
        """
        查找可能的锁定窗口
        
        Args:
            force_refresh: 是否强制刷新窗口列表
            
        Returns:
            包含窗口信息的字典列表
        """
        lock_windows = []
        
        def enum_windows_callback(hwnd, lock_windows_list):
            # 跳过自己的窗口
            if hwnd in self.own_window_handles:
                return True
                
            # 获取窗口标题
            title = win32gui.GetWindowText(hwnd)
            
            # 获取窗口类名
            class_name = win32gui.GetClassName(hwnd)
            
            # 检查窗口是否可见
            if not win32gui.IsWindowVisible(hwnd):
                return True
            
            # 检查是否为锁定窗口
            is_lock_window = False
            window_status = "suspicious"
            reason = ""
            
            # 检查标题特征
            for lock_title in self.LOCK_WINDOW_TITLES:
                if lock_title in title:
                    is_lock_window = True
                    window_status = "lock"
                    reason = f"标题包含'{lock_title}'"
                    break
            
            # 检查窗口类名特征
            if not is_lock_window:
                for lock_class in self.LOCK_WINDOW_CLASSES:
                    if lock_class in class_name:
                        # 进一步确认窗口的其他特征
                        style = self.GetWindowLongPtr(hwnd, win32con.GWL_EXSTYLE)
                        if style & win32con.WS_EX_TOPMOST:
                            is_lock_window = True
                            window_status = "topmost"
                            reason = f"类名包含'{lock_class}'且置顶"
                            break
            
            # 特别处理 przs 的 Form4 窗口
            if title == "Form4" or title == "Form2" or "禁止任务管理器" in title:
                is_lock_window = True
                window_status = "lock"
                reason = "przs锁屏窗口"
            
            # 特殊检查：全屏窗口
            if is_lock_window or (not title and class_name in self.LOCK_WINDOW_CLASSES):
                try:
                    # 获取窗口矩形
                    rect = win32gui.GetWindowRect(hwnd)
                    width = rect[2] - rect[0]
                    height = rect[3] - rect[1]
                    
                    # 获取屏幕尺寸
                    screen_width = self.GetSystemMetrics(0)
                    screen_height = self.GetSystemMetrics(1)
                    
                    # 如果窗口是全屏或接近全屏，且是置顶窗口
                    if (width > screen_width * 0.9 and height > screen_height * 0.9):
                        style = self.GetWindowLongPtr(hwnd, win32con.GWL_EXSTYLE)
                        if style & win32con.WS_EX_TOPMOST:
                            is_lock_window = True
                            window_status = "fullscreen"
                            reason = "全屏置顶窗口"
                except Exception:
                    pass
            
            if is_lock_window or force_refresh:
                # 获取窗口所属进程
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                
                # 记录找到的窗口
                if is_lock_window:
                    self.logger.info(f"找到可能的锁定窗口: {title} (类名: {class_name}, 句柄: {hwnd}, PID: {pid})")
                
                # 添加窗口信息到列表
                window_info = {
                    'hwnd': hwnd,
                    'title': title,
                    'class': class_name,
                    'pid': pid,
                    'status': window_status,
                    'reason': reason
                }
                
                lock_windows_list.append(window_info)
            
            return True
        
        # 枚举所有顶级窗口
        try:
            win32gui.EnumWindows(enum_windows_callback, lock_windows)
        except Exception as e:
            self.logger.error(f"枚举窗口时出错: {e}")
        
        # 更新锁屏计数器
        if [w for w in lock_windows if w.get('status') == 'lock']:
            current_time = time.time()
            # 如果5秒内再次检测到锁屏，增加计数器
            if current_time - self.last_lock_detected_time < 5:
                self.lock_counter += 1
                self.logger.warning(f"短时间内多次检测到锁屏，计数: {self.lock_counter}")
            else:
                self.lock_counter = 1
            
            self.last_lock_detected_time = current_time
        
        # 过滤结果(如果不是强制刷新模式，则只返回锁定窗口)
        if not force_refresh:
            lock_windows = [w for w in lock_windows if w.get('status') in ['lock', 'topmost', 'fullscreen']]
            
        return lock_windows
    
    def close_window(self, hwnd: int) -> bool:
        """关闭窗口"""
        try:
            # 检查窗口是否有效
            if not win32gui.IsWindow(hwnd):
                self.logger.warning(f"窗口 {hwnd} 无效")
                return False
                
            # 获取窗口标题
            title = win32gui.GetWindowText(hwnd)
            class_name = win32gui.GetClassName(hwnd)
            
            # 特殊处理Form2和Form4窗口（przs锁屏窗口）
            is_lock_form = (title == "Form2" or title == "Form4" or
                           class_name == "#32770" and ("禁止" in title or title == "警告"))
            
            if is_lock_form:
                self.logger.info(f"检测到przs锁屏窗口: {title} - 尝试特殊处理")
                
                # 尝试方法1: 先解除置顶状态
                self.remove_window_topmost(hwnd)
                
                # 尝试方法2: 最小化窗口
                self.ShowWindow(hwnd, win32con.SW_MINIMIZE)
                time.sleep(0.1)
                
                # 尝试方法3: 发送Alt+F4
                self.SendMessage(hwnd, win32con.WM_SYSCOMMAND, win32con.SC_CLOSE, 0)
                time.sleep(0.2)
                
                # 尝试方法4: 解除鼠标限制
                self.force_free_cursor()
                
                # 检查窗口是否已关闭
                if not win32gui.IsWindow(hwnd):
                    self.logger.info(f"成功关闭przs锁屏窗口: {title}")
                    return True
            
            # 尝试标准方法1: 发送关闭消息
            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            
            # 等待窗口关闭
            for _ in range(10):
                if not win32gui.IsWindow(hwnd):
                    self.logger.info(f"成功关闭窗口: {title} (句柄: {hwnd})")
                    return True
                time.sleep(0.1)
            
            # 如果是przs锁屏窗口且关闭失败，尝试更强的措施
            if is_lock_form and win32gui.IsWindow(hwnd):
                # 强制方法1: 修改窗口样式以尝试解除锁定效果
                style = self.GetWindowLongPtr(hwnd, win32con.GWL_STYLE)
                self.SetWindowLongPtr(hwnd, win32con.GWL_STYLE, 
                                   style & ~win32con.WS_DISABLED & ~win32con.WS_POPUP | win32con.WS_OVERLAPPED)
                
                # 强制方法2: 更强的关闭命令
                self.SendMessage(hwnd, win32con.WM_DESTROY, 0, 0)
                time.sleep(0.2)
                
                # 解除鼠标限制（即使窗口没关闭也要确保鼠标可以移动）
                self.force_free_cursor()
                
                # 再次检查
                if not win32gui.IsWindow(hwnd):
                    self.logger.info(f"使用强制方法关闭锁屏窗口: {title}")
                    return True
            
            # 如果窗口仍然存在，尝试方法2: 强制结束进程
            if win32gui.IsWindow(hwnd):
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                try:
                    # 打开进程
                    handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
                    # 终止进程
                    win32api.TerminateProcess(handle, 0)
                    win32api.CloseHandle(handle)
                    
                    # 确保解除鼠标限制
                    self.force_free_cursor()
                    
                    self.logger.info(f"强制关闭窗口: {title} (句柄: {hwnd}, PID: {pid})")
                    return True
                except Exception as e:
                    self.logger.error(f"强制关闭窗口 {title} 时出错: {e}")
            
            return False
        except Exception as e:
            self.logger.error(f"关闭窗口时出错: {e}")
            return False
    
    def remove_window_topmost(self, hwnd: int) -> bool:
        """移除窗口的置顶属性"""
        try:
            # 获取窗口当前扩展样式
            ex_style = self.GetWindowLongPtr(hwnd, win32con.GWL_EXSTYLE)
            
            # 如果窗口有置顶属性
            if ex_style & win32con.WS_EX_TOPMOST:
                # 移除置顶属性
                self.SetWindowPos(hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0, 
                               win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
                
                # 获取窗口标题
                title = win32gui.GetWindowText(hwnd)
                self.logger.info(f"移除窗口的置顶属性: {title} (句柄: {hwnd})")
                return True
        except Exception as e:
            self.logger.error(f"移除窗口置顶属性时出错: {e}")
        
        return False
    
    def handle_lock_windows(self) -> int:
        """处理锁定窗口，返回处理的窗口数量"""
        try:
            # 查找可能的锁定窗口
            lock_windows = self.find_lock_windows()
            
            if not lock_windows:
                return 0
                
            count = 0
            for window in lock_windows:
                hwnd = window['hwnd']
                
                # 先移除置顶属性
                self.remove_window_topmost(hwnd)
                
                # 如果是已处理过的窗口，但仍然存在，可能需要更强的措施
                if hwnd in self.handled_windows:
                    # 获取窗口标题
                    title = window['title']
                    # 如果是przs的锁屏窗口，尝试更强的措施
                    if title == "Form2" or title == "Form4" or "禁止" in title:
                        self.logger.warning(f"窗口 {title} 已处理过但仍然存在，尝试更强的措施")
                        
                        # 尝试以隐藏方式关闭窗口
                        self.ShowWindow(hwnd, win32con.SW_HIDE)
                        
                        # 修改窗口样式
                        style = self.GetWindowLongPtr(hwnd, win32con.GWL_STYLE)
                        self.SetWindowLongPtr(hwnd, win32con.GWL_STYLE, 
                                          style & ~win32con.WS_VISIBLE & ~win32con.WS_POPUP)
                        
                        # 强制移动窗口到屏幕外
                        self.SetWindowPos(hwnd, win32con.HWND_BOTTOM, -10000, -10000, 1, 1, 
                                       win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE)
                        
                        # 尝试结束进程
                        try:
                            _, pid = win32process.GetWindowThreadProcessId(hwnd)
                            handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
                            win32api.TerminateProcess(handle, 0)
                            win32api.CloseHandle(handle)
                            self.logger.info(f"强制终止进程: PID {pid}")
                        except Exception as e:
                            self.logger.error(f"终止进程时出错: {e}")
                
                # 关闭窗口
                if self.close_window(hwnd):
                    count += 1
                    self.handled_windows.add(hwnd)
                
                # 解除鼠标限制
                self.free_cursor()
            
            # 如果检测到多次锁屏（可能是przs反复启动锁屏），尝试更强的措施
            if self.lock_counter > 3:
                self.logger.warning(f"检测到持续的锁屏行为 (计数: {self.lock_counter})，尝试终止相关进程")
                
                # 收集锁屏窗口的进程ID
                lock_pids = set()
                for window in lock_windows:
                    _, pid = win32process.GetWindowThreadProcessId(window['hwnd'])
                    lock_pids.add(pid)
                
                # 终止这些进程
                for pid in lock_pids:
                    try:
                        handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
                        win32api.TerminateProcess(handle, 0)
                        win32api.CloseHandle(handle)
                        self.logger.info(f"强制终止锁屏相关进程: PID {pid}")
                    except Exception as e:
                        self.logger.error(f"终止进程 {pid} 时出错: {e}")
                
                # 检查przs相关进程
                self._terminate_przs_processes()
                
                # 重置计数器
                self.lock_counter = 0
            
            # 检查窗口处理的有效性
            if count > 0:
                # 等待窗口关闭
                time.sleep(0.2)
                
                # 再次检查锁定窗口
                remaining_windows = self.find_lock_windows()
                
                # 如果仍有锁定窗口，尝试更强的措施
                if remaining_windows:
                    self.logger.warning(f"仍有 {len(remaining_windows)} 个锁定窗口，尝试更强的措施")
                    
                    # 记录连续失败次数
                    consecutive_failures = 0
                    
                    # 对每个窗口尝试多种方法
                    for window in remaining_windows:
                        # 先尝试除去置顶状态
                        self.remove_window_topmost(window['hwnd'])
                        # 然后尝试关闭
                        if not self.close_window(window['hwnd']):
                            consecutive_failures += 1
                        else:
                            count += 1
                    
                    # 如果有多个连续失败，尝试更强的措施
                    if consecutive_failures > 1:
                        self.force_free_cursor()
                        self._terminate_przs_processes()
            
            return count
        except Exception as e:
            self.logger.error(f"处理锁定窗口时出错: {e}")
            return 0
    
    def prevent_screen_locking(self) -> bool:
        """防止屏幕锁定，主动解除przs锁屏窗口"""
        try:
            # 检查是否有锁定窗口
            lock_windows = self.find_lock_windows()
            if not lock_windows:
                return True  # 没有锁定窗口，不需要处理
            
            # 处理锁定窗口
            for window in lock_windows:
                hwnd = window['hwnd']
                self.close_window(hwnd)
            
            # 只有当检测到鼠标被限制时才解除
            if self.is_cursor_clipped():
                self.logger.info("在处理锁定窗口后检测到鼠标仍被限制，尝试解除")
                self.free_cursor()
            
            return True
        except Exception as e:
            self.logger.error(f"防止屏幕锁定时出错: {e}")
            return False
    
    def disable_lock_timers(self) -> bool:
        """
        尝试禁用przs使用的定时器，避免锁屏机制生效
        przs使用Timer_frm2/Timer_frm4/Timer_main等定时器控制锁屏
        """
        try:
            # 明确的przs计时器名称（从Form1.cs和Form4.cs中分析得到）
            przs_timer_names = [
                "Timer_frm2",    # Form2中的计时器
                "Timer_frm4",    # Form4中的计时器
                "Timer_main",    # 主计时器
                "Timer1",        # 用于监控jfglzs.exe
                "Timer2",        # 用于显示Form2
                "Timer4"         # 用于控制Form4
            ]
            
            # 更精确的计时器模式匹配
            timer_patterns = [
                re.compile(r'Timer_frm[24]', re.IGNORECASE),   # Timer_frm2, Timer_frm4
                re.compile(r'Timer_main', re.IGNORECASE),     # Timer_main
                re.compile(r'Timer[1-4]$', re.IGNORECASE)     # Timer1, Timer2, Timer3, Timer4
            ]
            
            # 窗口标题匹配
            form_titles = ["Form1", "Form2", "Form4", "机房管理"]
            
            timers_disabled = 0
            windows_processed = 0
            
            # 查找可疑进程
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name'].lower()
                    # 判断是否为przs相关进程
                    if any(name in proc_name for name in self.LOCK_PROCESS_NAMES) or \
                       (proc_name.endswith('.exe') and len(proc_name) <= 9 and 
                        (len(proc_name[:-4]) == 4 or (len(proc_name[:-4]) == 5 and all(c in 'klmnopqr' for c in proc_name[:-4])))):
                        
                        pid = proc.info['pid']
                        self.logger.info(f"发现可疑进程 {proc_name} (PID: {pid})，尝试禁用其计时器")
                        
                        # 枚举此进程的所有窗口
                        def enum_windows_proc(hwnd, _):
                            nonlocal timers_disabled, windows_processed
                            try:
                                # 检查窗口是否属于目标进程
                                _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                                if found_pid != pid:
                                    return True
                                
                                # 获取窗口标题和类名
                                window_title = win32gui.GetWindowText(hwnd)
                                class_name = win32gui.GetClassName(hwnd)
                                
                                # 检查是否匹配Form窗口
                                if any(title in window_title for title in form_titles) or class_name == "WindowsForms10.Window.8.app.0.378734a":
                                    windows_processed += 1
                                    self.logger.info(f"发现窗口: {window_title} (类名: {class_name})")
                                    
                                    # 尝试禁用所有可能的计时器
                                    for timer_name in przs_timer_names:
                                        try:
                                            # 发送WM_KILLTIMER消息
                                            # 尝试不同的定时器ID（0-10）
                                            for timer_id in range(11):
                                                result = self.SendMessage(hwnd, win32con.WM_KILLTIMER, timer_id, 0)
                                                if result:
                                                    timers_disabled += 1
                                                    self.logger.info(f"已禁用窗口 {window_title} 中的计时器ID: {timer_id}")
                                        except Exception as e:
                                            self.logger.error(f"禁用计时器 {timer_name} 时出错: {e}")
                                    
                                    # 尝试特殊处理 - PostMessage模拟计时器触发后关闭
                                    try:
                                        # 尝试发送WM_CLOSE
                                        self.SendMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                                        
                                        # 尝试发送ESC键
                                        self.SendMessage(hwnd, win32con.WM_KEYDOWN, win32con.VK_ESCAPE, 0)
                                        self.SendMessage(hwnd, win32con.WM_KEYUP, win32con.VK_ESCAPE, 0)
                                    except Exception as e:
                                        self.logger.error(f"模拟关闭窗口时出错: {e}")
                                
                                return True  # 继续枚举
                            except Exception as e:
                                self.logger.error(f"处理窗口时出错: {e}")
                                return True
                        
                        # 枚举所有窗口
                        win32gui.EnumWindows(enum_windows_proc, None)
                        
                except Exception as e:
                    self.logger.error(f"处理进程计时器时出错: {e}")
            
            # 返回是否成功禁用了计时器
            if timers_disabled > 0:
                self.logger.info(f"成功禁用 {timers_disabled} 个计时器，处理了 {windows_processed} 个窗口")
                return True
            elif windows_processed > 0:
                self.logger.info(f"处理了 {windows_processed} 个窗口，但未成功禁用计时器")
                return False
            else:
                self.logger.info("未找到可疑窗口或计时器")
                return False
                
        except Exception as e:
            self.logger.error(f"禁用锁定计时器时出错: {e}")
            return False
    
    def disable_hotkeys(self):
        """禁用危险的系统热键，如Alt+F4"""
        try:
            # 这部分需要根据实际需要添加
            pass
        except Exception as e:
            self.logger.error(f"禁用热键时出错: {e}")
    
    def start_monitoring(self):
        """启动监控线程"""
        if self.monitoring:
            self.logger.warning("监控线程已经在运行")
            return
            
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # 同时启动钩子保护
        self.start_hook_protection()
        
        self.logger.info("窗口监控线程已启动")
    
    def stop_monitoring(self):
        """停止监控线程"""
        if not self.monitoring:
            return
            
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(2.0)  # 等待最多2秒
            self.monitor_thread = None
        
        # 停止钩子保护
        self.stop_hook_protection()
            
        self.logger.info("窗口监控线程已停止")
    
    def _monitoring_loop(self):
        """监控循环"""
        consecutive_failures = 0
        last_cursor_check_time = 0
        
        while self.monitoring:
            try:
                current_time = time.time()
                
                # 控制鼠标检查和解除的频率，至少间隔30秒
                if current_time - last_cursor_check_time >= 30:
                    # 检查鼠标是否被限制
                    cursor_clipped = self.is_cursor_clipped()
                    
                    # 检查鼠标是否卡住
                    mouse_stuck = self.is_mouse_stuck()
                    
                    # 如果鼠标被限制或卡住，尝试解除
                    if cursor_clipped or mouse_stuck:
                        self.logger.info(f"检测到鼠标问题: 限制={cursor_clipped}, 卡住={mouse_stuck}")
                        if not self.force_free_cursor():
                            consecutive_failures += 1
                        else:
                            consecutive_failures = 0
                            self.logger.info("成功解除鼠标限制")
                    
                    last_cursor_check_time = current_time
                
                # 处理锁定窗口 - 这个可以每次循环都检查
                lock_windows = self.find_lock_windows()
                if lock_windows:
                    for hwnd in lock_windows:
                        # 先尝试除去置顶状态
                        self.remove_window_topmost(hwnd['hwnd'])
                        # 然后尝试关闭
                        if not self.close_window(hwnd['hwnd']):
                            consecutive_failures += 1
                        else:
                            consecutive_failures = 0
                            # 无论是否成功关闭窗口，都要确保解除鼠标限制
                            if current_time - last_cursor_check_time >= 30:
                                self.force_free_cursor()
                                last_cursor_check_time = current_time
                else:
                    # 无锁定窗口时重置连续失败计数
                    consecutive_failures = 0
                
                # 如果连续失败次数过多，可能是遇到了顽固的锁定
                if consecutive_failures >= 3:
                    self.logger.warning(f"连续 {consecutive_failures} 次解锁失败，采取更强措施")
                    # 尝试发送更多组合键
                    self.emergency_unlock()
                    consecutive_failures = 0
                
                # 如果短时间内频繁检测到锁屏，增加检查频率
                if self.lock_counter > 5:
                    time.sleep(0.2)  # 高频检查
                else:
                    time.sleep(0.5)  # 正常频率
                
            except Exception as e:
                self.logger.error(f"监控循环中出错: {e}")
                time.sleep(1.0)  # 出错时稍微延长间隔
    
    def emergency_unlock(self) -> bool:
        """紧急解锁，用于处理顽固的锁屏情况"""
        try:
            self.logger.warning("执行紧急解锁程序")
            
            # 解除所有鼠标限制
            self.force_free_cursor()
            
            # 重置鼠标位置到中心
            screen_width = self.GetSystemMetrics(0)
            screen_height = self.GetSystemMetrics(1)
            self.SetCursorPos(screen_width // 2, screen_height // 2)
            
            # 尝试Alt+Tab切换窗口
            self.keybd_event(0x12, 0, 0, 0)      # ALT按下
            time.sleep(0.1)
            self.keybd_event(0x09, 0, 0, 0)      # TAB按下
            time.sleep(0.1)
            self.keybd_event(0x09, 0, 2, 0)      # TAB释放
            time.sleep(0.1)
            self.keybd_event(0x12, 0, 2, 0)      # ALT释放
            
            # 尝试Ctrl+Alt+Del (在Windows中会打断大多数程序)
            self.keybd_event(0x11, 0, 0, 0)      # CTRL按下
            self.keybd_event(0x12, 0, 0, 0)      # ALT按下
            self.keybd_event(0x2E, 0, 0, 0)      # DEL按下
            time.sleep(0.1)
            self.keybd_event(0x2E, 0, 2, 0)      # DEL释放
            self.keybd_event(0x12, 0, 2, 0)      # ALT释放
            self.keybd_event(0x11, 0, 2, 0)      # CTRL释放
            
            # 尝试Win+D显示桌面
            self.keybd_event(0x5B, 0, 0, 0)      # Win按下
            self.keybd_event(0x44, 0, 0, 0)      # D按下
            time.sleep(0.1)
            self.keybd_event(0x44, 0, 2, 0)      # D释放
            self.keybd_event(0x5B, 0, 2, 0)      # Win释放
            
            # 强制关闭所有疑似锁屏窗口
            lock_windows = self.find_lock_windows()
            for hwnd in lock_windows:
                self.close_window(hwnd['hwnd'])
            
            # 再次检查鼠标限制
            if self.is_cursor_clipped():
                self.force_free_cursor()
                return False
            else:
                self.logger.info("紧急解锁成功")
                return True
                
        except Exception as e:
            self.logger.error(f"紧急解锁时出错: {e}")
            return False
    
    def cleanup(self):
        """清理资源"""
        try:
            self.logger.info("清理窗口自由模块资源...")
            
            # 停止监控线程
            if hasattr(self, 'is_monitoring') and self.is_monitoring:
                self.stop_monitoring()
            
            # 停止钩子保护
            if hasattr(self, 'hook_protection_active') and self.hook_protection_active:
                self.stop_hook_protection()
                
            # 解除光标限制
            self.free_cursor()
            
            self.logger.info("窗口自由模块资源清理完成")
            return True
        except Exception as e:
            self.logger.error(f"清理窗口自由模块资源时出错: {e}")
            return False
    
    def force_free_cursor(self) -> bool:
        """强制解除鼠标限制，针对przs的顽固限制"""
        try:
            # 尝试多种方法解除限制
            
            # 先尝试标准方法
            success = self.free_cursor()
            
            # 卸载所有键盘鼠标钩子
            self.unhook_keyboard_mouse()
            
            # 如果失败，尝试发送Alt+Tab组合键，切换窗口
            if not success or self.is_cursor_clipped():
                self.logger.info("标准方法失败，尝试发送Alt+Tab组合键解除锁定")
                # 按下Alt键
                self.keybd_event(0x12, 0, 0, 0)  # ALT键
                # 按下Tab键
                self.keybd_event(0x09, 0, 0, 0)  # TAB键
                # 释放Tab键
                self.keybd_event(0x09, 0, 2, 0)
                # 释放Alt键
                self.keybd_event(0x12, 0, 2, 0)
                
                time.sleep(0.1)
                
                # 再次尝试解除限制
                success = self.free_cursor()
                
                # 再次卸载钩子
                self.unhook_keyboard_mouse()
            
            # 如果还是失败，尝试发送Escape键
            if not success or self.is_cursor_clipped():
                self.logger.info("尝试发送Escape键解除锁定")
                self.keybd_event(0x1B, 0, 0, 0)  # ESC键
                self.keybd_event(0x1B, 0, 2, 0)
                
                time.sleep(0.1)
                
                # 再次尝试解除限制
                success = self.free_cursor()
                
                # 再次卸载钩子
                self.unhook_keyboard_mouse()
            
            return success
        except Exception as e:
            self.logger.error(f"强制释放鼠标时出错: {e}")
            return False
            
    def unhook_keyboard_mouse(self) -> bool:
        """卸载所有键盘和鼠标钩子"""
        try:
            self.logger.info("尝试卸载所有键盘和鼠标钩子")
            
            # 定义钩子类型常量
            WH_KEYBOARD = 2
            WH_KEYBOARD_LL = 13
            WH_MOUSE = 7
            WH_MOUSE_LL = 14
            
            # 当前线程ID
            current_thread_id = self.GetCurrentThreadId()
            
            # 枚举所有可能的钩子
            hook_types = [WH_KEYBOARD, WH_KEYBOARD_LL, WH_MOUSE, WH_MOUSE_LL]
            hook_names = ["键盘", "低级键盘", "鼠标", "低级鼠标"]
            
            unhooked_count = 0
            
            # 尝试枚举并卸载钩子
            for i, hook_type in enumerate(hook_types):
                try:
                    # 我们需要很大的线程ID范围来确保找到所有钩子
                    for thread_id in range(0, 10000, 4):
                        try:
                            # 尝试获取钩子句柄 (不确定能成功，因为这是Microsoft内部API)
                            hook_handle = ctypes.windll.user32.GetWindowsHookExA(hook_type, None, None, thread_id)
                            
                            # 如果成功获取钩子句柄，尝试卸载
                            if hook_handle:
                                if self.UnhookWindowsHookEx(hook_handle):
                                    unhooked_count += 1
                                    self.logger.info(f"成功卸载{hook_names[i]}钩子 (线程ID: {thread_id})")
                        except:
                            pass
                except Exception as e:
                    self.logger.error(f"尝试卸载{hook_names[i]}钩子时出错: {e}")
            
            if unhooked_count > 0:
                self.logger.info(f"成功卸载了 {unhooked_count} 个钩子")
                return True
            else:
                self.logger.warning("未找到可卸载的钩子")
                
            # 尝试使用WinAPI发送全局钩子卸载消息
            try:
                # 广播WM_CANCELMODE消息，可能帮助释放鼠标捕获
                self.PostMessageA(win32con.HWND_BROADCAST, win32con.WM_CANCELMODE, 0, 0)
                self.logger.info("已发送全局取消捕获消息")
                
                # 重置系统级鼠标捕获
                result = ctypes.windll.user32.ReleaseCapture()
                if result:
                    self.logger.info("成功释放系统级鼠标捕获")
                    return True
            except Exception as e:
                self.logger.error(f"尝试释放系统级捕获时出错: {e}")
            
            return unhooked_count > 0
        except Exception as e:
            self.logger.error(f"卸载键盘鼠标钩子时出错: {e}")
            return False
    
    def unhook_process_hooks(self, pid):
        """卸载指定进程的键盘鼠标钩子"""
        try:
            self.logger.info(f"尝试卸载进程PID {pid}的键盘鼠标钩子")
            
            unhooked = False
            
            # 获取进程的所有线程ID
            try:
                process = psutil.Process(pid)
                thread_ids = [thread.id for thread in process.threads()]
                
                self.logger.debug(f"进程 {pid} 有 {len(thread_ids)} 个线程")
                
                # 尝试卸载每个线程的钩子
                for thread_id in thread_ids:
                    # 尝试针对每种钩子类型卸载
                    hook_types = [self.WH_KEYBOARD, self.WH_KEYBOARD_LL, self.WH_MOUSE, self.WH_MOUSE_LL]
                    hook_names = ["键盘", "低级键盘", "鼠标", "低级鼠标"]
                    
                    for i, hook_type in enumerate(hook_types):
                        try:
                            # 尝试获取钩子句柄
                            hook_handle = ctypes.windll.user32.GetWindowsHookExA(hook_type, None, None, thread_id)
                            
                            # 如果成功获取钩子句柄，尝试卸载
                            if hook_handle:
                                if self.UnhookWindowsHookEx(hook_handle):
                                    unhooked = True
                                    self.logger.info(f"成功卸载进程 {pid} 线程 {thread_id} 的{hook_names[i]}钩子")
                        except:
                            pass
            except Exception as e:
                self.logger.error(f"获取进程 {pid} 线程时出错: {e}")
            
            return unhooked
        except Exception as e:
            self.logger.error(f"卸载进程 {pid} 钩子时出错: {e}")
            return False
    
    def _keyboard_hook_proc(self, nCode, wParam, lParam):
        """自定义键盘钩子回调函数"""
        # 这里可以添加键盘事件处理逻辑
        # 返回调用下一个钩子
        return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)
    
    def _mouse_hook_proc(self, nCode, wParam, lParam):
        """自定义鼠标钩子回调函数"""
        # 这里可以添加鼠标事件处理逻辑
        # 返回调用下一个钩子
        return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)
    
    def start_hook_protection(self):
        """启动钩子保护，循环创建自己的钩子并卸载恶意钩子"""
        if self.hook_protection_active:
            self.logger.warning("钩子保护已经在运行")
            return
        
        self.hook_protection_active = True
        self.hook_protect_thread = threading.Thread(target=self._hook_protection_loop)
        self.hook_protect_thread.daemon = True
        self.hook_protect_thread.start()
        
        self.logger.info("已启动钩子保护线程")
    
    def stop_hook_protection(self):
        """停止钩子保护"""
        if not self.hook_protection_active:
            return
        
        self.hook_protection_active = False
        if self.hook_protect_thread:
            self.hook_protect_thread.join(2.0)
            self.hook_protect_thread = None
        
        # 移除我们自己的钩子
        self._remove_own_hooks()
        
        self.logger.info("已停止钩子保护线程")
    
    def _hook_protection_loop(self):
        """钩子保护循环，定期创建自己的钩子并卸载其他钩子"""
        self.logger.info("钩子保护循环开始运行")
        
        # 钩子处理函数类型
        HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p)
        
        # 创建键盘和鼠标钩子回调函数
        self._c_keyboard_hook = HOOKPROC(self._keyboard_hook_proc)
        self._c_mouse_hook = HOOKPROC(self._mouse_hook_proc)
        
        while self.hook_protection_active:
            try:
                # 1. 移除所有现有钩子
                self.unhook_keyboard_mouse()
                
                # 2. 创建我们自己的钩子
                self._create_own_hooks()
                
                # 3. 等待一段时间
                time.sleep(self.hook_check_interval)
                
            except Exception as e:
                self.logger.error(f"钩子保护循环出错: {e}")
                time.sleep(1.0)  # 出错后稍微等待
    
    def _create_own_hooks(self):
        """创建我们自己的键盘和鼠标钩子"""
        try:
            # 移除旧钩子(如果存在)
            self._remove_own_hooks()
            
            # 获取当前线程ID
            thread_id = self.GetCurrentThreadId()
            
            # 获取当前模块句柄
            module_handle = self.GetModuleHandle(None)
            
            # 创建键盘钩子
            self.own_keyboard_hook = self.SetWindowsHookEx(
                self.WH_KEYBOARD_LL,  # 低级键盘钩子
                self._c_keyboard_hook,
                module_handle,
                0  # 0表示全局钩子
            )
            
            # 创建鼠标钩子
            self.own_mouse_hook = self.SetWindowsHookEx(
                self.WH_MOUSE_LL,  # 低级鼠标钩子
                self._c_mouse_hook,
                module_handle,
                0  # 0表示全局钩子
            )
            
            if self.own_keyboard_hook and self.own_mouse_hook:
                self.logger.debug("成功创建自己的键盘和鼠标钩子")
                return True
            else:
                self.logger.warning(f"创建钩子失败 - 键盘钩子: {bool(self.own_keyboard_hook)}, 鼠标钩子: {bool(self.own_mouse_hook)}")
                return False
        except Exception as e:
            self.logger.error(f"创建自己的钩子时出错: {e}")
            return False
    
    def _remove_own_hooks(self):
        """移除我们自己创建的钩子"""
        try:
            success = True
            
            # 移除键盘钩子
            if self.own_keyboard_hook:
                try:
                    if self.UnhookWindowsHookEx(self.own_keyboard_hook):
                        self.logger.debug("成功移除自己的键盘钩子")
                    else:
                        self.logger.warning("移除自己的键盘钩子失败")
                        success = False
                except Exception as e:
                    self.logger.error(f"移除键盘钩子时出错: {e}")
                    success = False
                finally:
                    self.own_keyboard_hook = None
            
            # 移除鼠标钩子
            if self.own_mouse_hook:
                try:
                    if self.UnhookWindowsHookEx(self.own_mouse_hook):
                        self.logger.debug("成功移除自己的鼠标钩子")
                    else:
                        self.logger.warning("移除自己的鼠标钩子失败")
                        success = False
                except Exception as e:
                    self.logger.error(f"移除鼠标钩子时出错: {e}")
                    success = False
                finally:
                    self.own_mouse_hook = None
            
            return success
        except Exception as e:
            self.logger.error(f"移除自己的钩子时出错: {e}")
            return False
    
    def is_mouse_stuck(self) -> bool:
        """检测鼠标是否被卡住（位置长时间不变）"""
        try:
            point = wintypes.POINT()
            if self.GetCursorPos(ctypes.byref(point)):
                current_pos = (point.x, point.y)
                
                # 检查位置是否变化
                if current_pos == self.last_mouse_pos:
                    # 如果鼠标位置没变，检查时间
                    if self.mouse_locked_time == 0:
                        self.mouse_locked_time = time.time()
                    elif time.time() - self.mouse_locked_time > 3.0:  # 3秒不动认为卡住
                        self.logger.warning(f"检测到鼠标可能卡住: 位置 {current_pos} 保持不变超过3秒")
                        return True
                else:
                    # 位置变化，重置计时
                    self.mouse_locked_time = 0
                    self.last_mouse_pos = current_pos
            
            return False
        except Exception as e:
            self.logger.error(f"检查鼠标是否卡住时出错: {e}")
            return False
    
    def _terminate_przs_processes(self):
        """终止所有przs相关的进程"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if any(name in proc.info['name'].lower() for name in self.LOCK_PROCESS_NAMES):
                    pid = proc.info['pid']
                    self.logger.info(f"发现可疑进程 {proc.info['name']} (PID: {pid})，尝试终止")
                    try:
                        handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
                        win32api.TerminateProcess(handle, 0)
                        win32api.CloseHandle(handle)
                        self.logger.info(f"强制终止进程: PID {pid}")
                    except Exception as e:
                        self.logger.error(f"终止进程 {pid} 时出错: {e}")
        except Exception as e:
            self.logger.error(f"终止przs相关进程时出错: {e}") 