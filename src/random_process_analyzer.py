#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
随机进程分析器
用于分析和处理przs的随机进程名逻辑
"""

import os
import sys
import re
import logging
import time
import psutil
import ctypes
import win32api
import win32con
import win32process
import win32security
import random
import string
import datetime
from typing import List, Dict, Set, Tuple, Any, Optional
from threading import Thread, Lock
from ctypes import wintypes
from datetime import datetime, timedelta
import platform

class RandomProcessAnalyzer:
    """
    随机进程分析器，用于检测和识别przs程序生成的随机进程名
    支持两种主要的进程名生成逻辑:
    1. 基于日期算法生成的4字符名称
    2. 基于随机算法生成的5-6字符名称
    """
    
    # przs随机进程名特征
    PROCESS_PATTERNS = [
        # 5-6个小写字母
        r"^[a-z]{5,6}\.exe$",
        # 5-6个大写字母
        r"^[A-Z]{5,6}\.exe$",
        # 5-6个混合大小写字母 
        r"^[a-zA-Z]{5,6}\.exe$",
        # 3-4个字母后跟2-3个数字
        r"^[a-zA-Z]{3,4}[0-9]{2,3}\.exe$"
    ]
    
    # 基于日期生成的进程名模式预测
    DATE_BASED_PATTERNS = [
        # 4个字母组合的模式
        r"^[a-z]{4}\.exe$"
    ]
    
    # 可疑安装路径模式
    SUSPICIOUS_PATHS = [
        r"C:\\Program Files \(x86\)\\[a-z]{3}\\",
        r"C:\\[a-z]{3}\\",
        r"C:\\[a-z]{3,4}\\"
    ]
    
    # 可疑行为特征
    SUSPICIOUS_BEHAVIORS = {
        "silent_process": "进程无窗口",
        "low_memory": "内存占用低（<5MB）",
        "unusual_location": "在异常位置运行",
        "created_recently": "近期创建（<5分钟）",
        "hidden_window": "窗口隐藏状态",
        "high_cpu": "CPU使用率异常",
        "no_window_title": "窗口无标题"
    }
    
    def __init__(self, logger=None):
        """
        初始化随机进程分析器
        
        Args:
            logger: 日志记录器对象
        """
        self.logger = logger or logging.getLogger("RandomProcessAnalyzer")
        self.suspicious_processes = {}  # 已识别的可疑进程 {pid: process_info}
        
        # 初始化进程分析工具
        import psutil
        global psutil
        
        # 确保导入所需模块
        import re, os, time
        global re, os, time
        
        # 初始化注册表访问
        if platform.system() == 'Windows':
            try:
                import winreg
                global winreg
            except ImportError:
                self.logger.warning("无法导入winreg模块，注册表功能将不可用")
        
        # 生成基于当前日期的可能进程名
        self.logger.info("RandomProcessAnalyzer初始化完成，开始分析随机进程")
    
    def _setup_win_api(self):
        """设置Windows API访问"""
        # 设置进程权限相关API
        self.OpenProcess = ctypes.windll.kernel32.OpenProcess
        self.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.OpenProcess.restype = wintypes.HANDLE
        
        self.CloseHandle = ctypes.windll.kernel32.CloseHandle
        self.CloseHandle.argtypes = [wintypes.HANDLE]
        self.CloseHandle.restype = wintypes.BOOL
        
        # 设置进程令牌相关API
        self.OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
        self.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        self.OpenProcessToken.restype = wintypes.BOOL
        
        # 设置权限相关API
        self.LookupPrivilegeValue = ctypes.windll.advapi32.LookupPrivilegeValueW
        self.AdjustTokenPrivileges = ctypes.windll.advapi32.AdjustTokenPrivileges
    
    def _generate_possible_names(self):
        """
        生成可能的przs随机进程名
        包括基于当前日期的进程名和最近几天的变体
        """
        possible_names = []
        
        # 1. 基于日期算法的进程名 (当前日期)
        now = datetime.now()
        
        # 计算未来3天和过去3天的可能进程名
        for day_offset in range(-3, 4):
            # 计算目标日期
            target_date = now + timedelta(days=day_offset)
            
            # 基础值计算 - przs算法核心
            base_value = target_date.month * target_date.day
            
            # 4字符模式 (基于分析的przs主要算法)
            c1 = chr(ord('a') + (base_value % 26))
            c2 = chr(ord('a') + ((base_value // 26) % 26))
            c3 = chr(ord('a') + ((base_value // (26*26)) % 26))
            c4 = chr(ord('a') + ((base_value // (26*26*26)) % 26))
            
            process_name = f"{c1}{c2}{c3}{c4}.exe"
            possible_names.append(process_name)
            
            # 其他可能的变体 (可能存在的算法变异)
            # 如：base_value + 1 的变体
            alt_base = base_value + 1
            alt_c1 = chr(ord('a') + (alt_base % 26))
            alt_c2 = chr(ord('a') + ((alt_base // 26) % 26))
            alt_c3 = chr(ord('a') + ((alt_base // (26*26)) % 26))
            alt_c4 = chr(ord('a') + ((alt_base // (26*26*26)) % 26))
            
            alt_process_name = f"{alt_c1}{alt_c2}{alt_c3}{alt_c4}.exe"
            possible_names.append(alt_process_name)
        
        self.logger.debug(f"生成了{len(possible_names)}个基于日期的可能进程名")
        return possible_names
    
    def is_admin(self) -> bool:
        """检查当前是否有管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            self.logger.error(f"检查管理员权限时出错: {e}")
            return False
    
    def enable_privilege(self, privilege_name: str) -> bool:
        """启用当前进程的特定权限"""
        if not self.is_admin():
            self.logger.warning("没有管理员权限，无法启用权限")
            return False
            
        try:
            # 定义必要的结构体
            class LUID(ctypes.Structure):
                _fields_ = [
                    ("LowPart", wintypes.DWORD),
                    ("HighPart", wintypes.LONG)
                ]

            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [
                    ("Luid", LUID),
                    ("Attributes", wintypes.DWORD)
                ]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)
                ]

            token = wintypes.HANDLE()
            luid = LUID()
            
            # 获取进程令牌
            if not self.OpenProcessToken(ctypes.windll.kernel32.GetCurrentProcess(), 
                                         win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
                                         ctypes.byref(token)):
                self.logger.error("无法获取进程令牌")
                return False
                
            # 查找权限
            if not self.LookupPrivilegeValue(None, privilege_name, ctypes.byref(luid)):
                self.CloseHandle(token)
                self.logger.error(f"无法查找权限: {privilege_name}")
                return False
                
            # 设置权限
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = win32con.SE_PRIVILEGE_ENABLED
            
            # 调整令牌权限
            if not self.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 
                                             ctypes.sizeof(TOKEN_PRIVILEGES), 
                                             None, None):
                self.CloseHandle(token)
                self.logger.error("无法调整令牌权限")
                return False
                
            self.CloseHandle(token)
            self.logger.info(f"成功启用权限: {privilege_name}")
            return True
        except Exception as e:
            self.logger.error(f"启用权限时出错: {e}")
            return False
    
    def is_przs_random_name(self, proc_name: str) -> bool:
        """
        判断进程名是否为przs生成的随机名称
        
        Args:
            proc_name: 进程名
            
        Returns:
            bool: 是否为随机进程名
        """
        # 转为小写并确保比较的是纯文件名
        proc_name = proc_name.lower()
        if not proc_name.endswith('.exe'):
            proc_name += '.exe'
        
        # 1. 检查是否为当前预测的日期算法名称
        possible_names = self._generate_possible_names()
        if proc_name in possible_names:
            self.logger.debug(f"进程名{proc_name}匹配日期算法预测")
            return True
        
        # 2. 检查是否匹配4字符日期模式
        for pattern in self.DATE_BASED_PATTERNS:
            if re.match(pattern, proc_name):
                # 进一步检查是否可能是日期生成的(只有小写字母a-z)
                if all(c in 'abcdefghijklmnopqrstuvwxyz' for c in proc_name[:-4]):
                    self.logger.debug(f"进程名{proc_name}匹配日期模式但非当前预测值")
                    return True
        
        # 3. 检查随机名称模式
        for pattern in self.PROCESS_PATTERNS:
            if re.match(pattern, proc_name):
                self.logger.debug(f"进程名{proc_name}匹配随机名称模式")
                return True
        
        # 4. 不匹配任何模式
        return False
    
    def get_process_info(self, proc: psutil.Process) -> Dict[str, Any]:
        """
        获取进程的详细信息，包括可疑行为分析
        
        Args:
            proc: psutil.Process对象
            
        Returns:
            Dict[str, Any]: 进程详细信息
        """
        process_info = {
            'pid': proc.pid,
            'name': '',
            'exe': '',
            'cmdline': [],
            'cwd': '',
            'username': '',
            'create_time': 0,
            'suspicious_behaviors': [],
            'relationships': []
        }
        
        try:
            # 基础信息
            with proc.oneshot():  # 一次性收集所有信息提高效率
                process_info['name'] = proc.name()
                
                try:
                    process_info['exe'] = proc.exe()
                except (psutil.AccessDenied, FileNotFoundError):
                    process_info['exe'] = "访问被拒绝"
                
                try:
                    process_info['cmdline'] = proc.cmdline()
                except psutil.AccessDenied:
                    process_info['cmdline'] = ["访问被拒绝"]
                
                try:
                    process_info['cwd'] = proc.cwd()
                except (psutil.AccessDenied, FileNotFoundError):
                    process_info['cwd'] = "访问被拒绝"
                
                try:
                    process_info['username'] = proc.username()
                except psutil.AccessDenied:
                    process_info['username'] = "访问被拒绝"
                
                process_info['create_time'] = proc.create_time()
                
                # 添加内存信息
                try:
                    memory_info = proc.memory_info()
                    process_info['memory_rss'] = memory_info.rss
                    process_info['memory_vms'] = memory_info.vms
                    
                    # 检查低内存使用（可能是隐藏进程的特征）
                    if memory_info.rss < 5 * 1024 * 1024:  # 小于5MB
                        process_info['suspicious_behaviors'].append("low_memory")
                except psutil.AccessDenied:
                    pass
                
                # 添加CPU使用率信息
                try:
                    cpu_percent = proc.cpu_percent(interval=0.1)
                    process_info['cpu_percent'] = cpu_percent
                    
                    # 异常CPU使用率检测
                    if cpu_percent > 90:
                        process_info['suspicious_behaviors'].append("high_cpu")
                except psutil.AccessDenied:
                    pass
                
                # 检查是否在异常位置运行
                if process_info['exe'] != "访问被拒绝":
                    # 检查是否位于Program Files (x86)
                    if "Program Files (x86)" in process_info['exe']:
                        # 检查是否在特定的随机目录中
                        if re.search(r"\\[a-z]{3}\\", process_info['exe']):
                            process_info['suspicious_behaviors'].append("unusual_location")
                    
                    # 检查是否在系统驱动器根目录的随机文件夹下
                    if re.search(r"C:\\[a-z]{3,4}\\", process_info['exe']):
                        process_info['suspicious_behaviors'].append("unusual_location")
                
                # 检查是否近期创建
                create_time = process_info['create_time']
                if (time.time() - create_time) < 300:  # 5分钟内创建
                    process_info['suspicious_behaviors'].append("created_recently")
            
            # 检查窗口信息（这需要额外的Win32 API调用）
            if platform.system() == 'Windows':
                try:
                    import win32gui
                    import win32process
                    
                    def callback(hwnd, hwnds):
                        if win32gui.IsWindowVisible(hwnd):
                            _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                            if found_pid == proc.pid:
                                hwnds.append(hwnd)
                        return True
                    
                    hwnds = []
                    win32gui.EnumWindows(callback, hwnds)
                    
                    # 如果进程有窗口但找不到可见窗口，标记为隐藏窗口
                    if len(hwnds) == 0:
                        has_window = False
                        for hwnd in hwnds:
                            if win32gui.IsWindowVisible(hwnd):
                                has_window = True
                                break
                        
                        if not has_window:
                            process_info['suspicious_behaviors'].append("hidden_window")
                    
                    # 检查窗口标题是否为空
                    for hwnd in hwnds:
                        title = win32gui.GetWindowText(hwnd)
                        if not title and win32gui.IsWindowVisible(hwnd):
                            process_info['suspicious_behaviors'].append("no_window_title")
                            break
                
                except ImportError:
                    self.logger.debug("无法导入win32gui模块，跳过窗口检查")
                except Exception as e:
                    self.logger.debug(f"检查窗口信息时出错: {e}")
            
            # 检查没有窗口的进程 (基于cmdline检查)
            if not process_info['cmdline'] or (
                    len(process_info['cmdline']) == 1 and 
                    not any(kw in process_info['cmdline'][0].lower() for kw in 
                           ['window', 'gui', 'display', 'show', 'visible', 'ui'])):
                process_info['suspicious_behaviors'].append("silent_process")
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            self.logger.debug(f"获取进程信息时出错: {e}")
        except Exception as e:
            self.logger.error(f"获取进程信息时遇到未知错误: {e}")
        
        # 计算可疑程度评分 (基于行为数量)
        behavior_count = len(process_info['suspicious_behaviors'])
        if behavior_count >= 3:
            process_info['suspicion_level'] = "高"
        elif behavior_count >= 1:
            process_info['suspicion_level'] = "中"
        else:
            process_info['suspicion_level'] = "低"
        
        return process_info
    
    def lower_process_privilege(self, pid: int) -> bool:
        """降低进程权限，特别是针对przs和jfglzs程序"""
        if not self.is_admin():
            self.logger.warning("没有管理员权限，无法修改进程权限")
            return False
        
        try:
            # 启用必要的权限
            self.enable_privilege("SeDebugPrivilege")
            
            # 打开目标进程
            PROCESS_ALL_ACCESS = 0x1F0FFF
            process_handle = self.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            
            if not process_handle:
                self.logger.error(f"无法打开进程 (PID: {pid})")
                return False
            
            try:
                # 获取进程令牌
                token_handle = wintypes.HANDLE()
                TOKEN_ADJUST_PRIVILEGES = 0x00000020
                TOKEN_QUERY = 0x00000008
                
                if not self.OpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
                                           ctypes.byref(token_handle)):
                    self.logger.error(f"无法获取进程令牌 (PID: {pid})")
                    return False
                
                try:
                    # 定义需要移除的权限
                    privileges_to_disable = [
                        "SeDebugPrivilege",           # 调试权限
                        "SeTakeOwnershipPrivilege",   # 取得所有权权限
                        "SeLoadDriverPrivilege",      # 加载驱动程序权限
                        "SeBackupPrivilege",          # 备份权限
                        "SeRestorePrivilege",         # 恢复权限
                        "SeShutdownPrivilege",        # 关机权限
                        "SeSystemtimePrivilege",      # 修改系统时间权限
                        "SeSystemEnvironmentPrivilege", # 修改系统环境权限
                        "SeManageVolumePrivilege"     # 管理卷权限
                    ]
                    
                    # 移除每个权限
                    for privilege in privileges_to_disable:
                        # 定义必要的结构体
                        class LUID(ctypes.Structure):
                            _fields_ = [
                                ("LowPart", wintypes.DWORD),
                                ("HighPart", wintypes.LONG)
                            ]

                        class LUID_AND_ATTRIBUTES(ctypes.Structure):
                            _fields_ = [
                                ("Luid", LUID),
                                ("Attributes", wintypes.DWORD)
                            ]

                        class TOKEN_PRIVILEGES(ctypes.Structure):
                            _fields_ = [
                                ("PrivilegeCount", wintypes.DWORD),
                                ("Privileges", LUID_AND_ATTRIBUTES * 1)
                            ]
                        
                        luid = LUID()
                        
                        if self.LookupPrivilegeValue(None, privilege, ctypes.byref(luid)):
                            tp = TOKEN_PRIVILEGES()
                            tp.PrivilegeCount = 1
                            tp.Privileges[0].Luid = luid
                            tp.Privileges[0].Attributes = 0  # 移除权限
                            
                            self.AdjustTokenPrivileges(token_handle, False, ctypes.byref(tp), 
                                                     ctypes.sizeof(TOKEN_PRIVILEGES), 
                                                     None, None)
                    
                    self.logger.info(f"成功降低进程权限 (PID: {pid})")
                    return True
                    
                finally:
                    self.CloseHandle(token_handle)
            finally:
                self.CloseHandle(process_handle)
        
        except Exception as e:
            self.logger.error(f"降低进程权限时出错 (PID: {pid}): {e}")
            return False
    
    def scan_przs_processes(self) -> List[Dict[str, Any]]:
        """
        扫描系统中的przs随机进程
        
        Returns:
            List[Dict[str, Any]]: 可疑进程列表，包含详细信息
        """
        suspicious_processes = []
        
        try:
            # 获取所有进程
            all_processes = psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'cwd', 'username', 'create_time'])
            
            # 生成当前可能的进程名列表 (基于日期算法)
            possible_day_based_names = self._generate_possible_names()
            
            # 转换为集合提高查找效率
            possible_names_set = set(possible_day_based_names)
            
            suspicious_count = 0
            self.logger.info(f"开始扫描przs随机进程...")
            
            for proc in all_processes:
                try:
                    # 跳过自己的进程
                    if proc.pid == os.getpid():
                        continue
                    
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()
                    
                    # 检查是否是已知的目标进程直接名称
                    if proc_name in ['przs.exe', 'jfglzs.exe', 'zmserv.exe']:
                        suspicious_processes.append(self.get_process_info(proc))
                        suspicious_count += 1
                        continue
                    
                    # 1. 快速路径: 直接检查是否在预计算的基于日期的名称列表中
                    if proc_name in possible_names_set:
                        self.logger.info(f"找到基于日期算法的przs进程: {proc_name} (PID: {proc.pid})")
                        suspicious_processes.append(self.get_process_info(proc))
                        suspicious_count += 1
                        continue
                    
                    # 2. 检查是否匹配任何随机模式
                    if self.is_przs_random_name(proc_name):
                        # 获取进程详细信息
                        proc_detail = self.get_process_info(proc)
                        suspicious_processes.append(proc_detail)
                        suspicious_count += 1
                        
                        self.logger.info(f"找到可疑随机进程: {proc_name} (PID: {proc.pid})")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    self.logger.debug(f"访问进程时出错: {e}")
                except Exception as e:
                    self.logger.error(f"扫描进程时出错: {e}")
            
            self.logger.info(f"扫描完成，发现 {suspicious_count} 个可疑随机进程")
            
            # 分析进程关系，查找进程间的联系
            if suspicious_processes:
                self._analyze_process_relationships(suspicious_processes)
                
            return suspicious_processes
            
        except Exception as e:
            self.logger.error(f"扫描随机进程失败: {e}")
            return []
            
    def _analyze_process_relationships(self, suspicious_processes: List[Dict[str, Any]]) -> None:
        """
        分析可疑进程之间的关系，查找可能的互相监控和保护关系
        
        Args:
            suspicious_processes: 可疑进程列表
        """
        try:
            # 提取所有可疑进程的PID
            suspicious_pids = [proc['pid'] for proc in suspicious_processes]
            
            # 检查互相监控关系
            for proc in suspicious_processes:
                pid = proc['pid']
                try:
                    # 获取进程的所有连接
                    p = psutil.Process(pid)
                    connections = p.connections(kind='all')
                    
                    # 检查是否与其他可疑进程有连接
                    for conn in connections:
                        if hasattr(conn, 'raddr') and conn.raddr:
                            # 检查是否连接到本地端口
                            if conn.raddr.ip == '127.0.0.1':
                                # 尝试找到使用该端口的进程
                                for other_proc in psutil.process_iter(['pid', 'connections']):
                                    try:
                                        if other_proc.pid in suspicious_pids and other_proc.pid != pid:
                                            other_connections = other_proc.connections(kind='all')
                                            for other_conn in other_connections:
                                                if (hasattr(other_conn, 'laddr') and other_conn.laddr and 
                                                    other_conn.laddr.port == conn.raddr.port):
                                                    self.logger.warning(
                                                        f"发现互相监控关系: {pid} 连接到 {other_proc.pid}")
                                                    proc['relationships'] = proc.get('relationships', [])
                                                    proc['relationships'].append({
                                                        'type': 'monitors',
                                                        'target_pid': other_proc.pid
                                                    })
                                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                                        continue
                except Exception as e:
                    self.logger.debug(f"分析进程 {pid} 关系时出错: {e}")
                    
            # 检查父子进程关系
            for proc in suspicious_processes:
                pid = proc['pid']
                try:
                    p = psutil.Process(pid)
                    parent = p.parent()
                    
                    if parent and parent.pid in suspicious_pids:
                        self.logger.warning(f"可疑进程 {pid} 的父进程 {parent.pid} 也是可疑进程")
                        proc['relationships'] = proc.get('relationships', [])
                        proc['relationships'].append({
                            'type': 'child_of',
                            'parent_pid': parent.pid
                        })
                    
                    # 检查子进程
                    children = p.children()
                    for child in children:
                        if child.pid in suspicious_pids:
                            self.logger.warning(f"可疑进程 {pid} 拥有可疑子进程 {child.pid}")
                            proc['relationships'] = proc.get('relationships', [])
                            proc['relationships'].append({
                                'type': 'parent_of',
                                'child_pid': child.pid
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    continue
                    
        except Exception as e:
            self.logger.error(f"分析进程关系时出错: {e}")
    
    def lower_przs_processes_privileges(self) -> int:
        """
        降低所有přzs随机进程的权限
        
        Returns:
            int: 成功处理的进程数量
        """
        processes = self.scan_przs_processes()
        lowered_count = 0
        
        for proc_info in processes:
            pid = proc_info.get('pid')
            name = proc_info.get('name', '').lower()
            
            try:
                if self.lower_process_privilege(pid):
                    self.logger.info(f"已降低进程权限: {name} (PID: {pid})")
                    lowered_count += 1
            except Exception as e:
                self.logger.error(f"降低进程 {name} (PID: {pid}) 权限时出错: {e}")
        
        return lowered_count
    
    def run_analyzer(self, interval=60, callback=None):
        """
        运行进程分析器，定期扫描并识别可疑进程
        
        Args:
            interval: 扫描间隔（秒）
            callback: 每次扫描后的回调函数，接收可疑进程列表作为参数
            
        Returns:
            Thread: 分析器线程
        """
        self.stop_flag = False
        
        def analyzer_loop():
            while not self.stop_flag:
                try:
                    suspicious_processes = self.scan_przs_processes()
                    
                    if callback and callable(callback):
                        callback(suspicious_processes)
                    
                    time.sleep(interval)
                except Exception as e:
                    self.logger.error(f"分析器循环出错: {e}")
                    time.sleep(10)  # 错误后短暂休眠再重试
        
        self.analyzer_thread = Thread(target=analyzer_loop, daemon=True)
        self.analyzer_thread.start()
        self.logger.info(f"进程分析器已启动，扫描间隔: {interval}秒")
        return self.analyzer_thread
    
    def stop_analyzer(self):
        """停止进程分析器"""
        self.stop_flag = True
        if hasattr(self, 'analyzer_thread') and self.analyzer_thread.is_alive():
            self.analyzer_thread.join(timeout=5)
            self.logger.info("进程分析器已停止")
    
    def analyze_przs_random_name_logic(self) -> Dict[str, Any]:
        """
        分析przs的随机进程名生成逻辑，返回可能的模式和预测
        
        Returns:
            Dict[str, Any]: 分析结果
        """
        now = datetime.now()
        
        # 分析基于日期算法的命名
        date_based_examples = []
        for day_offset in range(-2, 3):
            target_date = now + timedelta(days=day_offset)
            date_str = target_date.strftime("%Y-%m-%d")
            
            # 基础值计算 (przs算法)
            base_value = target_date.month * target_date.day
            
            c1 = chr(ord('a') + (base_value % 26))
            c2 = chr(ord('a') + ((base_value // 26) % 26))
            c3 = chr(ord('a') + ((base_value // (26*26)) % 26))
            c4 = chr(ord('a') + ((base_value // (26*26*26)) % 26))
            
            process_name = f"{c1}{c2}{c3}{c4}.exe"
            date_based_examples.append({
                "date": date_str,
                "calculated_value": base_value,
                "process_name": process_name
            })
        
        # 分析基于随机数的命名
        random_pattern_examples = {
            "5-6个小写字母": ["abcde.exe", "abcdef.exe"],
            "5-6个大写字母": ["ABCDE.exe", "ABCDEF.exe"],
            "5-6个混合字母": ["AbCdE.exe", "AbCdEf.exe"],
            "3-4字母+2-3数字": ["abc12.exe", "abcd123.exe"]
        }
        
        analysis_result = {
            "timestamp": time.time(),
            "date_based_algorithm": {
                "description": "基于日期的进程名生成算法 (月份 * 日期 -> 基于26进制的字符映射)",
                "examples": date_based_examples
            },
            "random_based_algorithm": {
                "description": "基于随机数的进程名生成算法",
                "patterns": random_pattern_examples
            },
            "detection_patterns": {
                "date_based": self.DATE_BASED_PATTERNS,
                "random_based": self.PROCESS_PATTERNS
            }
        }
        
        return analysis_result 