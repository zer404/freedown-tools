#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
反制措施管理器
负责管理针对监控程序的反制措施
"""

import os
import sys
import time
import logging
import threading
import re
import psutil
import ctypes
import winreg
import win32api
import win32con
import win32service
import win32process
import win32security
from typing import List, Dict, Tuple, Optional, Any, Set
import traceback
import random
import datetime
import platform
import win32gui

class SelfProtection:
    """
    自我保护类，用于防止反制系统本身被目标程序监视或终止
    """
    
    def __init__(self):
        """初始化自我保护"""
        self.logger = logging.getLogger("SelfProtection")
        self.our_pid = os.getpid()
        self.protected_processes = set()
        self.protected_processes.add(self.our_pid)
        self.logger.info("自我保护系统初始化完成")
    
    def add_protected_process(self, pid):
        """添加需要保护的进程"""
        if pid and isinstance(pid, int):
            self.protected_processes.add(pid)
            self.logger.info(f"添加受保护进程 PID: {pid}")
            return True
        return False
    
    def is_protected(self, pid):
        """检查进程是否被保护"""
        return pid in self.protected_processes
    
    def cleanup(self):
        """清理资源"""
        try:
            self.logger.info("清理自我保护资源...")
            self.protected_processes.clear()
            return True
        except Exception as e:
            self.logger.error(f"清理自我保护资源时出错: {e}")
            return False


class CountermeasureManager:
    """管理反制措施的类，专门针对 jfglzs、przs 和 set 程序"""
    
    # 监控程序的进程名称
    TARGET_PROCESSES = ["jfglzs.exe", "przs.exe", "zmserv.exe", "set.exe"]
    
    # przs随机进程名特征
    PRZS_PATTERNS = [
        r"^[a-z]{5,6}\.exe$",              # 5-6个小写字母，如"abcde.exe"
        r"^[A-Z]{5,6}\.exe$",              # 5-6个大写字母
        r"^[a-zA-Z]{5,6}\.exe$",           # 5-6个混合大小写字母
        r"^[a-zA-Z]{3,4}[0-9]{2,3}\.exe$", # 3-4个字母后跟2-3个数字
    ]
    
    # 关键注册表键值
    REGISTRY_KEYS = {
        "usb_detection": r"Software\jfglzs\usb_jianche",
        "vm_detection": r"Software\jfglzs\xnj_jianche",
        "cmd_detection": r"Software\jfglzs\cmd_jianche",
        "cmd_disable": r"Software\Policies\Microsoft\Windows\System\DisableCMD",
        "logout_button": r"Software\jfglzs\zhuxiao_button",
        "desktop_button": r"Software\jfglzs\xnzm_button",
        "pd_key": r"Software\pd",
        "autostart_key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "autostart_key_32": r"SOFTWARE\WOW6432NODE\Microsoft\Windows\CurrentVersion\Run",
        "bianhao": r"Software\jfglzs\bianhao",
    }
    
    # 添加被禁用系统工具列表
    DISABLED_SYSTEM_TOOLS = [
        "taskkill.exe",
        "ntsd.exe",
        "sidebar.exe",
        "Chess.exe",
        "FreeCell.exe",
        "Hearts.exe",
        "Minesweeper.exe",
        "PurblePlace.exe",
        "Mahjong.exe",
        "SpiderSolitaire.exe",
        "bckgzm.exe",
        "chkrzm.exe",
        "shvlzm.exe", 
        "Solitaire.exe",
        "winmine.exe",
        "Magnify.exe",
        "sethc.exe",
        "QQPCTray.exe"
    ]
    
    # 可疑进程特征
    PROCESS_SIGNATURES = {
        "jfglzs": {
            "files": ["jfglzs.exe"],
            "services": ["zmserv"],
            "description": "教室管理程序"
        },
        "przs": {
            "files": ["przs.exe"],
            "services": [],
            "description": "屏幕监控程序"
        },
        "set": {
            "files": ["set.exe"],
            "services": [],
            "description": "系统限制程序"
        }
    }
    
    # 已知自我保护机制
    SELF_PROTECTION_MECHANISMS = {
        "mutual_monitoring": "互相监控",
        "auto_restart": "自动重启",
        "system_restart": "系统重启",
        "self_replication": "自我复制",
        "process_hiding": "进程隐藏",
        "window_locking": "窗口锁定",
        "cursor_restriction": "鼠标限制",
        "registry_protection": "注册表保护"
    }
    
    def __init__(self):
        """初始化反制管理器"""
        try:
            # 设置日志
            self.logger = logging.getLogger("CountermeasureManager")
            
            # 初始化自保护
            self.self_protection = SelfProtection()
            
            # 初始化线程控制
            self._monitoring_thread = None
            self._should_stop = False
            self.monitoring = False
            self.found_targets = []
            self.lock = threading.RLock()
            self.handled_processes = set()  # 添加已处理的进程集合
            self.suspicious_processes = {}  # 添加可疑进程字典
            
            # 初始化上次随机分析时间
            self.last_random_analysis_time = time.time()
            
            # 初始化自启动项列表
            self.startup_keys = ["przs", "jfglzs", "zmserv", "xwzc"]
            
            # 初始化进程关系字典
            self.process_relationships = {}
            
            # 初始化5分钟循环相关变量
            self.last_full_scan_time = 0  # 上次完整扫描的时间
            self.excluded_processes = {}  # 格式: {pid: {count: 0, last_check: timestamp, exclude_until: timestamp, has_suspicious: False}}
            
            # 确保TARGET_PROCESSES已定义
            if not hasattr(self, 'TARGET_PROCESSES') or not self.TARGET_PROCESSES:
                self.TARGET_PROCESSES = ["jfglzs.exe", "przs.exe", "zmserv.exe", "set.exe"]
                
            self.logger.info("反制管理器初始化完成")
        except Exception as e:
            self.logger.error(f"初始化反制管理器时出错: {e}")
            # 确保基本属性即使在出错情况下也被设置
            if not hasattr(self, 'logger'):
                self.logger = logging.getLogger("CountermeasureManager")
            if not hasattr(self, 'lock'):
                self.lock = threading.RLock()
            if not hasattr(self, 'found_targets'):
                self.found_targets = []
            if not hasattr(self, 'handled_processes'):
                self.handled_processes = set()
            if not hasattr(self, 'suspicious_processes'):
                self.suspicious_processes = {}
            if not hasattr(self, 'last_random_analysis_time'):
                self.last_random_analysis_time = time.time()
            if not hasattr(self, '_monitoring_thread'):
                self._monitoring_thread = None
            if not hasattr(self, '_should_stop'):
                self._should_stop = False
            if not hasattr(self, 'monitoring'):
                self.monitoring = False
            if not hasattr(self, 'process_relationships'):
                self.process_relationships = {}
            if not hasattr(self, 'monitor_thread'):
                self.monitor_thread = None
            if not hasattr(self, 'last_full_scan_time'):
                self.last_full_scan_time = 0
            if not hasattr(self, 'excluded_processes'):
                self.excluded_processes = {}
            
            traceback.print_exc()
            
    def get_found_targets(self):
        """获取发现的目标列表"""
        try:
            # 检查lock属性是否存在，如果不存在则初始化
            if not hasattr(self, 'lock'):
                self.logger.warning("获取目标列表时发现lock属性未初始化，正在创建")
                self.lock = threading.RLock()
                
            # 检查found_targets属性是否存在，如果不存在则初始化
            if not hasattr(self, 'found_targets'):
                self.logger.warning("获取目标列表时发现found_targets属性未初始化，正在创建")
                self.found_targets = []
                
            with self.lock:
                return self.found_targets.copy()
        except Exception as e:
            self.logger.error(f"获取目标列表时出错: {e}")
            return []
            
    def stop_monitoring_thread(self):
        """停止监控线程"""
        try:
            # 设置停止标志
            self._should_stop = True
            self.monitoring = False
            
            # 等待线程结束
            if hasattr(self, '_monitoring_thread') and self._monitoring_thread is not None and self._monitoring_thread.is_alive():
                self.logger.info("等待监控线程结束...")
                # 不使用join，防止阻塞主线程
                self._monitoring_thread = None
            
            self.logger.info("监控线程已停止")
            return True
        except Exception as e:
            self.logger.error(f"停止监控线程时出错: {e}")
            return False
            
    def cleanup(self):
        """清理资源"""
        self.stop_monitoring_thread()
        self.logger.info("反制措施管理器已清理资源")
    
    def is_admin(self) -> bool:
        """检查是否有管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            self.logger.error(f"检查管理员权限时出错: {e}")
            return False
    
    def execute_random_analysis(self):
        """执行随机分析，避免被检测到规律性操作"""
        try:
            # 检查last_random_analysis_time属性是否存在，如果不存在则初始化
            if not hasattr(self, 'last_random_analysis_time'):
                self.logger.warning("执行随机分析时发现last_random_analysis_time属性未初始化，正在创建")
                self.last_random_analysis_time = 0
                
            # 控制执行频率 - 随机间隔2-8秒
            current_time = time.time()
            if current_time - self.last_random_analysis_time < random.uniform(2, 8):
                return

            self.last_random_analysis_time = current_time
            
            # 确保进程查找函数存在并可执行
            if not hasattr(self, '_find_processes') or not callable(self._find_processes):
                self.logger.error("随机分析执行失败: _find_processes方法未定义")
                return None
                
            # 执行进程查找
            self._find_processes(random_mode=True)
            
            # 执行随机动作以混淆监控
            # 1. 随机睡眠一小段时间
            time.sleep(random.uniform(0.1, 0.5))
            
            # 2. 随机生成一些CPU活动
            if random.random() < 0.3:  # 30%的概率执行
                _ = [i**2 for i in range(1000)]
                
            # 3. 随机读取一些系统信息
            if random.random() < 0.25:  # 25%的概率执行
                _ = platform.system()
                _ = platform.release()
                
            return True
        except Exception as e:
            self.logger.error(f"执行随机分析时出错: {e}")
            # 确保属性被设置，即使出错
            if not hasattr(self, 'last_random_analysis_time'):
                self.last_random_analysis_time = time.time()
            return None
            
    def is_suspicious_process_name(self, proc_name: str) -> bool:
        """判断进程名是否符合przs随机命名的特征"""
        try:
            # 排除一些常见的系统或应用程序
            common_system_procs = [
                "ngciso", "todesk", "chsime", "ctfmon", "python", 
                "explorer", "chrome", "firefox", "svchost", "csrss",
                "lsass", "winlogon", "dwm", "conhost", "taskmgr",
                "notepad", "cmd", "powershell", "wininit", "devenv",
                "msedge", "runtimebroker", "searchapp", "shellexperiencehost",
                "mmc", "wmiprvse", "sihost", "fontdrvhost", "searchindexer",
                "web32", "igfxem", "wscript", "dllhost", "audiodg", 
                "sqlservr", "sqlwriter", "steam", "discord", "spotify"
            ]
            
            # 如果是常见进程，直接排除
            proc_name_lower = proc_name.lower()
            proc_base_name = proc_name_lower.split('.')[0]
            if proc_base_name in common_system_procs:
                return False
                
            # 明确的przs相关进程
            if proc_name_lower in ["przs.exe", "jfglzs.exe", "zmserv.exe", "set.exe"]:
                self.logger.info(f"发现已知目标进程: {proc_name}")
                return True
                
            # 检查是否为4字符的进程名 (基于日期生成的przs进程)
            if re.match(r'^[a-z]{4}\.exe$', proc_name_lower):
                # 计算当天可能的进程名
                current_day = datetime.datetime.now().day
                current_month = datetime.datetime.now().month
                base_num = current_month * current_day
                
                # 计算可能的字符组合
                possible_names = self._generate_possible_przs_names(base_num)
                
                if proc_base_name in possible_names:
                    # 进一步验证 - 检查进程路径
                    try:
                        proc_obj = next((p for p in psutil.process_iter(['name', 'exe']) if p.info['name'].lower() == proc_name_lower), None)
                        if proc_obj and proc_obj.info.get('exe'):
                            exe_path = proc_obj.info['exe'].lower()
                            # 检查是否在可疑路径
                            if "program files (x86)" in exe_path and len(os.path.dirname(exe_path).split("\\")[-1]) <= 3:
                                self.logger.info(f"发现基于日期生成的przs进程: {proc_name} (安装在可疑目录)")
                                return True
                    except Exception:
                        pass
                        
                    self.logger.info(f"发现基于日期生成的przs进程: {proc_name}")
                    return True
                
            # 检查是否为5字符进程名（基于随机数生成的przs进程）
            if re.match(r'^[k-r]{5}\.exe$', proc_name_lower):
                # Form1.cs中生成随机进程名的代码显示字符范围是k-r(ASCII 107-114)
                try:
                    proc_obj = next((p for p in psutil.process_iter(['name', 'exe']) if p.info['name'].lower() == proc_name_lower), None)
                    if proc_obj and proc_obj.info.get('exe'):
                        exe_path = proc_obj.info['exe'].lower()
                        # 检查是否在可疑路径
                        if ("program files (x86)" in exe_path or ":" in exe_path[:3]) and len(os.path.dirname(exe_path).split("\\")[-1]) <= 3:
                            self.logger.info(f"发现基于随机数生成的przs进程: {proc_name} (安装在可疑目录)")
                            return True
                except Exception:
                    pass
                    
                self.logger.info(f"发现可能基于随机数生成的przs进程: {proc_name}")
                return True
                
            # 原有模式匹配保留，但增加额外验证步骤
            for pattern in self.PRZS_PATTERNS:
                if re.match(pattern, proc_name_lower):
                    # 额外验证而不是直接判定为可疑
                    try:
                        proc_obj = next((p for p in psutil.process_iter(['name', 'exe']) 
                                        if p.info['name'].lower() == proc_name_lower), None)
                        if proc_obj and proc_obj.info.get('exe'):
                            exe_path = proc_obj.info['exe'].lower()
                            # 检查是否在可疑路径
                            suspicious_paths = ["c:\\program files (x86)\\", "c:\\"]
                            for path_prefix in suspicious_paths:
                                if path_prefix in exe_path:
                                    # 提取安装目录名
                                    dir_parts = os.path.dirname(exe_path).replace(path_prefix, "").split("\\")
                                    if len(dir_parts) <= 1:
                                        subdir = dir_parts[0]
                                        # 子目录名是3-4个字符的字母
                                        if 2 <= len(subdir) <= 4 and subdir.isalpha():
                                            self.logger.info(f"发现可疑进程: {proc_name}，安装在可疑路径: {exe_path}")
                                            return True
                    except Exception:
                        # 出错时不判定为可疑
                        pass
            
            return False
        except Exception as e:
            self.logger.error(f"判断进程名是否可疑时出错: {e}")
            return False
            
    def _generate_possible_przs_names(self, base_num):
        """
        生成基于Form1.cs中算法的可能的przs进程名
        分析Form1.cs中的代码，przs有两种进程名生成方法：
        1. 基于日期的4字符进程名：用当天月×日计算出基础数字，再用不同的模运算生成字符
        2. 基于随机数的5字符进程名：生成随机数并转换为字符(ASCII值107-114范围，即k-r)
        """
        possible_names = []
        
        # 1. 基于日期的4字符生成算法
        # 计算各种取模值
        mod7 = base_num % 7
        mod9 = base_num % 9
        mod5 = base_num % 5
        mod3 = base_num % 3
        
        # 偶数情况和奇数情况使用不同的组合逻辑（直接从Form1.cs的156-186行翻译）
        if base_num % 2 == 0:  # 偶数
            name = chr(97 + mod7) + chr(98 + mod9) + chr(101 + mod5) + chr(99 + mod3)
        else:  # 奇数
            name = chr(97 + mod9) + chr(98 + mod7) + chr(101 + mod3) + chr(99 + mod5)
            
        possible_names.append(name)
        
        # 添加前一天和后一天的可能值，避免因日期误差导致检测不到
        for offset in [-1, 1]:
            # 计算前一天或后一天的日期
            date = datetime.datetime.now() + datetime.timedelta(days=offset)
            alt_base_num = date.month * date.day
            
            # 计算各种取模值
            alt_mod7 = alt_base_num % 7
            alt_mod9 = alt_base_num % 9
            alt_mod5 = alt_base_num % 5
            alt_mod3 = alt_base_num % 3
            
            # 偶数情况
            if alt_base_num % 2 == 0:
                alt_name = chr(97 + alt_mod7) + chr(98 + alt_mod9) + chr(101 + alt_mod5) + chr(99 + alt_mod3)
            # 奇数情况
            else:
                alt_name = chr(97 + alt_mod9) + chr(98 + alt_mod7) + chr(101 + alt_mod3) + chr(99 + alt_mod5)
                
            possible_names.append(alt_name)
        
        # 2. 记录一些从Form1.cs中分析得到的随机名生成逻辑
        # 从L224-243分析，生成的随机进程名是由5个ASCII值为107-114的字符组成
        # 我们在is_suspicious_process_name中已经实现对应的检测 (^[k-r]{5}\.exe$)
        
        # 日志记录生成的可能进程名
        self.logger.debug(f"生成的可能进程名: {possible_names}")
        
        return possible_names
    
    def get_process_path(self, pid: int) -> str:
        """获取进程的可执行文件路径"""
        try:
            process = psutil.Process(pid)
            return process.exe()
        except Exception as e:
            self.logger.error(f"获取进程路径时出错: {e}")
            return ""
    
    def analyze_process_relationships(self) -> Dict[int, Dict[str, Any]]:
        """分析进程间的关系，特别是互相监控的进程"""
        relationships = {}
        
        try:
            # 获取所有进程
            all_processes = list(psutil.process_iter(['pid', 'name', 'ppid']))
            
            # 创建进程ID到进程对象的映射
            pid_to_process = {}
            for proc in all_processes:
                try:
                    if hasattr(proc, 'info') and 'pid' in proc.info and proc.info['pid'] is not None:
                        pid_to_process[proc.info['pid']] = proc
                except (AttributeError, KeyError, TypeError) as e:
                    self.logger.warning(f"处理进程信息时出错: {e}")
            
            # 查找可疑进程
            suspicious_pids = []
            for proc in all_processes:
                try:
                    if not hasattr(proc, 'info') or 'name' not in proc.info or not proc.info['name']:
                        continue
                    
                    proc_name = proc.info['name']
                    if self.is_suspicious_process_name(proc_name):
                        if 'pid' in proc.info and proc.info['pid'] is not None:
                            suspicious_pids.append(proc.info['pid'])
                except (AttributeError, KeyError, TypeError) as e:
                    self.logger.warning(f"检查可疑进程名时出错: {e}")
            
            # 分析进程关系
            for pid in suspicious_pids:
                if pid not in pid_to_process:
                    continue
                
                proc = pid_to_process[pid]
                proc_relationships = {
                    'pid': pid,
                    'name': proc.info.get('name', '未知'),
                    'parent': None,
                    'children': [],
                    'possible_monitoring': [],
                    'suspicious_actions': []
                }
                
                # 记录父进程
                if hasattr(proc, 'info') and 'ppid' in proc.info and proc.info['ppid'] in pid_to_process:
                    parent_proc = pid_to_process[proc.info['ppid']]
                    if hasattr(parent_proc, 'info'):
                        proc_relationships['parent'] = {
                            'pid': parent_proc.info.get('pid', 0),
                            'name': parent_proc.info.get('name', '未知')
                        }
                
                # 记录子进程
                for other_proc in all_processes:
                    try:
                        if (hasattr(other_proc, 'info') and 'ppid' in other_proc.info 
                                and other_proc.info['ppid'] == pid 
                                and 'pid' in other_proc.info):
                            proc_relationships['children'].append({
                                'pid': other_proc.info.get('pid', 0),
                                'name': other_proc.info.get('name', '未知')
                            })
                    except (AttributeError, KeyError) as e:
                        self.logger.warning(f"处理子进程关系时出错: {e}")
                
                # 检查是否有互相监控的进程
                try:
                    # 检查进程是否仍然存在
                    proc_obj = psutil.Process(pid)
                    open_files = []
                    connections = []
                    
                    try:
                        open_files = proc_obj.open_files()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    try:
                        connections = proc_obj.connections()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # 检查文件访问
                    for file_obj in open_files:
                        for target_proc in self.TARGET_PROCESSES:
                            if hasattr(file_obj, 'path') and target_proc in file_obj.path.lower():
                                proc_relationships['suspicious_actions'].append(
                                    f"访问文件: {file_obj.path}"
                                )
                    
                    # 检查网络连接
                    if connections:
                        proc_relationships['suspicious_actions'].append(
                            f"存在网络连接: {len(connections)} 个"
                        )
                    
                    # 检查互相监控
                    for other_pid in suspicious_pids:
                        if other_pid == pid:
                            continue
                        
                        try:
                            # 检查进程是否仍然存在
                            if not psutil.pid_exists(other_pid):
                                continue
                            
                            other_proc_obj = psutil.Process(other_pid)
                            other_proc_files = []
                            try:
                                other_proc_files = [f.path for f in other_proc_obj.open_files() if hasattr(f, 'path')]
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                continue
                            
                            other_proc_name = other_proc_obj.name()
                            
                            # 如果一个进程访问了另一个进程的文件
                            proc_path = self.get_process_path(pid)
                            if proc_path and any(proc_path in f for f in other_proc_files):
                                proc_relationships['possible_monitoring'].append({
                                    'pid': other_pid,
                                    'name': other_proc_name,
                                    'reason': f"进程 {other_proc_name} 访问此进程文件"
                                })
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                            self.logger.debug(f"检查进程互相监控时出错 (PID: {other_pid}): {e}")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    self.logger.debug(f"获取进程详细信息时出错 (PID: {pid}): {e}")
                
                relationships[pid] = proc_relationships
            
            # 保存进程关系图
            self.process_relationships = relationships
            
            return relationships
        except Exception as e:
            self.logger.error(f"分析进程关系时出错: {e}")
            # 确保该属性存在
            if not hasattr(self, 'process_relationships'):
                self.process_relationships = {}
            return {}
    
    def get_process_signature(self, process: psutil.Process) -> Dict[str, Any]:
        """获取进程特征信息"""
        try:
            signature = {
                'pid': process.pid,
                'name': process.name(),
                'is_suspicious': False,
                'is_target': False,
                'reason': [],
                'connections': [],
                'open_files': [],
                'memory_usage': 0,
                'cpu_usage': 0
            }
            
            # 检查是否为目标进程
            if process.name() in self.TARGET_PROCESSES:
                signature['is_target'] = True
                signature['is_suspicious'] = True
                signature['reason'].append(f"已知监控进程: {process.name()}")
            
            # 检查是否为可疑随机进程名
            elif self.is_suspicious_process_name(process.name()):
                signature['is_suspicious'] = True
                signature['reason'].append(f"可疑随机进程名: {process.name()}")
            
            # 获取内存使用情况
            try:
                memory_info = process.memory_info()
                signature['memory_usage'] = memory_info.rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # 获取CPU使用情况
            try:
                signature['cpu_usage'] = process.cpu_percent(interval=0.1)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # 获取网络连接
            try:
                connections = process.connections()
                for conn in connections:
                    if hasattr(conn, 'laddr') and hasattr(conn, 'raddr'):
                        signature['connections'].append({
                            'local': conn.laddr,
                            'remote': conn.raddr if conn.raddr else None,
                            'status': conn.status
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # 获取打开的文件
            try:
                open_files = process.open_files()
                signature['open_files'] = [f.path for f in open_files]
                
                # 检查是否访问了其他监控程序文件
                for file_path in signature['open_files']:
                    for target in self.TARGET_PROCESSES:
                        if target in file_path.lower():
                            signature['is_suspicious'] = True
                            signature['reason'].append(f"访问监控程序文件: {file_path}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # 获取命令行参数
            try:
                signature['cmdline'] = process.cmdline()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                signature['cmdline'] = []
            
            # 获取进程可执行文件路径
            try:
                signature['exe'] = process.exe()
                
                # 检查是否在可疑路径中
                suspicious_paths = ["C:\\Program Files (x86)\\", "C:\\Windows\\"]
                for path in suspicious_paths:
                    if signature['exe'].startswith(path) and not signature['is_target']:
                        suspicious_name = os.path.basename(signature['exe'])
                        
                        # 进一步检查可执行文件名
                        if len(suspicious_name) <= 8 and suspicious_name.lower() not in [
                            "notepad.exe", "calc.exe", "cmd.exe", "explorer.exe"
                        ]:
                            signature['is_suspicious'] = True
                            signature['reason'].append(f"系统目录中的可疑程序: {suspicious_name}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                signature['exe'] = ""
            
            return signature
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            self.logger.error(f"获取进程特征时出错 (PID: {process.pid}): {e}")
            return {
                'pid': process.pid,
                'name': process.name() if hasattr(process, 'name') else "未知",
                'is_suspicious': False,
                'reason': [f"无法访问: {str(e)}"]
            }
    
    def scan_target_processes(self) -> Dict[str, List[psutil.Process]]:
        """扫描目标进程"""
        try:
            self.logger.debug("开始扫描目标进程")
            # 使用新的_find_processes方法并指定random_mode=False
            result = self._find_processes(random_mode=False)
            self.logger.debug(f"扫描完成: 发现 {len(result['target'])} 个目标进程, {len(result['suspicious'])} 个可疑进程")
            return result
        except Exception as e:
            self.logger.error(f"扫描目标进程时出错: {e}")
            # 确保返回值结构正确
            return {'target': [], 'suspicious': [], 'random': []}
    
    def disable_registry_restrictions(self) -> bool:
        """禁用注册表中的限制设置"""
        try:
            if not self.is_admin():
                self.logger.warning("没有管理员权限，无法修改注册表")
                return False
                
            success = True
            
            # 修改 jfglzs 相关键值
            for key_name, key_path in self.REGISTRY_KEYS.items():
                if key_name in ["usb_detection", "vm_detection", "cmd_detection"]:
                    try:
                        # 尝试打开键
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                             os.path.dirname(key_path), 0, 
                                             winreg.KEY_WRITE)
                        # 设置值为"off"
                        winreg.SetValueEx(key, os.path.basename(key_path), 0, 
                                          winreg.REG_SZ, "off")
                        winreg.CloseKey(key)
                        self.logger.info(f"已禁用注册表限制: {key_path}")
                    except FileNotFoundError:
                        # 如果键不存在，则尝试创建
                        try:
                            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, 
                                                  os.path.dirname(key_path))
                            winreg.SetValueEx(key, os.path.basename(key_path), 0, 
                                             winreg.REG_SZ, "off")
                            winreg.CloseKey(key)
                            self.logger.info(f"已创建并禁用注册表限制: {key_path}")
                        except Exception as e:
                            self.logger.error(f"创建注册表键 {key_path} 时出错: {e}")
                            success = False
                    except Exception as e:
                        self.logger.error(f"修改注册表键 {key_path} 时出错: {e}")
                        success = False
            
            # 修改 CMD 禁用键值
            try:
                cmd_key_path = os.path.dirname(self.REGISTRY_KEYS["cmd_disable"])
                cmd_value_name = os.path.basename(self.REGISTRY_KEYS["cmd_disable"])
                
                # 尝试打开键
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cmd_key_path, 0, 
                                    winreg.KEY_WRITE)
                # 设置值为0（启用CMD）
                winreg.SetValueEx(key, cmd_value_name, 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                self.logger.info(f"已启用命令提示符")
            except FileNotFoundError:
                # 键不存在，不需要修改
                pass
            except Exception as e:
                self.logger.error(f"启用命令提示符时出错: {e}")
                success = False
            
            return success
        except Exception as e:
            self.logger.error(f"禁用注册表限制时出错: {e}")
            return False
    
    def safe_terminate_process(self, process: psutil.Process) -> bool:
        """安全终止进程，避免触发保护机制"""
        try:
            if process.pid in self.handled_processes:
                return True  # 已经处理过的进程
                
            process_name = process.name()
            pid = process.pid
            
            self.logger.info(f"尝试终止进程: {process_name} (PID: {pid})")
            
            # 记录进程信息
            try:
                exe_path = process.exe()
                cmdline = process.cmdline()
                create_time = process.create_time()
                cwd = process.cwd()
                
                self.logger.info(f"进程信息: 路径={exe_path}, 创建时间={create_time}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # 检查是否有子进程，并记录
            try:
                children = process.children()
                if children:
                    child_info = []
                    for child in children:
                        try:
                            child_info.append({
                                'pid': child.pid,
                                'name': child.name()
                            })
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                    
                    if child_info:
                        self.logger.info(f"发现子进程: {child_info}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # 检查是否参与互相监控
            process_relationships = self.analyze_process_relationships()
            if pid in process_relationships:
                monitoring_processes = process_relationships[pid].get('possible_monitoring', [])
                if monitoring_processes:
                    self.logger.warning(f"进程 {process_name} 可能被其他进程监控: {monitoring_processes}")
                    
                    # 尝试同时终止监控进程
                    for monitor_info in monitoring_processes:
                        monitor_pid = monitor_info.get('pid')
                        if monitor_pid and monitor_pid != pid:
                            try:
                                monitor_proc = psutil.Process(monitor_pid)
                                # 同时发起终止，降低互相保护的成功率
                                monitor_proc.terminate()
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                pass
            
            # 尝试终止进程
            try:
                process.terminate()
                
                # 等待进程结束
                gone, alive = psutil.wait_procs([process], timeout=3)
                
                if process in gone:
                    self.logger.info(f"成功终止进程: {process_name} (PID: {pid})")
                    self.handled_processes.add(pid)
                    return True
                else:
                    # 进程仍然存活，尝试强制终止
                    self.logger.warning(f"进程 {process_name} 未响应终止信号，尝试强制终止")
                    process.kill()
                    
                    gone, alive = psutil.wait_procs([process], timeout=2)
                    if process in gone:
                        self.logger.info(f"成功强制终止进程: {process_name} (PID: {pid})")
                        self.handled_processes.add(pid)
                        return True
                    else:
                        self.logger.error(f"无法终止进程: {process_name} (PID: {pid})")
                        return False
            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                self.logger.error(f"终止进程 {process_name} 时出错: {e}")
                return False
        except Exception as e:
            self.logger.error(f"安全终止进程时出错: {e}")
            return False
        
    def stop_monitoring_service(self, service_name: str) -> bool:
        """停止Windows服务"""
        try:
            if not self.is_admin():
                self.logger.warning("没有管理员权限，无法停止服务")
                return False
                
            self.logger.info(f"尝试停止服务: {service_name}")
            
            # 检查服务是否存在
            try:
                service_handle = win32service.OpenService(
                    win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS),
                    service_name,
                    win32service.SERVICE_ALL_ACCESS
                )
                
                # 获取服务状态
                service_status = win32service.QueryServiceStatus(service_handle)
                
                # 检查服务是否在运行
                if service_status[1] == win32service.SERVICE_RUNNING:
                    # 停止服务
                    win32service.ControlService(service_handle, win32service.SERVICE_CONTROL_STOP)
                    
                    # 等待服务停止
                    for _ in range(10):  # 最多等待10秒
                        service_status = win32service.QueryServiceStatus(service_handle)
                        if service_status[1] == win32service.SERVICE_STOPPED:
                            win32service.CloseServiceHandle(service_handle)
                            self.logger.info(f"成功停止服务: {service_name}")
                            return True
                        time.sleep(1)
                    
                    # 如果服务未能停止
                    win32service.CloseServiceHandle(service_handle)
                    self.logger.warning(f"服务 {service_name} 未能停止")
                    return False
                elif service_status[1] == win32service.SERVICE_STOPPED:
                    # 服务已经停止
                    win32service.CloseServiceHandle(service_handle)
                    self.logger.info(f"服务 {service_name} 已经是停止状态")
                    return True
                else:
                    # 服务处于其他状态
                    win32service.CloseServiceHandle(service_handle)
                    self.logger.warning(f"服务 {service_name} 处于状态 {service_status[1]}，无法停止")
                    return False
                
            except Exception as e:
                self.logger.error(f"操作服务 {service_name} 时出错: {e}")
                return False
        except Exception as e:
            self.logger.error(f"停止服务时出错: {e}")
            return False
    
    def disable_autostart(self) -> bool:
        """禁用自启动项"""
        try:
            if not self.is_admin():
                self.logger.warning("没有管理员权限，无法禁用自启动项")
                return False
                
            success = True
            
            # 检查注册表自启动项
            startup_locations = [
                (winreg.HKEY_LOCAL_MACHINE, self.REGISTRY_KEYS["autostart_key"]),
                (winreg.HKEY_LOCAL_MACHINE, self.REGISTRY_KEYS["autostart_key_32"])
            ]
            
            for hkey, key_path in startup_locations:
                try:
                    key = winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
                    
                    # 尝试删除监控程序的自启动键
                    for target in self.startup_keys:
                        try:
                            # 先读取值以备份
                            try:
                                value, _ = winreg.QueryValueEx(key, target)
                                self.logger.info(f"找到自启动项: {target} = {value}")
                            except FileNotFoundError:
                                continue
                                
                            # 删除自启动项
                            winreg.DeleteValue(key, target)
                            self.logger.info(f"已从 {key_path} 删除自启动项 {target}")
                        except FileNotFoundError:
                            # 键不存在，继续检查其他键
                            pass
                        except Exception as e:
                            self.logger.warning(f"删除自启动项 {target} 时出错: {e}")
                            success = False
                    
                    winreg.CloseKey(key)
                except Exception as e:
                    self.logger.warning(f"检查自启动注册表项 {key_path} 时出错: {e}")
                    success = False
            
            return success
        except Exception as e:
            self.logger.error(f"禁用自启动项时出错: {e}")
            return False
    
    def detect_self_replication(self) -> Dict[str, List[str]]:
        """检测并阻止自我复制行为"""
        try:
            result = {
                'suspicious_directories': [],
                'suspicious_files': []
            }
            
            # 检查可疑目录 (przs使用的C:\Program Files (x86)\xxx格式)
            program_files_dir = os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'))
            
            if os.path.exists(program_files_dir):
                for entry in os.scandir(program_files_dir):
                    if entry.is_dir() and len(entry.name) <= 3:
                        # 检查是否有随机名称的可执行文件
                        suspicious_dir = entry.path
                        result['suspicious_directories'].append(suspicious_dir)
                        
                        for file_entry in os.scandir(suspicious_dir):
                            if file_entry.is_file() and file_entry.name.endswith('.exe'):
                                if any(re.match(pattern, file_entry.name) for pattern in self.PRZS_PATTERNS):
                                    result['suspicious_files'].append(file_entry.path)
                                    self.logger.warning(f"发现可疑自复制文件: {file_entry.path}")
            
            return result
        except Exception as e:
            self.logger.error(f"检测自我复制行为时出错: {e}")
            return {
                'suspicious_directories': [],
                'suspicious_files': []
            }
    
    def prevent_window_locking(self) -> bool:
        """防止窗口锁定"""
        try:
            # 这个功能主要由WindowFreedom模块处理
            # 这里只提供基本的检测功能
            
            # 检查是否有Form4窗口，这是przs用于锁定屏幕的窗口
            def enum_windows_callback(hwnd, windows):
                window_title = win32gui.GetWindowText(hwnd)
                for title in ["Form4", "Form2", "机房管理", "禁止"]:
                    if title in window_title and win32gui.IsWindowVisible(hwnd):
                        windows.append((hwnd, window_title))
                return True
            
            lock_windows = []
            win32gui.EnumWindows(enum_windows_callback, lock_windows)
            
            if lock_windows:
                self.logger.warning(f"检测到可能的锁定窗口: {lock_windows}")
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"防止窗口锁定检测时出错: {e}")
            return False
    
    def handle_przs_mutual_monitoring(self) -> bool:
        """处理przs与jfglzs互相监控的机制"""
        try:
            # 分析进程关系
            relationships = self.analyze_process_relationships()
            
            # 查找相互监控的进程
            mutual_monitoring = []
            for pid, info in relationships.items():
                for monitor in info.get('possible_monitoring', []):
                    monitor_pid = monitor.get('pid')
                    if monitor_pid and monitor_pid in relationships:
                        if any(m.get('pid') == pid for m in relationships[monitor_pid].get('possible_monitoring', [])):
                            mutual_monitoring.append((pid, monitor_pid))
            
            if mutual_monitoring:
                self.logger.warning(f"发现互相监控的进程: {mutual_monitoring}")
                
                # 同时终止互相监控的进程
                success = True
                for pid1, pid2 in mutual_monitoring:
                    try:
                        proc1 = psutil.Process(pid1)
                        proc2 = psutil.Process(pid2)
                        
                        # 同时发起终止
                        proc1.terminate()
                        proc2.terminate()
                        
                        # 等待进程结束
                        gone, alive = psutil.wait_procs([proc1, proc2], timeout=3)
                        
                        # 检查结果
                        if proc1 in alive or proc2 in alive:
                            # 有进程仍然存活，尝试强制终止
                            for proc in alive:
                                proc.kill()
                            
                            # 再次等待
                            gone, alive = psutil.wait_procs(alive, timeout=2)
                            
                            if alive:
                                self.logger.error(f"无法终止部分互相监控的进程: {[p.pid for p in alive]}")
                                success = False
                        
                        # 添加到已处理列表
                        self.handled_processes.add(pid1)
                        self.handled_processes.add(pid2)
                    except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                        self.logger.error(f"处理互相监控进程时出错: {e}")
                        success = False
                
                return success
            else:
                self.logger.info("未发现互相监控的进程")
                return True
        except Exception as e:
            self.logger.error(f"处理互相监控机制时出错: {e}")
            return False
    
    def start_monitoring_thread(self):
        """启动监控线程"""
        try:
            # 如果线程已经存在且活动，则不重新启动
            if hasattr(self, '_monitoring_thread') and self._monitoring_thread is not None and self._monitoring_thread.is_alive():
                self.logger.info("监控线程已经在运行")
                return
            
            # 重置停止标志
            self._should_stop = False
            self.monitoring = True
            
            # 创建并启动线程
            self._monitoring_thread = threading.Thread(target=self._monitoring_loop)
            self._monitoring_thread.daemon = True
            self._monitoring_thread.start()
            
            self.logger.info("监控线程已启动")
        except Exception as e:
            self.logger.error(f"启动监控线程时出错: {e}")
            self._monitoring_thread = None
            self.monitoring = False
    
    def _monitoring_loop(self):
        """监控循环，定期检查系统状态"""
        try:
            self.logger.info("监控循环启动")
            
            while not hasattr(self, '_should_stop') or not self._should_stop:
                try:
                    # 清理过期的排除进程记录
                    self._cleanup_excluded_processes()
                    
                    # 记录实际执行状态
                    self.monitoring = True
                    
                    # 每5分钟执行一次完整的反制措施
                    current_time = time.time()
                    if not hasattr(self, 'last_full_scan_time') or current_time - self.last_full_scan_time > 300:  # 5分钟
                        self.logger.info("执行定期完整反制措施...")
                        self._execute_periodic_countermeasure()
                        self.last_full_scan_time = current_time
                    
                    # 清理超时的进程
                    self._cleanup_process_timeout()
                    
                    # 查找并处理可疑进程
                    processes = self._find_processes()
                    
                    # 处理目标进程
                    for proc in processes.get('target', []):
                        try:
                            # 检查是否应该处理此进程
                            if not self._should_process_target(proc):
                                self.logger.debug(f"跳过目标进程 {proc.pid} ({proc.name() if hasattr(proc, 'name') and callable(getattr(proc, 'name')) else 'unknown'})")
                                continue
                            
                            # 增加进程检查计数
                            self._add_to_process_check_count(proc)
                            
                            # 处理已确认的目标进程
                            self.logger.info(f"发现已知目标进程: {proc.name()} (PID: {proc.pid})")
                            # 降低进程权限
                            try:
                                from .privilege_manager import PrivilegeManager
                                privilege_manager = PrivilegeManager()
                                privilege_manager.lower_process_privilege(proc.pid)
                            except Exception as e:
                                self.logger.error(f"降低进程权限时出错: {e}")
                                
                            # 终止进程
                            self.safe_terminate_process(proc)
                        except Exception as e:
                            self.logger.error(f"处理目标进程 {proc.pid} 时出错: {e}")
                    
                    # 处理可疑进程
                    for proc in processes.get('suspicious', []):
                        try:
                            # 检查是否应该处理此进程
                            if not self._should_process_target(proc):
                                self.logger.debug(f"跳过可疑进程 {proc.pid} ({proc.name() if hasattr(proc, 'name') and callable(getattr(proc, 'name')) else 'unknown'})")
                                continue
                            
                            # 增加进程检查计数
                            self._add_to_process_check_count(proc)
                            
                            # 获取进程签名
                            signature = self.get_process_signature(proc)
                            
                            # 如果有可疑特征，尝试终止它
                            if signature.get('is_suspicious', False):
                                # 如果有可疑特征，记录并处理
                                self.logger.info(f"发现可疑进程: {proc.name()} (PID: {proc.pid}), 原因: {', '.join(signature.get('reason', []))}")
                                
                                # 如果确实有可疑特征，则终止进程
                                if proc.pid in self.excluded_processes and self.excluded_processes[proc.pid]["has_suspicious"]:
                                    try:
                                        # 降低进程权限
                                        from .privilege_manager import PrivilegeManager
                                        privilege_manager = PrivilegeManager()
                                        privilege_manager.lower_process_privilege(proc.pid)
                                    except Exception as e:
                                        self.logger.error(f"降低进程权限时出错: {e}")
                                    
                                    # 终止进程
                                    self.safe_terminate_process(proc)
                        except Exception as e:
                            self.logger.error(f"处理可疑进程 {proc.pid} 时出错: {e}")
                    
                    # 检查进程间关系
                    try:
                        relationships = self.analyze_process_relationships()
                        if relationships:
                            self.logger.info(f"发现 {len(relationships)} 个进程关系")
                            self.process_relationships = relationships
                    except Exception as e:
                        self.logger.error(f"分析进程关系时出错: {e}")
                    
                    # 检查并处理锁定窗口
                    try:
                        # 确保window_freedom属性可用
                        self._ensure_window_freedom()
                        
                        if hasattr(self, 'window_freedom') and self.window_freedom:
                            # 处理锁定窗口
                            lock_count = self.window_freedom.handle_lock_windows()
                            if lock_count > 0:
                                self.logger.info(f"处理了 {lock_count} 个锁定窗口")
                            
                            # 防止屏幕锁定
                            self.window_freedom.prevent_screen_locking()
                    except Exception as e:
                        self.logger.error(f"处理锁定窗口时出错: {e}")
                
                except Exception as e:
                    self.logger.error(f"监控循环中出错: {e}")
                
                # 休眠一段时间
                time.sleep(10)  # 每10秒检查一次
            
            self.logger.info("监控循环已退出")
        
        except Exception as e:
            self.logger.error(f"监控循环发生严重错误: {e}")
            self.monitoring = False
    
    def _should_process_target(self, proc):
        """
        判断是否应该处理目标进程
        
        Args:
            proc: psutil.Process对象
            
        Returns:
            bool: 如果应该处理目标进程则返回True，否则返回False
        """
        try:
            # 检查进程是否还存在
            if not psutil.pid_exists(proc.pid):
                return False
                
            # 获取进程名，用于日志
            try:
                proc_name = proc.name() if hasattr(proc, 'name') and callable(getattr(proc, 'name')) else f"PID:{proc.pid}"
            except Exception:
                proc_name = f"PID:{proc.pid}"
            
            # 显式排除smss.exe
            if proc_name.lower() == "smss.exe":
                return False
                
            # 跳过已排除的进程
            if hasattr(self, 'excluded_processes') and proc.pid in self.excluded_processes:
                exclude_info = self.excluded_processes[proc.pid]
                current_time = time.time()
                
                # 如果排除时间未到，跳过此进程
                if current_time < exclude_info.get("exclude_until", 0):
                    remaining = int(exclude_info['exclude_until'] - current_time)
                    self.logger.debug(f"跳过进程 {proc.pid} ({exclude_info.get('name', proc_name)})，排除期还有 {remaining} 秒")
                    return False
                else:
                    # 排除期已过，从排除列表中移除
                    if exclude_info.get("exclude_until", 0) > 0:
                        self.logger.debug(f"进程 {proc.pid} ({exclude_info.get('name', proc_name)}) 排除期已过，恢复检查")
                    del self.excluded_processes[proc.pid]
            
            # 跳过自身
            if proc.pid == os.getpid():
                return False
                
            # 跳过自保护进程
            if hasattr(self, 'self_protection') and self.self_protection and self.self_protection.is_protected(proc.pid):
                return False
            
            # 跳过受信任的进程
            try:
                proc_name = proc.name().lower()
                # 系统关键进程列表
                trusted_processes = [
                    "system", "smss.exe", "csrss.exe", "wininit.exe", 
                    "services.exe", "lsass.exe", "winlogon.exe", 
                    "explorer.exe", "svchost.exe", "dllhost.exe",
                    "spoolsv.exe", "msdtc.exe", "taskhost.exe",
                    "taskhostw.exe", "taskmgr.exe", "conhost.exe",
                    "dwm.exe", "fontdrvhost.exe"
                ]
                
                # 常见浏览器列表
                trusted_browsers = [
                    "chrome.exe", "firefox.exe", "iexplore.exe", 
                    "microsoftedge.exe", "msedge.exe", "brave.exe", 
                    "opera.exe", "safari.exe"
                ]
                
                # 常见程序列表
                common_programs = [
                    "notepad.exe", "calc.exe", "regedit.exe", "mspaint.exe", 
                    "outlook.exe", "excel.exe", "word.exe", "powerpnt.exe",
                    "teams.exe", "code.exe", "devenv.exe", "pythonw.exe", 
                    "python.exe", "cmd.exe", "powershell.exe", "ping.exe",
                    "todesk.exe", "teamviewer.exe", "skype.exe", "zoom.exe",
                    "wechat.exe", "qqmusic.exe", "qq.exe", "wpspdf.exe"
                ]
                
                # 检查是否是受信任的进程
                if (proc_name in trusted_processes or 
                    proc_name in trusted_browsers or 
                    proc_name in common_programs):
                    return False
                    
            except Exception as e:
                self.logger.error(f"检查进程名时出错: {e}")
                
            # 默认处理其他进程
            return True
            
        except Exception as e:
            self.logger.error(f"判断是否处理进程时出错: {e}")
            return False
    
    def _check_process_has_suspicious_features(self, pid):
        """
        检查进程是否具有可疑特征（如可疑窗口或计时器）
        
        Args:
            pid: 进程ID
            
        Returns:
            bool: 如果进程具有可疑特征则返回True，否则返回False
        """
        try:
            # 检查进程是否存在
            if not psutil.pid_exists(pid):
                return False
            
            # 获取进程对象
            proc = psutil.Process(pid)
            
            # 检查是否有可疑窗口
            has_suspicious_window = False
            windows = []
            
            def enum_windows_callback(hwnd, windows_list):
                try:
                    # 检查窗口是否属于目标进程
                    _, window_pid = win32process.GetWindowThreadProcessId(hwnd)
                    if window_pid == pid and win32gui.IsWindowVisible(hwnd):
                        # 获取窗口标题和类名
                        title = win32gui.GetWindowText(hwnd)
                        class_name = win32gui.GetClassName(hwnd)
                        
                        # 初始化window_freedom确保LOCK_WINDOW_TITLES和LOCK_WINDOW_CLASSES可用
                        if not hasattr(self, 'window_freedom') or self.window_freedom is None:
                            self._ensure_window_freedom()
                        
                        if hasattr(self, 'window_freedom'):
                            # 检查窗口标题
                            for keyword in self.window_freedom.LOCK_WINDOW_TITLES:
                                if keyword.lower() in title.lower():
                                    windows_list.append({
                                        "hwnd": hwnd,
                                        "title": title,
                                        "class": class_name,
                                        "suspicious": True,
                                        "reason": f"窗口标题包含关键字 '{keyword}'"
                                    })
                                    return
                            
                            # 检查窗口类名
                            for keyword in self.window_freedom.LOCK_WINDOW_CLASSES:
                                if keyword.lower() in class_name.lower():
                                    windows_list.append({
                                        "hwnd": hwnd,
                                        "title": title,
                                        "class": class_name,
                                        "suspicious": True,
                                        "reason": f"窗口类名包含关键字 '{keyword}'"
                                    })
                                    return
                        
                        # 检查窗口属性
                        window_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
                        if window_style & win32con.WS_EX_TOPMOST:
                            windows_list.append({
                                "hwnd": hwnd,
                                "title": title,
                                "class": class_name,
                                "suspicious": True,
                                "reason": "窗口具有置顶属性"
                            })
                            return
                except Exception:
                    pass  # 忽略单个窗口的错误，继续枚举
            
            # 确保window_freedom属性可用
            self._ensure_window_freedom()
            
            # 枚举进程的窗口
            try:
                win32gui.EnumWindows(enum_windows_callback, windows)
                has_suspicious_window = any(window.get("suspicious", False) for window in windows)
                
                # 如果没有可疑窗口但是进程名可疑，仍然返回True
                proc_name = proc.name().lower()
                if proc_name in [p.lower() for p in self.TARGET_PROCESSES]:
                    return True
                
                for pattern in self.PRZS_PATTERNS:
                    if re.match(pattern, proc_name, re.IGNORECASE):
                        return True
                
                return has_suspicious_window
            
            except Exception as e:
                self.logger.error(f"检查进程窗口时出错: {e}")
                return False
        
        except Exception as e:
            self.logger.error(f"检查进程可疑特征时出错 (PID: {pid}): {e}")
            return False
    
    def _add_to_process_check_count(self, proc):
        """
        增加进程检查计数，必要时将其添加到排除列表
        
        Args:
            proc: psutil.Process对象
        """
        try:
            current_time = time.time()
            pid = proc.pid
            
            # 初始化或更新进程检查信息
            if pid not in self.excluded_processes:
                proc_name = proc.name() if hasattr(proc, 'name') and callable(getattr(proc, 'name')) else "unknown"
                self.excluded_processes[pid] = {
                    "count": 1,
                    "last_check": current_time,
                    "exclude_until": 0,  # 0表示不排除
                    "has_suspicious": False,
                    "name": proc_name,
                }
                self.logger.debug(f"首次检查进程 {pid} ({proc_name})")
            else:
                # 更新检查计数和时间
                self.excluded_processes[pid]["count"] += 1
                self.excluded_processes[pid]["last_check"] = current_time
                self.logger.debug(f"进程 {pid} ({self.excluded_processes[pid]['name']}) 检查计数: {self.excluded_processes[pid]['count']}")
            
            # 检查是否有可疑特征
            has_suspicious = self._check_process_has_suspicious_features(pid)
            self.excluded_processes[pid]["has_suspicious"] = has_suspicious
            
            # 如果检查次数达到5次且没有可疑特征，将其排除5分钟
            if self.excluded_processes[pid]["count"] >= 5 and not has_suspicious:
                exclude_time = current_time + 300  # 5分钟 = 300秒
                self.excluded_processes[pid]["exclude_until"] = exclude_time
                proc_name = self.excluded_processes[pid]["name"]
                self.logger.info(f"进程 {pid} ({proc_name}) 已被排除5分钟，因为它被检查了5次且没有可疑特征")
        
        except Exception as e:
            self.logger.error(f"更新进程检查计数时出错: {e}")
            
    def _cleanup_excluded_processes(self):
        """清理过期的排除进程记录"""
        try:
            if not hasattr(self, 'excluded_processes'):
                self.excluded_processes = {}
                return
                
            current_time = time.time()
            to_remove = []
            
            # 找出需要移除的进程（排除期已过或进程不存在）
            for pid, info in self.excluded_processes.items():
                if info["exclude_until"] > 0 and current_time > info["exclude_until"]:
                    to_remove.append(pid)
                    self.logger.debug(f"进程 {pid} ({info['name']}) 排除期已过，从排除列表中移除")
                elif not psutil.pid_exists(pid):
                    to_remove.append(pid)
                    self.logger.debug(f"进程 {pid} ({info['name']}) 已不存在，从排除列表中移除")
            
            # 移除过期条目
            for pid in to_remove:
                del self.excluded_processes[pid]
                
            # 记录日志
            if to_remove:
                self.logger.debug(f"已清理 {len(to_remove)} 个排除进程记录")
        
        except Exception as e:
            self.logger.error(f"清理排除进程记录时出错: {e}")
            # 确保不抛出异常
            self.excluded_processes = {}
    
    def _execute_periodic_countermeasure(self):
        """执行定期（5分钟）完整反制措施，执行步骤1-6"""
        try:
            self.logger.info("开始执行5分钟定期完整反制措施...")
            
            # 0. 检查并解除鼠标限制（如果需要）
            self.logger.info("步骤0: 检查并解除鼠标限制")
            self._ensure_window_freedom()
            if hasattr(self, 'window_freedom') and self.window_freedom is not None:
                try:
                    # 先检查鼠标是否确实被限制
                    if self.window_freedom.is_cursor_clipped():
                        self.window_freedom.force_free_cursor()
                        self.logger.info("成功解除鼠标限制")
                    else:
                        self.logger.info("鼠标未被限制，无需解除")
                except Exception as e:
                    self.logger.error(f"解除鼠标限制时出错: {e}")
            
            # 1. 处理互相监控机制
            self.logger.info("步骤1: 处理互相监控机制")
            self.handle_przs_mutual_monitoring()
            
            # 2. 禁用注册表限制
            self.logger.info("步骤2: 禁用注册表限制")
            self.disable_registry_restrictions()
            
            # 3. 停止相关服务
            self.logger.info("步骤3: 停止相关服务")
            for service in ["zmserv", "tdnetfilter", "tdfilefilter"]:
                self.stop_monitoring_service(service)
            
            # 4. 禁用自启动项
            self.logger.info("步骤4: 禁用自启动项")
            self.disable_autostart()
            
            # 5. 检测并处理自我复制行为
            self.logger.info("步骤5: 检测自我复制行为")
            replication_result = self.detect_self_replication()
            
            # 6. 清理超时的进程检查记录
            self.logger.info("步骤6: 清理过期的进程检查记录")
            self._cleanup_process_timeout()
            
            self.logger.info("5分钟定期完整反制措施执行完成")
        except Exception as e:
            self.logger.error(f"执行5分钟定期完整反制措施时出错: {e}")

    def _cleanup_process_timeout(self):
        """清理过期的进程检查超时记录"""
        try:
            if not hasattr(self, 'process_check_timeout'):
                self.process_check_timeout = {}
                return
            
            current_time = time.time()
            expired_processes = []
            
            # 找出所有过期的记录
            for proc_name, next_check_time in self.process_check_timeout.items():
                if current_time >= next_check_time:
                    expired_processes.append(proc_name)
            
            # 移除过期记录
            for proc_name in expired_processes:
                del self.process_check_timeout[proc_name]
            
            if expired_processes:
                self.logger.info(f"已清理 {len(expired_processes)} 个过期的进程检查记录")
        except Exception as e:
            self.logger.error(f"清理过期进程检查记录时出错: {e}")
            # 重置超时字典
            self.process_check_timeout = {}

    def _find_processes(self, random_mode=False):
        """
        查找可疑进程的内部方法，支持随机模式
        @param random_mode: 如果为True，则使用轻量级扫描并随机化行为
        """
        try:
            # 确保lock存在
            if not hasattr(self, 'lock'):
                self.logger.warning("查找进程时发现lock未初始化，正在创建")
                self.lock = threading.RLock()
                
            # 确保found_targets存在
            if not hasattr(self, 'found_targets'):
                self.logger.warning("查找进程时发现found_targets未初始化，正在创建")
                self.found_targets = []
                
            # 确保handled_processes存在
            if not hasattr(self, 'handled_processes'):
                self.logger.warning("查找进程时发现handled_processes未初始化，正在创建")
                self.handled_processes = set()
                
            # 确保suspicious_processes存在
            if not hasattr(self, 'suspicious_processes'):
                self.logger.warning("查找进程时发现suspicious_processes未初始化，正在创建")
                self.suspicious_processes = {}
                
            # 获取所有进程
            all_processes = []
            try:
                all_processes = list(psutil.process_iter())
            except Exception as e:
                self.logger.error(f"获取进程列表时出错: {e}")
                return {'target': [], 'suspicious': [], 'random': []}
                
            # 随机模式下，随机化遍历顺序，降低被检测概率
            if random_mode:
                random.shuffle(all_processes)
                
            result = {
                'target': [],
                'suspicious': [],
                'random': []
            }
            
            # 随机模式下，随机跳过一些进程，进一步降低被检测概率
            process_sample = all_processes
            if random_mode and len(all_processes) > 20:  # 至少有20个进程时才采样
                sample_size = int(len(all_processes) * random.uniform(0.7, 0.9))
                process_sample = random.sample(all_processes, sample_size)
            
            for proc in process_sample:
                try:
                    # 跳过已经不存在的进程
                    if not psutil.pid_exists(proc.pid):
                        continue
                        
                    # 随机模式下，小概率休眠以进一步随机化行为
                    if random_mode and random.random() < 0.1:  # 10%概率
                        time.sleep(random.uniform(0.01, 0.05))
                    
                    # 确保进程信息可访问
                    try:    
                        proc_name = proc.name().lower()  # 转小写统一处理
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    
                    # 检查是否为目标进程
                    # 确保TARGET_PROCESSES存在
                    if not hasattr(self, 'TARGET_PROCESSES'):
                        self.logger.warning("查找进程时发现TARGET_PROCESSES未初始化，使用默认列表")
                        self.TARGET_PROCESSES = ["przs.exe", "jfglzs.exe", "scmdaemon.exe", "xwzc.exe"]
                        
                    if proc_name in [p.lower() for p in self.TARGET_PROCESSES]:
                        result['target'].append(proc)
                        if not random_mode:  # 随机模式下减少日志输出
                            self.logger.info(f"发现目标进程: {proc_name} (PID: {proc.pid})")
                    
                    # 检查是否为可疑随机进程名
                    elif hasattr(self, 'is_suspicious_process_name') and callable(self.is_suspicious_process_name):
                        if self.is_suspicious_process_name(proc_name):
                            result['suspicious'].append(proc)
                            result['random'].append(proc)
                            if not random_mode:  # 随机模式下减少日志输出
                                self.logger.info(f"发现可疑随机进程: {proc_name} (PID: {proc.pid})")
                            
                            # 添加到可疑进程字典
                            if hasattr(self, 'get_process_signature') and callable(self.get_process_signature):
                                try:
                                    signature = self.get_process_signature(proc)
                                    with self.lock:
                                        self.suspicious_processes[proc.pid] = signature
                                except Exception as e:
                                    if not random_mode:  # 随机模式下减少日志输出
                                        self.logger.error(f"获取进程签名时出错: {e}")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    if not random_mode:  # 随机模式下减少日志输出
                        self.logger.error(f"处理进程时出错: {e}")
            
            # 分析进程关系，但在随机模式下有50%概率跳过，降低被检测概率
            if not random_mode or random.random() < 0.5:
                if (result['target'] or result['suspicious']) and hasattr(self, 'analyze_process_relationships'):
                    try:
                        self.analyze_process_relationships()
                    except Exception as e:
                        self.logger.error(f"分析进程关系时出错: {e}")
            
            # 更新found_targets以便其他方法可以访问结果
            with self.lock:
                # 将新发现的目标添加到found_targets，避免重复
                for proc in result['target'] + result['suspicious']:
                    # 检查进程是否仍存在
                    if hasattr(proc, 'pid') and psutil.pid_exists(proc.pid):
                        if proc.pid not in [p.pid for p in self.found_targets if hasattr(p, 'pid')]:
                            try:
                                # 再次确认进程名
                                _ = proc.name()  # 如果进程已终止会抛出异常
                                self.found_targets.append(proc)
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
            
            self.logger.debug(f"查找进程完成: 发现 {len(result['target'])} 个目标, {len(result['suspicious'])} 个可疑进程")
            return result
        except Exception as e:
            self.logger.error(f"查找进程(_find_processes)时出错: {e}")
            return {'target': [], 'suspicious': [], 'random': []}

    def execute_full_countermeasure(self) -> bool:
        """执行完整的反制措施"""
        try:
            self.logger.info("开始执行完整反制措施...")
            results = {
                "admin_check": False,
                "mutual_monitoring": False,
                "registry_restrictions": False,
                "services": False,
                "autostart": False,
                "self_replication": False,
                "processes": False,
                "monitoring": False,
                "system_tools": False  # 添加系统工具恢复结果
            }
            
            # 1. 检查管理员权限
            if not self.is_admin():
                self.logger.warning("没有管理员权限，部分功能可能受限")
                results["admin_check"] = False
            else:
                self.logger.info("已获取管理员权限")
                results["admin_check"] = True
            
            # 2. 处理互相监控
            self.logger.info("检查和处理互相监控...")
            results["mutual_monitoring"] = self.handle_przs_mutual_monitoring()
            
            # 3. 禁用注册表限制
            self.logger.info("禁用注册表限制...")
            results["registry_restrictions"] = self.disable_registry_restrictions()
            
            # 4. 停止服务
            self.logger.info("停止监控服务...")
            results["services"] = self.stop_monitoring_service("zmserv")
            
            # 5. 禁用自启动
            self.logger.info("禁用自启动项...")
            results["autostart"] = self.disable_autostart()
            
            # 6. 检测自我复制
            self.logger.info("检测自我复制...")
            replication_results = self.detect_self_replication()
            results["self_replication"] = len(replication_results.get("copies", [])) > 0
            
            # 7. 恢复被禁用的系统工具
            self.logger.info("恢复被禁用的系统工具...")
            results["system_tools"] = self.restore_disabled_system_tools()
            
            # 8. 终止目标进程
            self.logger.info("终止目标进程...")
            target_processes = self.scan_target_processes()
            terminated_count = 0
            for process_list in target_processes.values():
                for process in process_list:
                    if self.safe_terminate_process(process):
                        terminated_count += 1
            results["processes"] = terminated_count > 0
            
            # 9. 开始持续监控
            self.logger.info("启动持续监控...")
            # 检查_monitoring_thread是否已定义并且没有在运行
            if not hasattr(self, '_monitoring_thread') or self._monitoring_thread is None or not self._monitoring_thread.is_alive():
                self.start_monitoring_thread()
                results["monitoring"] = True
            else:
                self.logger.info("监控线程已经在运行")
                results["monitoring"] = True
            
            # 总结结果
            success_count = sum(1 for result in results.values() if result)
            self.logger.info(f"完整反制措施完成: {success_count}/{len(results)} 项成功")
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"执行完整反制措施时出错: {e}")
            return False

    def restore_disabled_system_tools(self) -> bool:
        """
        恢复被禁用的系统工具
        通过删除注册表中的Image File Execution Options下的Debugger值来恢复
        """
        try:
            self.logger.info("开始恢复被禁用的系统工具...")
            success_count = 0
            failure_count = 0
            
            for tool in self.DISABLED_SYSTEM_TOOLS:
                try:
                    # 构建注册表路径
                    reg_path = f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{tool}"
                    
                    # 尝试删除Debugger值
                    try:
                        import winreg
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, 
                                           winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
                        winreg.DeleteValue(key, "Debugger")
                        winreg.CloseKey(key)
                        self.logger.info(f"成功恢复系统工具: {tool}")
                        success_count += 1
                    except FileNotFoundError:
                        # 如果键不存在，则说明该工具没有被禁用
                        self.logger.debug(f"系统工具 {tool} 没有被禁用")
                        success_count += 1
                    except PermissionError:
                        # 如果没有权限，尝试使用管理员权限
                        self.logger.warning(f"没有权限修复 {tool}，尝试使用管理员权限...")
                        
                        # 通过调用reg.exe删除键值
                        import subprocess
                        cmd = f'reg delete "HKLM\\{reg_path}" /v Debugger /f'
                        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                        
                        if process.returncode == 0:
                            self.logger.info(f"使用reg.exe成功恢复系统工具: {tool}")
                            success_count += 1
                        else:
                            self.logger.error(f"使用reg.exe恢复系统工具 {tool} 失败: {process.stderr}")
                            failure_count += 1
                    except Exception as tool_error:
                        self.logger.error(f"恢复系统工具 {tool} 时发生错误: {tool_error}")
                        failure_count += 1
                except Exception as e:
                    self.logger.error(f"处理系统工具 {tool} 时发生异常: {e}")
                    failure_count += 1
            
            self.logger.info(f"系统工具恢复完成: 成功 {success_count} 个, 失败 {failure_count} 个")
            return success_count > 0 and failure_count == 0
            
        except Exception as e:
            self.logger.error(f"恢复被禁用的系统工具时出错: {e}")
            return False 

    def _ensure_window_freedom(self):
        """确保window_freedom属性已初始化"""
        try:
            if not hasattr(self, 'window_freedom') or self.window_freedom is None:
                from .window_freedom import WindowFreedom
                self.window_freedom = WindowFreedom()
                self.logger.debug("窗口自由模块已初始化")
            return True
        except Exception as e:
            self.logger.error(f"初始化窗口自由模块时出错: {e}")
            return False