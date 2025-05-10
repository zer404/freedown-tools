#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
集成反制措施模块
整合随机进程分析、窗口自由和反制管理器功能
"""

import os
import sys
import time
import logging
import threading
import traceback
from typing import Dict, List, Any, Optional

from .countermeasure_manager import CountermeasureManager
from .window_freedom import WindowFreedom
from .random_process_analyzer import RandomProcessAnalyzer

# 配置日志记录器
logger = logging.getLogger("IntegratedCountermeasure")

class IntegratedCountermeasure:
    """集成反制措施类，整合所有功能"""
    
    def __init__(self):
        """初始化集成反制措施"""
        try:
            # 初始化日志
            logger.info("初始化集成反制措施...")
            
            # 初始化状态标志
            self.is_running = False
            self.protection_active = False
            self.main_window_hwnd = None
            
            # 初始化组件
            self.window_freedom = None  # 延迟初始化，避免过早访问Windows API
            self.countermeasure_manager = None  # 延迟初始化
            
            # 初始化状态监控线程
            self.status_thread = None
            self.status_lock = threading.RLock()
            self.status = {
                'is_running': False,
                'protection_active': False,
                'targets_found': 0,
                'cursor_restricted': False,
                'found_targets': []
            }
            
            # 初始化随机进程分析器
            try:
                self.random_process_analyzer = RandomProcessAnalyzer()
            except Exception as e:
                logger.error(f"初始化随机进程分析器时出错: {e}")
                self.random_process_analyzer = None
            
            logger.info("集成反制措施初始化完成")
        except Exception as e:
            logger.error(f"初始化集成反制措施时出错: {e}")
            # 确保基本属性被初始化，即使发生错误
            if not hasattr(self, 'is_running'):
                self.is_running = False
            if not hasattr(self, 'protection_active'):
                self.protection_active = False
            if not hasattr(self, 'status'):
                self.status = {
                    'is_running': False,
                    'protection_active': False,
                    'targets_found': 0,
                    'cursor_restricted': False,
                    'found_targets': []
                }
            if not hasattr(self, 'status_lock'):
                self.status_lock = threading.RLock()
            
            traceback.print_exc()
    
    def register_window(self, hwnd: int) -> bool:
        """注册主窗口句柄"""
        try:
            logger.info(f"注册主窗口句柄: {hwnd}")
            self.main_window_hwnd = hwnd
            return True
        except Exception as e:
            logger.error(f"注册主窗口句柄时出错: {e}")
            return False
    
    def start_protection(self) -> bool:
        """启动完整保护"""
        try:
            logger.info("启动完整保护...")
            
            # 如果已经在运行，返回True
            if hasattr(self, 'is_running') and self.is_running:
                logger.info("保护已经在运行中")
                return True
                
            # 初始化窗口自由模块
            if not hasattr(self, 'window_freedom') or self.window_freedom is None:
                try:
                    logger.info("初始化窗口自由模块...")
                    self.window_freedom = WindowFreedom()
                except Exception as e:
                    logger.error(f"初始化窗口自由模块失败: {e}")
                    # 失败时不终止整个操作，继续尝试其他功能
            
            # 初始化反制管理器
            if not hasattr(self, 'countermeasure_manager') or self.countermeasure_manager is None:
                try:
                    logger.info("初始化反制管理器...")
                    self.countermeasure_manager = CountermeasureManager()
                except Exception as e:
                    logger.error(f"初始化反制管理器失败: {e}")
                    # 如果反制管理器初始化失败，尝试恢复被禁用的系统工具
                    self._attempt_recover_system_tools()
            
            # 启动状态监控线程
            self.is_running = True
            self.protection_active = True
            
            if not hasattr(self, 'status_thread') or self.status_thread is None or not self.status_thread.is_alive():
                try:
                    logger.info("启动状态监控线程...")
                    self.status_thread = threading.Thread(target=self._status_monitoring_loop, daemon=True)
                    self.status_thread.start()
                except Exception as e:
                    logger.error(f"启动状态监控线程失败: {e}")
                    # 线程启动失败不影响其他功能
            
            # 执行一次全面反制
            success = False
            if hasattr(self, 'countermeasure_manager') and self.countermeasure_manager is not None:
                try:
                    success = self.countermeasure_manager.execute_full_countermeasure()
                except Exception as e:
                    logger.error(f"执行全面反制时出错: {e}")
            
            logger.info(f"完整保护已启动，反制结果: {'成功' if success else '部分功能可能未生效'}")
            return True
        except Exception as e:
            logger.error(f"启动保护时出错: {e}")
            traceback.print_exc()
            if hasattr(self, 'is_running'):
                self.is_running = False
            if hasattr(self, 'protection_active'):
                self.protection_active = False
            return False
    
    def _attempt_recover_system_tools(self):
        """尝试恢复系统工具，即使反制管理器初始化失败"""
        try:
            logger.info("尝试直接恢复系统工具...")
            
            # 系统工具列表，与CountermeasureManager中的一致
            system_tools = [
                "taskkill.exe", "ntsd.exe", "sidebar.exe", "Chess.exe",
                "FreeCell.exe", "Hearts.exe", "Minesweeper.exe", "PurblePlace.exe",
                "Mahjong.exe", "SpiderSolitaire.exe", "bckgzm.exe", "chkrzm.exe",
                "shvlzm.exe", "Solitaire.exe", "winmine.exe", "Magnify.exe",
                "sethc.exe", "QQPCTray.exe"
            ]
            
            # 尝试使用reg.exe恢复系统工具
            import subprocess
            success_count = 0
            
            for tool in system_tools:
                try:
                    reg_path = f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{tool}"
                    cmd = f'reg delete "HKLM\\{reg_path}" /v Debugger /f'
                    process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if process.returncode == 0:
                        logger.info(f"成功恢复系统工具: {tool}")
                        success_count += 1
                except Exception as e:
                    logger.error(f"恢复系统工具 {tool} 时出错: {e}")
            
            logger.info(f"直接恢复系统工具完成: 成功 {success_count} 个")
        except Exception as e:
            logger.error(f"尝试恢复系统工具时出错: {e}")
    
    def stop_protection(self) -> bool:
        """停止保护"""
        try:
            logger.info("正在停止保护...")
            
            # 先检查属性是否存在
            if not hasattr(self, 'is_running') or not self.is_running:
                logger.info("保护未在运行，无需停止")
                # 确保状态正确
                if hasattr(self, 'is_running'):
                    self.is_running = False
                if hasattr(self, 'protection_active'):
                    self.protection_active = False
                return True
            
            # 停止保护
            self.protection_active = False
            
            # 停止反制管理器
            if hasattr(self, 'countermeasure_manager') and self.countermeasure_manager is not None:
                try:
                    logger.info("停止反制管理器...")
                    self.countermeasure_manager.stop_monitoring_thread()
                except Exception as e:
                    logger.error(f"停止反制管理器时出错: {e}")
            
            logger.info("保护已停止")
            return True
        except Exception as e:
            logger.error(f"停止保护时出错: {e}")
            traceback.print_exc()
            # 确保状态正确
            if hasattr(self, 'protection_active'):
                self.protection_active = False
            return False
    
    def _status_monitoring_loop(self) -> None:
        """状态监控循环"""
        try:
            logger.info("状态监控线程启动")
            
            # 上次检查光标状态的时间
            last_cursor_check_time = 0
            
            while hasattr(self, 'is_running') and self.is_running:
                try:
                    current_time = time.time()
                    
                    # 更新状态信息
                    with self.status_lock:
                        self.status['is_running'] = self.is_running
                        self.status['protection_active'] = self.protection_active
                        
                        # 获取反制管理器状态
                        if hasattr(self, 'countermeasure_manager') and self.countermeasure_manager is not None:
                            try:
                                # 确保countermeasure_manager的方法存在
                                if hasattr(self.countermeasure_manager, 'get_found_targets'):
                                    targets = self.countermeasure_manager.get_found_targets()
                                    self.status['found_targets'] = targets
                                    self.status['targets_found'] = len(targets)
                                else:
                                    logger.warning("反制管理器缺少get_found_targets方法")
                                    self.status['found_targets'] = []
                                    self.status['targets_found'] = 0
                            except Exception as e:
                                logger.error(f"获取目标列表时出错: {e}")
                                self.status['found_targets'] = []
                                self.status['targets_found'] = 0
                        else:
                            self.status['found_targets'] = []
                            self.status['targets_found'] = 0
                        
                        # 只有在保护功能已激活时才检查光标状态，每15秒检查一次
                        if self.protection_active and (current_time - last_cursor_check_time) >= 15:
                            # 检查window_freedom是否已初始化，如果没有则初始化
                            if not hasattr(self, 'window_freedom') or self.window_freedom is None:
                                try:
                                    logger.info("状态循环中延迟初始化窗口自由模块...")
                                    self.window_freedom = WindowFreedom()
                                except Exception as e:
                                    logger.error(f"状态循环中初始化窗口自由模块失败: {e}")
                                    self.status['cursor_restricted'] = False
                                    continue  # 跳过本次循环的剩余部分
                            
                            # 检查鼠标状态
                            if hasattr(self, 'window_freedom') and self.window_freedom is not None:
                                try:
                                    cursor_restricted = self.window_freedom.is_cursor_clipped()
                                    self.status['cursor_restricted'] = cursor_restricted
                                    
                                    # 只记录状态，不自动释放
                                    if cursor_restricted:
                                        logger.info("检测到鼠标限制，状态已更新")
                                except Exception as e:
                                    logger.error(f"检查鼠标限制时出错: {e}")
                                    self.status['cursor_restricted'] = False
                            else:
                                self.status['cursor_restricted'] = False
                                
                            last_cursor_check_time = current_time
                    
                    # 如果保护功能已激活，执行实时反制
                    if self.protection_active:
                        # 使用随机间隔执行反制，避免被检测
                        if hasattr(self, 'countermeasure_manager') and self.countermeasure_manager is not None:
                            try:
                                # 确保countermeasure_manager的方法存在
                                if hasattr(self.countermeasure_manager, 'execute_random_analysis'):
                                    self.countermeasure_manager.execute_random_analysis()
                            except Exception as e:
                                logger.error(f"执行实时反制时出错: {e}")
                    
                    # 休眠一段时间
                    time.sleep(3)
                except Exception as e:
                    logger.error(f"状态更新循环出错: {e}")
                    time.sleep(3)  # 出错后等待一段时间再继续
            
            logger.info("状态监控线程已退出")
        except Exception as e:
            logger.error(f"状态监控循环发生严重错误: {e}")
            traceback.print_exc()
    
    def get_status(self) -> Dict[str, Any]:
        """获取当前状态"""
        try:
            with self.status_lock:
                return self.status.copy()
        except Exception as e:
            logger.error(f"获取状态时出错: {e}")
            return {
                'is_running': False,
                'protection_active': False,
                'targets_found': 0,
                'cursor_restricted': False,
                'found_targets': []
            }
    
    def emergency_unlock(self) -> bool:
        """紧急解锁功能，释放鼠标并处理锁定窗口"""
        try:
            logger.info("执行紧急解锁...")
            result = False
            
            # 初始化窗口自由模块（如果未初始化）
            if not hasattr(self, 'window_freedom') or self.window_freedom is None:
                try:
                    logger.info("紧急解锁时初始化窗口自由模块...")
                    from .window_freedom import WindowFreedom
                    self.window_freedom = WindowFreedom()
                except Exception as e:
                    logger.error(f"紧急解锁时初始化窗口自由模块失败: {e}")
                    return False
            
            # 确保window_freedom存在
            if hasattr(self, 'window_freedom') and self.window_freedom is not None:
                try:
                    # 强制释放鼠标光标（不检查是否被限制，直接解除）
                    logger.info("紧急解锁: 强制释放鼠标光标")
                    self.window_freedom.force_free_cursor()
                    
                    # 找到并处理所有锁定窗口
                    lock_windows = self.window_freedom.find_lock_windows(force_refresh=True)
                    lock_windows_count = len(lock_windows)
                    logger.info(f"紧急解锁: 发现 {lock_windows_count} 个锁定窗口")
                    
                    # 处理每个锁定窗口
                    for window in lock_windows:
                        logger.info(f"紧急解锁: 正在处理窗口 '{window.get('title', '未知')}' (hwnd: {window['hwnd']})")
                        self.window_freedom.close_window(window['hwnd'])
                    
                    # 禁用锁定计时器
                    self.window_freedom.disable_lock_timers()
                    
                    # 再次强制释放鼠标
                    self.window_freedom.force_free_cursor()
                    
                    # 强制更新状态
                    with self.status_lock:
                        self.status['cursor_restricted'] = self.window_freedom.is_cursor_clipped()
                    
                    result = True
                    logger.info(f"紧急解锁成功，处理了 {lock_windows_count} 个锁定窗口")
                except Exception as e:
                    logger.error(f"紧急解锁操作时出错: {e}")
                    return False
            else:
                logger.error("紧急解锁失败：窗口自由模块不可用")
                return False
            
            return result
        except Exception as e:
            logger.error(f"紧急解锁时出错: {e}")
            traceback.print_exc()
            return False
    
    def terminate_suspicious_process(self, pid: int) -> bool:
        """终止特定的可疑进程"""
        try:
            import psutil
            process = psutil.Process(pid)
            return self.countermeasure_manager.safe_terminate_process(process)
        except Exception as e:
            logger.error(f"终止进程(PID: {pid})时出错: {e}")
            return False
    
    def analyze_przs_logic(self) -> Dict[str, Any]:
        """分析przs随机进程名生成逻辑"""
        try:
            return self.random_process_analyzer.analyze_przs_random_name_logic()
        except Exception as e:
            logger.error(f"分析przs逻辑时出错: {e}")
            return {}
    
    def cleanup(self) -> bool:
        """清理资源"""
        try:
            logger.info("清理资源...")
            
            # 停止保护
            if hasattr(self, 'is_running') and self.is_running:
                try:
                    self.stop_protection()
                except Exception as e:
                    logger.error(f"清理时停止保护出错: {e}")
            
            # 停止状态监控线程
            if hasattr(self, 'is_running'):
                self.is_running = False
            
            # 停止反制管理器
            if hasattr(self, 'countermeasure_manager') and self.countermeasure_manager is not None:
                try:
                    logger.info("清理反制管理器资源...")
                    self.countermeasure_manager.cleanup()
                except Exception as e:
                    logger.error(f"清理反制管理器资源时出错: {e}")
                finally:
                    self.countermeasure_manager = None
            
            # 清理窗口自由模块
            if hasattr(self, 'window_freedom') and self.window_freedom is not None:
                try:
                    logger.info("清理窗口自由模块资源...")
                    self.window_freedom.cleanup()
                except Exception as e:
                    logger.error(f"清理窗口自由模块资源时出错: {e}")
                finally:
                    self.window_freedom = None
            
            logger.info("资源清理完成")
            return True
        except Exception as e:
            logger.error(f"清理资源时出错: {e}")
            traceback.print_exc()
            return False
    
    def __del__(self):
        """析构函数"""
        self.cleanup() 