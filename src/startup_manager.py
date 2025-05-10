#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
启动项管理器
处理系统启动项
"""

import os
import sys
import logging
import winreg
import subprocess

class StartupManager:
    """管理系统启动项的类"""
    
    # 注册表启动项路径
    RUN_KEY_PATH_32 = r"SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN"
    RUN_KEY_PATH = r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN"
    
    # 启动项键名
    STARTUP_VALUE_NAME = "prozs"
    
    def __init__(self):
        """初始化启动项管理器"""
        self.logger = logging.getLogger("SystemDiagnosticTool.StartupManager")
        
        # 检查平台是否为Windows
        if sys.platform != 'win32':
            self.logger.warning("当前不是Windows平台，启动项功能将不可用")
    
    def is_startup_enabled(self):
        """检查是否已设置启动项"""
        try:
            # 先检查64位注册表
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.RUN_KEY_PATH, 0, winreg.KEY_READ)
                value, _ = winreg.QueryValueEx(key, self.STARTUP_VALUE_NAME)
                winreg.CloseKey(key)
                return value != ""
            except FileNotFoundError:
                pass
            except Exception as e:
                self.logger.error(f"检查64位启动项时出错: {e}")
            
            # 再检查32位注册表
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.RUN_KEY_PATH_32, 0, winreg.KEY_READ)
                value, _ = winreg.QueryValueEx(key, self.STARTUP_VALUE_NAME)
                winreg.CloseKey(key)
                return value != ""
            except FileNotFoundError:
                return False
            except Exception as e:
                self.logger.error(f"检查32位启动项时出错: {e}")
                return False
        except Exception as e:
            self.logger.error(f"检查启动项时出错: {e}")
            return False
    
    def set_startup(self, enable, exe_path=None):
        """设置或移除启动项"""
        try:
            # 如果没有提供可执行文件路径，尝试自动查找
            if exe_path is None and enable:
                exe_path = self._find_przs_exe()
                if not exe_path:
                    self.logger.error("无法找到przs.exe")
                    return False
            
            # 设置启动项
            success = False
            
            # 尝试设置64位注册表
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, self.RUN_KEY_PATH, 0, winreg.KEY_WRITE)
                if enable:
                    winreg.SetValueEx(key, self.STARTUP_VALUE_NAME, 0, winreg.REG_SZ, exe_path)
                else:
                    winreg.DeleteValue(key, self.STARTUP_VALUE_NAME)
                winreg.CloseKey(key)
                success = True
            except Exception as e:
                self.logger.error(f"设置64位启动项时出错: {e}")
            
            # 尝试设置32位注册表
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, self.RUN_KEY_PATH_32, 0, winreg.KEY_WRITE)
                if enable:
                    winreg.SetValueEx(key, self.STARTUP_VALUE_NAME, 0, winreg.REG_SZ, exe_path)
                else:
                    winreg.DeleteValue(key, self.STARTUP_VALUE_NAME)
                winreg.CloseKey(key)
                success = True
            except Exception as e:
                self.logger.error(f"设置32位启动项时出错: {e}")
            
            return success
        except Exception as e:
            self.logger.error(f"设置启动项时出错: {e}")
            return False
    
    def _find_przs_exe(self):
        """查找przs.exe"""
        try:
            # 可能的位置
            possible_locations = [
                os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'przs.exe'),
                os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'), 'przs.exe'),
                r'C:\przs.exe',
                r'C:\jfglzs\przs.exe',
            ]
            
            # 检查这些位置
            for location in possible_locations:
                if os.path.exists(location):
                    return location
            
            # 如果没有找到，尝试在C盘搜索
            return self._search_file_in_drive('przs.exe', 'C:\\')
        except Exception as e:
            self.logger.error(f"查找przs.exe时出错: {e}")
            return None
    
    def _search_file_in_drive(self, filename, drive):
        """在指定驱动器搜索文件"""
        try:
            # 使用where命令搜索文件
            if sys.platform == 'win32':
                try:
                    # 使用where命令搜索文件（仅Windows）
                    result = subprocess.run(['where', '/R', drive, filename], 
                                           capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        # 找到文件，返回第一个匹配的路径
                        paths = result.stdout.strip().split('\n')
                        if paths:
                            return paths[0]
                except Exception as e:
                    self.logger.error(f"使用where命令搜索文件时出错: {e}")
            
            # 手动搜索
            for root, _, files in os.walk(drive):
                if filename in files:
                    return os.path.join(root, filename)
            
            return None
        except Exception as e:
            self.logger.error(f"在驱动器{drive}搜索文件{filename}时出错: {e}")
            return None
    
    def create_user_startup_shortcut(self, exe_path=None):
        """创建用户启动文件夹中的快捷方式（备用方法）"""
        try:
            if sys.platform != 'win32':
                return False
                
            if exe_path is None:
                exe_path = self._find_przs_exe()
                if not exe_path:
                    return False
            
            # 获取用户启动文件夹
            startup_folder = os.path.join(
                os.environ.get('APPDATA', ''),
                r'Microsoft\Windows\Start Menu\Programs\Startup'
            )
            
            # 确保文件夹存在
            if not os.path.exists(startup_folder):
                os.makedirs(startup_folder)
            
            # 创建快捷方式
            shortcut_path = os.path.join(startup_folder, 'przs.lnk')
            
            # 使用PowerShell创建快捷方式
            ps_command = f'''
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("{shortcut_path}")
            $Shortcut.TargetPath = "{exe_path}"
            $Shortcut.Save()
            '''
            
            # 执行PowerShell命令
            subprocess.run(['powershell', '-Command', ps_command], 
                          capture_output=True, text=True)
            
            return os.path.exists(shortcut_path)
        except Exception as e:
            self.logger.error(f"创建用户启动快捷方式时出错: {e}")
            return False 