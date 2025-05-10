#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
注册表管理器
处理Windows注册表相关操作
"""

import sys
import logging
import winreg

class RegistryManager:
    """管理Windows注册表的类"""
    
    # 注册表路径常量
    JFGLZS_KEY_PATH = r"Software\jfglzs"
    USB_KEY_NAME = "usb_jianche"
    VM_KEY_NAME = "xnj_jianche"
    CMD_KEY_NAME = "cmd_jianche"
    LOGOUT_KEY_NAME = "zhuxiao_button"
    DESKTOP_KEY_NAME = "xnzm_button"
    DISPLAY_NUMBER_KEY_NAME = "bianhao"
    
    # 系统限制注册表路径
    DISABLE_CMD_KEY_PATH = r"Software\Policies\Microsoft\Windows\System"
    DISABLE_CMD_VALUE_NAME = "DisableCMD"
    
    DISABLE_REGEDIT_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    DISABLE_REGEDIT_VALUE_NAME = "DisableRegistryTools"
    
    DISABLE_RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    DISABLE_RUN_VALUE_NAME = "NoRun"
    
    HIDE_FILE_EXT_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    HIDE_FILE_EXT_VALUE_NAME = "HideFileExt"
    
    def __init__(self):
        """初始化注册表管理器"""
        self.logger = logging.getLogger("SystemDiagnosticTool.RegistryManager")
        
        # 检查平台是否为Windows
        if sys.platform != 'win32':
            self.logger.warning("当前不是Windows平台，注册表功能将不可用")
    
    def _create_key_if_not_exists(self, key_path, access=winreg.KEY_ALL_ACCESS):
        """如果注册表键不存在则创建"""
        try:
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, access)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            self.logger.error(f"创建注册表键时出错: {e}")
            return False
    
    def _set_reg_value(self, key_path, value_name, value_data, value_type=winreg.REG_SZ):
        """设置注册表值"""
        try:
            # 确保父键存在
            if not self._create_key_if_not_exists(key_path):
                return False
            
            # 打开键并设置值
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, value_name, 0, value_type, value_data)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            self.logger.error(f"设置注册表值时出错: {e}")
            return False
    
    def _get_reg_value(self, key_path, value_name, default=None):
        """获取注册表值"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return value
        except FileNotFoundError:
            return default
        except Exception as e:
            self.logger.error(f"获取注册表值时出错: {e}")
            return default
    
    def set_usb_restriction(self, enabled):
        """设置USB设备限制"""
        try:
            value = "on" if enabled else "off"
            return self._set_reg_value(self.JFGLZS_KEY_PATH, self.USB_KEY_NAME, value)
        except Exception as e:
            self.logger.error(f"设置USB限制时出错: {e}")
            return False
    
    def get_usb_restriction(self):
        """获取USB设备限制状态"""
        try:
            value = self._get_reg_value(self.JFGLZS_KEY_PATH, self.USB_KEY_NAME, "off")
            return value == "on"
        except Exception as e:
            self.logger.error(f"获取USB限制状态时出错: {e}")
            return False
    
    def set_vm_restriction(self, enabled):
        """设置虚拟机限制"""
        try:
            value = "on" if enabled else "off"
            return self._set_reg_value(self.JFGLZS_KEY_PATH, self.VM_KEY_NAME, value)
        except Exception as e:
            self.logger.error(f"设置虚拟机限制时出错: {e}")
            return False
    
    def get_vm_restriction(self):
        """获取虚拟机限制状态"""
        try:
            value = self._get_reg_value(self.JFGLZS_KEY_PATH, self.VM_KEY_NAME, "off")
            return value == "on"
        except Exception as e:
            self.logger.error(f"获取虚拟机限制状态时出错: {e}")
            return False
    
    def set_cmd_restriction(self, enabled):
        """设置命令行限制"""
        try:
            # 设置jfglzs下的cmd_jianche值
            jfglzs_result = self._set_reg_value(self.JFGLZS_KEY_PATH, self.CMD_KEY_NAME, 
                                               "on" if enabled else "off")
            
            # 设置系统DisableCMD值
            sys_result = self._set_reg_value(self.DISABLE_CMD_KEY_PATH, self.DISABLE_CMD_VALUE_NAME, 
                                          1 if enabled else 0, winreg.REG_DWORD)
            
            return jfglzs_result and sys_result
        except Exception as e:
            self.logger.error(f"设置命令行限制时出错: {e}")
            return False
    
    def get_cmd_restriction(self):
        """获取命令行限制状态"""
        try:
            value = self._get_reg_value(self.JFGLZS_KEY_PATH, self.CMD_KEY_NAME, "off")
            return value == "on"
        except Exception as e:
            self.logger.error(f"获取命令行限制状态时出错: {e}")
            return False
    
    def set_logout_button(self, enabled):
        """设置注销按钮状态"""
        try:
            value = "on" if enabled else "off"
            return self._set_reg_value(self.JFGLZS_KEY_PATH, self.LOGOUT_KEY_NAME, value)
        except Exception as e:
            self.logger.error(f"设置注销按钮状态时出错: {e}")
            return False
    
    def get_logout_button(self):
        """获取注销按钮状态"""
        try:
            value = self._get_reg_value(self.JFGLZS_KEY_PATH, self.LOGOUT_KEY_NAME, "off")
            return value == "on"
        except Exception as e:
            self.logger.error(f"获取注销按钮状态时出错: {e}")
            return False
    
    def enable_registry_tools(self, enabled):
        """启用或禁用注册表编辑器"""
        try:
            return self._set_reg_value(self.DISABLE_REGEDIT_KEY_PATH, 
                                      self.DISABLE_REGEDIT_VALUE_NAME, 
                                      0 if enabled else 1, 
                                      winreg.REG_DWORD)
        except Exception as e:
            self.logger.error(f"设置注册表编辑器状态时出错: {e}")
            return False
    
    def enable_run_dialog(self, enabled):
        """启用或禁用运行对话框"""
        try:
            return self._set_reg_value(self.DISABLE_RUN_KEY_PATH, 
                                      self.DISABLE_RUN_VALUE_NAME, 
                                      0 if enabled else 1, 
                                      winreg.REG_DWORD)
        except Exception as e:
            self.logger.error(f"设置运行对话框状态时出错: {e}")
            return False
    
    def show_file_extensions(self, show):
        """显示或隐藏文件扩展名"""
        try:
            return self._set_reg_value(self.HIDE_FILE_EXT_KEY_PATH, 
                                      self.HIDE_FILE_EXT_VALUE_NAME, 
                                      0 if show else 1, 
                                      winreg.REG_DWORD)
        except Exception as e:
            self.logger.error(f"设置文件扩展名显示状态时出错: {e}")
            return False

    def reset_all_restrictions(self):
        """重置所有限制（仅在测试环境中使用）"""
        try:
            results = []
            results.append(self.set_usb_restriction(False))
            results.append(self.set_vm_restriction(False))
            results.append(self.set_cmd_restriction(False))
            results.append(self.set_logout_button(True))
            results.append(self.enable_registry_tools(True))
            results.append(self.enable_run_dialog(True))
            results.append(self.show_file_extensions(True))
            
            return all(results)
        except Exception as e:
            self.logger.error(f"重置所有限制时出错: {e}")
            return False 