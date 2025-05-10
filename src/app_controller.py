#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
应用程序控制器
负责协调UI和后端功能
"""

import os
import sys
import logging
from PyQt5.QtCore import QObject, pyqtSignal
from .registry_manager import RegistryManager
from .password_manager import PasswordManager
from .startup_manager import StartupManager
from .service_manager import ServiceManager

class AppController(QObject):
    """应用程序控制器，管理各个组件之间的交互"""
    
    # 定义信号
    status_changed = pyqtSignal(str)
    operation_completed = pyqtSignal(bool, str)
    admin_status_changed = pyqtSignal(bool)
    
    def __init__(self):
        super().__init__()
        
        # 初始化日志
        self._setup_logging()
        
        # 初始化各管理器
        self.registry_manager = RegistryManager()
        self.password_manager = PasswordManager()
        self.startup_manager = StartupManager()
        self.service_manager = ServiceManager()
        
        # 检查管理员权限
        self._check_admin_privileges()
        
        self.logger.info("应用程序控制器初始化完成")
    
    def _setup_logging(self):
        """设置日志系统"""
        self.logger = logging.getLogger("SystemDiagnosticTool")
        self.logger.setLevel(logging.DEBUG)
        
        # 创建控制台处理器
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        
        # 设置日志格式
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        
        # 添加处理器到日志器
        self.logger.addHandler(ch)
    
    def _check_admin_privileges(self):
        """检查当前是否有管理员权限"""
        try:
            # 在Windows上检查权限
            if sys.platform == 'win32':
                import ctypes
                self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # 在Unix/Linux上检查权限
                self.is_admin = os.geteuid() == 0
            
            self.admin_status_changed.emit(self.is_admin)
            self.logger.info(f"管理员权限状态: {self.is_admin}")
        except Exception as e:
            self.logger.error(f"检查权限时出错: {e}")
            self.is_admin = False
            self.admin_status_changed.emit(self.is_admin)
    
    def toggle_usb_restriction(self, enabled):
        """切换USB设备限制"""
        try:
            result = self.registry_manager.set_usb_restriction(enabled)
            message = "USB限制已" + ("启用" if enabled else "禁用")
            self.operation_completed.emit(result, message)
            return result
        except Exception as e:
            self.logger.error(f"设置USB限制时出错: {e}")
            self.operation_completed.emit(False, f"错误: {str(e)}")
            return False
    
    def toggle_vm_restriction(self, enabled):
        """切换虚拟机限制"""
        try:
            result = self.registry_manager.set_vm_restriction(enabled)
            message = "虚拟机限制已" + ("启用" if enabled else "禁用")
            self.operation_completed.emit(result, message)
            return result
        except Exception as e:
            self.logger.error(f"设置虚拟机限制时出错: {e}")
            self.operation_completed.emit(False, f"错误: {str(e)}")
            return False
    
    def toggle_cmd_restriction(self, enabled):
        """切换命令行限制"""
        try:
            result = self.registry_manager.set_cmd_restriction(enabled)
            message = "命令行限制已" + ("启用" if enabled else "禁用")
            self.operation_completed.emit(result, message)
            return result
        except Exception as e:
            self.logger.error(f"设置命令行限制时出错: {e}")
            self.operation_completed.emit(False, f"错误: {str(e)}")
            return False
    
    def toggle_logout_button(self, enabled):
        """切换注销按钮状态"""
        try:
            result = self.registry_manager.set_logout_button(enabled)
            message = "注销按钮已" + ("启用" if enabled else "禁用")
            self.operation_completed.emit(result, message)
            return result
        except Exception as e:
            self.logger.error(f"设置注销按钮时出错: {e}")
            self.operation_completed.emit(False, f"错误: {str(e)}")
            return False
    
    def change_password(self, old_password, new_password):
        """更改密码"""
        try:
            if not self.password_manager.verify_password(old_password):
                self.operation_completed.emit(False, "原密码不正确")
                return False
            
            if len(new_password) < 6:
                self.operation_completed.emit(False, "新密码长度必须至少为6位")
                return False
            
            if new_password == "123456":
                self.operation_completed.emit(False, "新密码过于简单")
                return False
            
            result = self.password_manager.change_password(old_password, new_password)
            self.operation_completed.emit(result, "密码修改成功" if result else "密码修改失败")
            return result
        except Exception as e:
            self.logger.error(f"更改密码时出错: {e}")
            self.operation_completed.emit(False, f"错误: {str(e)}")
            return False
    
    def manage_startup(self, enabled):
        """管理启动项"""
        try:
            result = self.startup_manager.set_startup(enabled)
            message = "启动项已" + ("添加" if enabled else "移除")
            self.operation_completed.emit(result, message)
            return result
        except Exception as e:
            self.logger.error(f"管理启动项时出错: {e}")
            self.operation_completed.emit(False, f"错误: {str(e)}")
            return False
    
    def get_current_settings(self):
        """获取当前所有设置状态"""
        try:
            settings = {
                'usb_restriction': self.registry_manager.get_usb_restriction(),
                'vm_restriction': self.registry_manager.get_vm_restriction(),
                'cmd_restriction': self.registry_manager.get_cmd_restriction(),
                'logout_button': self.registry_manager.get_logout_button(),
                'startup_enabled': self.startup_manager.is_startup_enabled()
            }
            return settings
        except Exception as e:
            self.logger.error(f"获取当前设置时出错: {e}")
            return {}
    
    def restart_service(self, service_name):
        """重启指定服务"""
        try:
            result = self.service_manager.restart_service(service_name)
            message = f"服务 {service_name} 已" + ("重启" if result else "重启失败")
            self.operation_completed.emit(result, message)
            return result
        except Exception as e:
            self.logger.error(f"重启服务时出错: {e}")
            self.operation_completed.emit(False, f"错误: {str(e)}")
            return False 