#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
系统限制标签页
管理系统限制设置
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QGroupBox, QRadioButton, 
                           QPushButton, QLabel, QCheckBox, QFormLayout,
                           QMessageBox)
from PyQt5.QtCore import Qt


class RestrictionTab(QWidget):
    """系统限制标签页"""
    
    def __init__(self, controller):
        """初始化系统限制标签页"""
        super().__init__()
        
        # 保存控制器引用
        self.controller = controller
        
        # 创建UI组件
        self._create_ui()
        
        # 刷新显示
        self.refresh()
    
    def _create_ui(self):
        """创建UI组件"""
        # 创建主布局
        layout = QVBoxLayout(self)
        
        # USB设备限制组
        usb_group = QGroupBox("USB设备检测")
        usb_layout = QVBoxLayout(usb_group)
        
        self.usb_on_radio = QRadioButton("开启")
        self.usb_off_radio = QRadioButton("关闭")
        
        usb_layout.addWidget(self.usb_on_radio)
        usb_layout.addWidget(self.usb_off_radio)
        
        layout.addWidget(usb_group)
        
        # 虚拟机限制组
        vm_group = QGroupBox("虚拟机检测")
        vm_layout = QVBoxLayout(vm_group)
        
        self.vm_on_radio = QRadioButton("开启")
        self.vm_off_radio = QRadioButton("关闭")
        
        vm_layout.addWidget(self.vm_on_radio)
        vm_layout.addWidget(self.vm_off_radio)
        
        layout.addWidget(vm_group)
        
        # 命令行限制组
        cmd_group = QGroupBox("命令行检测")
        cmd_layout = QVBoxLayout(cmd_group)
        
        self.cmd_on_radio = QRadioButton("开启")
        self.cmd_off_radio = QRadioButton("关闭")
        
        cmd_layout.addWidget(self.cmd_on_radio)
        cmd_layout.addWidget(self.cmd_off_radio)
        
        layout.addWidget(cmd_group)
        
        # 注销按钮限制组
        logout_group = QGroupBox("注销按钮")
        logout_layout = QVBoxLayout(logout_group)
        
        self.logout_on_radio = QRadioButton("开启")
        self.logout_off_radio = QRadioButton("关闭")
        
        logout_layout.addWidget(self.logout_on_radio)
        logout_layout.addWidget(self.logout_off_radio)
        
        layout.addWidget(logout_group)
        
        # 其他系统限制组
        other_group = QGroupBox("其他系统选项")
        other_layout = QFormLayout(other_group)
        
        self.registry_checkbox = QCheckBox("启用注册表编辑器")
        self.run_dialog_checkbox = QCheckBox("启用运行对话框")
        self.file_ext_checkbox = QCheckBox("显示文件扩展名")
        
        other_layout.addRow(self.registry_checkbox)
        other_layout.addRow(self.run_dialog_checkbox)
        other_layout.addRow(self.file_ext_checkbox)
        
        layout.addWidget(other_group)
        
        # 添加应用按钮
        self.apply_button = QPushButton("应用设置")
        layout.addWidget(self.apply_button)
        
        # 添加重置按钮
        self.reset_button = QPushButton("重置所有限制")
        layout.addWidget(self.reset_button)
        
        # 连接信号
        self.apply_button.clicked.connect(self._apply_settings)
        self.reset_button.clicked.connect(self._reset_settings)
    
    def refresh(self):
        """刷新显示"""
        try:
            # 获取当前设置
            settings = self.controller.get_current_settings()
            
            # 更新UI状态
            self.usb_on_radio.setChecked(settings.get('usb_restriction', False))
            self.usb_off_radio.setChecked(not settings.get('usb_restriction', False))
            
            self.vm_on_radio.setChecked(settings.get('vm_restriction', False))
            self.vm_off_radio.setChecked(not settings.get('vm_restriction', False))
            
            self.cmd_on_radio.setChecked(settings.get('cmd_restriction', False))
            self.cmd_off_radio.setChecked(not settings.get('cmd_restriction', False))
            
            self.logout_on_radio.setChecked(settings.get('logout_button', True))
            self.logout_off_radio.setChecked(not settings.get('logout_button', True))
        except Exception as e:
            QMessageBox.warning(self, "刷新失败", f"刷新设置失败: {str(e)}")
    
    def _apply_settings(self):
        """应用设置"""
        try:
            # 获取用户选择
            usb_enabled = self.usb_on_radio.isChecked()
            vm_enabled = self.vm_on_radio.isChecked()
            cmd_enabled = self.cmd_on_radio.isChecked()
            logout_enabled = self.logout_on_radio.isChecked()
            
            # 应用设置
            self.controller.toggle_usb_restriction(usb_enabled)
            self.controller.toggle_vm_restriction(vm_enabled)
            self.controller.toggle_cmd_restriction(cmd_enabled)
            self.controller.toggle_logout_button(logout_enabled)
            
            # 应用其他系统设置
            if hasattr(self.controller.registry_manager, 'enable_registry_tools'):
                self.controller.registry_manager.enable_registry_tools(self.registry_checkbox.isChecked())
            
            if hasattr(self.controller.registry_manager, 'enable_run_dialog'):
                self.controller.registry_manager.enable_run_dialog(self.run_dialog_checkbox.isChecked())
            
            if hasattr(self.controller.registry_manager, 'show_file_extensions'):
                self.controller.registry_manager.show_file_extensions(self.file_ext_checkbox.isChecked())
        except Exception as e:
            QMessageBox.warning(self, "设置失败", f"应用设置失败: {str(e)}")
    
    def _reset_settings(self):
        """重置所有限制"""
        try:
            reply = QMessageBox.question(self, '确认重置', 
                                       '确定要重置所有系统限制吗？\n注意：这将禁用所有限制功能。',
                                       QMessageBox.Yes | QMessageBox.No,
                                       QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                if hasattr(self.controller.registry_manager, 'reset_all_restrictions'):
                    result = self.controller.registry_manager.reset_all_restrictions()
                    if result:
                        QMessageBox.information(self, "重置成功", "所有系统限制已重置")
                        self.refresh()
                    else:
                        QMessageBox.warning(self, "重置失败", "重置系统限制失败")
                else:
                    QMessageBox.warning(self, "功能不可用", "重置功能不可用")
        except Exception as e:
            QMessageBox.warning(self, "重置失败", f"重置系统限制失败: {str(e)}") 