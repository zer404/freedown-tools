#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
启动项标签页
管理系统启动项
"""

import os
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QGroupBox, QRadioButton, 
                           QPushButton, QLabel, QFileDialog, QLineEdit,
                           QHBoxLayout, QMessageBox, QFormLayout)
from PyQt5.QtCore import Qt


class StartupTab(QWidget):
    """启动项标签页"""
    
    def __init__(self, controller):
        """初始化启动项标签页"""
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
        
        # 创建标题标签
        title_label = QLabel("启动项管理")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # 创建描述标签
        desc_label = QLabel("此页面用于管理系统启动项")
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        # 创建启动项状态组
        status_group = QGroupBox("启动项状态")
        status_layout = QVBoxLayout(status_group)
        
        self.status_label = QLabel("加载中...")
        status_layout.addWidget(self.status_label)
        
        layout.addWidget(status_group)
        
        # 创建启动项控制组
        control_group = QGroupBox("启动项控制")
        control_layout = QVBoxLayout(control_group)
        
        self.enable_radio = QRadioButton("启用自启动")
        self.disable_radio = QRadioButton("禁用自启动")
        
        control_layout.addWidget(self.enable_radio)
        control_layout.addWidget(self.disable_radio)
        
        # 添加应用按钮
        self.apply_button = QPushButton("应用设置")
        self.apply_button.clicked.connect(self._apply_settings)
        control_layout.addWidget(self.apply_button)
        
        layout.addWidget(control_group)
        
        # 创建自定义启动项组
        custom_group = QGroupBox("自定义启动项")
        custom_layout = QFormLayout(custom_group)
        
        # 添加可执行文件路径输入框和浏览按钮
        path_layout = QHBoxLayout()
        
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("可执行文件路径")
        path_layout.addWidget(self.path_edit)
        
        self.browse_button = QPushButton("浏览...")
        self.browse_button.clicked.connect(self._browse_file)
        path_layout.addWidget(self.browse_button)
        
        custom_layout.addRow("可执行文件路径：", path_layout)
        
        # 添加设置按钮
        self.set_button = QPushButton("设置自定义启动项")
        self.set_button.clicked.connect(self._set_custom_startup)
        custom_layout.addRow("", self.set_button)
        
        layout.addWidget(custom_group)
        
        # 创建备用方法组（仅在管理员权限不足时使用）
        self.fallback_group = QGroupBox("备用方法（用户级别启动项）")
        fallback_layout = QVBoxLayout(self.fallback_group)
        
        fallback_label = QLabel("如果无法设置系统级启动项，可以使用此方法在当前用户的启动文件夹中创建启动项")
        fallback_label.setWordWrap(True)
        fallback_layout.addWidget(fallback_label)
        
        self.create_shortcut_button = QPushButton("在用户启动文件夹中创建快捷方式")
        self.create_shortcut_button.clicked.connect(self._create_user_shortcut)
        fallback_layout.addWidget(self.create_shortcut_button)
        
        layout.addWidget(self.fallback_group)
        
        # 根据管理员权限设置控件状态
        self._update_controls()
    
    def refresh(self):
        """刷新显示"""
        try:
            # 获取当前设置
            enabled = self.controller.startup_manager.is_startup_enabled()
            
            # 更新UI状态
            self.enable_radio.setChecked(enabled)
            self.disable_radio.setChecked(not enabled)
            
            # 更新状态标签
            if enabled:
                self.status_label.setText("当前状态：已启用自启动")
                self.status_label.setStyleSheet("color: green;")
            else:
                self.status_label.setText("当前状态：未启用自启动")
                self.status_label.setStyleSheet("color: red;")
            
            # 更新控件状态
            self._update_controls()
        except Exception as e:
            QMessageBox.warning(self, "刷新失败", f"刷新启动项状态失败: {str(e)}")
    
    def _update_controls(self):
        """根据管理员权限更新控件状态"""
        is_admin = self.controller.is_admin
        
        # 启动项控制组件只有管理员可用
        self.enable_radio.setEnabled(is_admin)
        self.disable_radio.setEnabled(is_admin)
        self.apply_button.setEnabled(is_admin)
        self.set_button.setEnabled(is_admin)
        
        # 备用方法组总是可用（因为用户级启动项不需要管理员权限）
        self.fallback_group.setEnabled(True)
    
    def _apply_settings(self):
        """应用启动项设置"""
        try:
            # 检查是否有管理员权限
            if not self.controller.is_admin:
                QMessageBox.warning(self, "权限不足", "需要管理员权限才能修改系统启动项")
                return
            
            # 获取用户选择
            enable = self.enable_radio.isChecked()
            
            # 调用控制器设置启动项
            result = self.controller.manage_startup(enable)
            
            if result:
                QMessageBox.information(self, "设置成功", f"启动项已{'启用' if enable else '禁用'}")
                self.refresh()
            else:
                QMessageBox.warning(self, "设置失败", "无法设置启动项")
        except Exception as e:
            QMessageBox.warning(self, "设置失败", f"设置启动项失败: {str(e)}")
    
    def _browse_file(self):
        """浏览文件对话框"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "选择可执行文件", "", "可执行文件 (*.exe);;所有文件 (*)"
            )
            
            if file_path:
                self.path_edit.setText(file_path)
        except Exception as e:
            QMessageBox.warning(self, "选择文件失败", f"选择文件时出错: {str(e)}")
    
    def _set_custom_startup(self):
        """设置自定义启动项"""
        try:
            # 检查是否有管理员权限
            if not self.controller.is_admin:
                QMessageBox.warning(self, "权限不足", "需要管理员权限才能修改系统启动项")
                return
            
            # 获取用户输入的路径
            exe_path = self.path_edit.text().strip()
            
            if not exe_path:
                QMessageBox.warning(self, "输入错误", "请输入可执行文件路径")
                return
            
            if not os.path.exists(exe_path):
                QMessageBox.warning(self, "文件不存在", "指定的可执行文件不存在")
                return
            
            # 调用控制器设置自定义启动项
            result = self.controller.startup_manager.set_startup(True, exe_path)
            
            if result:
                QMessageBox.information(self, "设置成功", f"已设置 {exe_path} 为启动项")
                self.refresh()
            else:
                QMessageBox.warning(self, "设置失败", "无法设置自定义启动项")
        except Exception as e:
            QMessageBox.warning(self, "设置失败", f"设置自定义启动项失败: {str(e)}")
    
    def _create_user_shortcut(self):
        """在用户启动文件夹中创建快捷方式"""
        try:
            # 获取用户输入的路径
            exe_path = self.path_edit.text().strip()
            
            if not exe_path:
                # 尝试自动查找przs.exe
                exe_path = self.controller.startup_manager._find_przs_exe()
                if not exe_path:
                    QMessageBox.warning(self, "找不到程序", "请输入可执行文件路径")
                    return
            
            if not os.path.exists(exe_path):
                QMessageBox.warning(self, "文件不存在", "指定的可执行文件不存在")
                return
            
            # 调用创建快捷方式方法
            result = self.controller.startup_manager.create_user_startup_shortcut(exe_path)
            
            if result:
                QMessageBox.information(self, "创建成功", "已在用户启动文件夹中创建快捷方式")
            else:
                QMessageBox.warning(self, "创建失败", "无法创建快捷方式")
        except Exception as e:
            QMessageBox.warning(self, "创建失败", f"创建快捷方式失败: {str(e)}") 