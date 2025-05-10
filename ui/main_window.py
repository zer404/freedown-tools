#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
主窗口
包含应用程序的主要UI
"""

import sys
import os
from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QLabel, QPushButton, 
                           QVBoxLayout, QHBoxLayout, QWidget, QMessageBox,
                           QStatusBar, QApplication)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QIcon, QPixmap, QFont

from .tabs.restriction_tab import RestrictionTab
from .tabs.password_tab import PasswordTab
from .tabs.startup_tab import StartupTab
from .tabs.service_tab import ServiceTab
from .tabs.about_tab import AboutTab

class MainWindow(QMainWindow):
    """应用程序主窗口"""
    
    def __init__(self, controller):
        """初始化主窗口"""
        super().__init__()
        
        # 保存控制器引用
        self.controller = controller
        
        # 设置窗口属性
        self.setWindowTitle("系统安全管理工具")
        self.setMinimumSize(800, 600)
        
        # 创建UI组件
        self._create_ui()
        
        # 连接信号和槽
        self._connect_signals()
        
        # 显示管理员权限状态
        self._update_admin_status(self.controller.is_admin)
    
    def _create_ui(self):
        """创建UI组件"""
        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 创建主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标题标签
        title_label = QLabel("系统安全管理工具")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        main_layout.addWidget(title_label)
        
        # 创建管理员状态标签
        self.admin_status_label = QLabel()
        self.admin_status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.admin_status_label)
        
        # 创建标签页控件
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # 创建标签页
        self.restriction_tab = RestrictionTab(self.controller)
        self.password_tab = PasswordTab(self.controller)
        self.startup_tab = StartupTab(self.controller)
        self.service_tab = ServiceTab(self.controller)
        self.about_tab = AboutTab()
        
        # 添加标签页
        self.tab_widget.addTab(self.restriction_tab, "系统限制")
        self.tab_widget.addTab(self.password_tab, "密码管理")
        self.tab_widget.addTab(self.startup_tab, "启动项")
        self.tab_widget.addTab(self.service_tab, "服务管理")
        self.tab_widget.addTab(self.about_tab, "关于")
        
        # 创建状态栏
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("就绪")
        
        # 创建按钮布局
        button_layout = QHBoxLayout()
        main_layout.addLayout(button_layout)
        
        # 添加退出按钮
        self.exit_button = QPushButton("退出")
        button_layout.addWidget(self.exit_button)
        
        # 添加刷新按钮
        self.refresh_button = QPushButton("刷新")
        button_layout.addWidget(self.refresh_button)
        
        # 设置布局的间距和边距
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
    
    def _connect_signals(self):
        """连接信号和槽"""
        # 连接控制器信号
        self.controller.status_changed.connect(self.statusBar.showMessage)
        self.controller.operation_completed.connect(self._handle_operation_completed)
        self.controller.admin_status_changed.connect(self._update_admin_status)
        
        # 连接按钮信号
        self.exit_button.clicked.connect(self.close)
        self.refresh_button.clicked.connect(self._refresh_all)
    
    @pyqtSlot(bool)
    def _update_admin_status(self, is_admin):
        """更新管理员状态标签"""
        if is_admin:
            self.admin_status_label.setText("状态: 管理员权限 ✓")
            self.admin_status_label.setStyleSheet("color: green;")
        else:
            self.admin_status_label.setText("状态: 非管理员权限 ✗")
            self.admin_status_label.setStyleSheet("color: red;")
    
    @pyqtSlot(bool, str)
    def _handle_operation_completed(self, success, message):
        """处理操作完成信号"""
        self.statusBar.showMessage(message)
        
        # 如果是重要操作，弹出消息框
        if success:
            QMessageBox.information(self, "操作成功", message)
        else:
            QMessageBox.warning(self, "操作失败", message)
    
    def _refresh_all(self):
        """刷新所有标签页"""
        try:
            self.restriction_tab.refresh()
            self.startup_tab.refresh()
            self.service_tab.refresh()
            self.statusBar.showMessage("刷新完成")
        except Exception as e:
            self.statusBar.showMessage(f"刷新失败: {str(e)}")
    
    def closeEvent(self, event):
        """关闭窗口事件处理"""
        reply = QMessageBox.question(self, '确认退出', 
                                    '确定要退出程序吗？',
                                    QMessageBox.Yes | QMessageBox.No,
                                    QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore() 