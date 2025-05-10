#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
密码管理标签页
管理系统密码
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QGroupBox, QLabel, 
                           QLineEdit, QPushButton, QFormLayout, QHBoxLayout,
                           QMessageBox, QCheckBox)
from PyQt5.QtCore import Qt


class PasswordTab(QWidget):
    """密码管理标签页"""
    
    def __init__(self, controller):
        """初始化密码管理标签页"""
        super().__init__()
        
        # 保存控制器引用
        self.controller = controller
        
        # 创建UI组件
        self._create_ui()
    
    def _create_ui(self):
        """创建UI组件"""
        # 创建主布局
        layout = QVBoxLayout(self)
        
        # 创建标题标签
        title_label = QLabel("密码管理")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # 创建描述标签
        desc_label = QLabel("此页面用于修改系统管理密码")
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        # 创建密码修改组
        password_group = QGroupBox("修改密码")
        password_layout = QFormLayout(password_group)
        
        # 原密码输入
        self.old_password_edit = QLineEdit()
        self.old_password_edit.setEchoMode(QLineEdit.Password)
        password_layout.addRow("原密码：", self.old_password_edit)
        
        # 新密码输入
        self.new_password_edit = QLineEdit()
        self.new_password_edit.setEchoMode(QLineEdit.Password)
        password_layout.addRow("新密码：", self.new_password_edit)
        
        # 确认新密码
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        password_layout.addRow("确认新密码：", self.confirm_password_edit)
        
        # 显示密码复选框
        self.show_password_checkbox = QCheckBox("显示密码")
        self.show_password_checkbox.stateChanged.connect(self._toggle_password_visibility)
        password_layout.addRow("", self.show_password_checkbox)
        
        # 密码强度提示
        password_hint = QLabel("• 密码长度必须至少为6位\n• 密码不能是简单的'123456'\n• 建议使用字母、数字和特殊字符的组合")
        password_hint.setStyleSheet("color: gray;")
        password_layout.addRow("", password_hint)
        
        # 添加修改密码按钮
        button_layout = QHBoxLayout()
        
        self.change_button = QPushButton("修改密码")
        self.change_button.clicked.connect(self._change_password)
        button_layout.addWidget(self.change_button)
        
        self.reset_button = QPushButton("重置输入")
        self.reset_button.clicked.connect(self._reset_input)
        button_layout.addWidget(self.reset_button)
        
        password_layout.addRow("", button_layout)
        
        layout.addWidget(password_group)
        
        # 添加紧急密码重置（仅管理员可见）
        self.emergency_group = QGroupBox("紧急密码重置（仅限管理员）")
        emergency_layout = QVBoxLayout(self.emergency_group)
        
        emergency_label = QLabel("如果忘记密码，可以在这里重置密码为默认值'123456'")
        emergency_layout.addWidget(emergency_label)
        
        self.reset_password_button = QPushButton("重置为默认密码")
        self.reset_password_button.clicked.connect(self._reset_password)
        emergency_layout.addWidget(self.reset_password_button)
        
        layout.addWidget(self.emergency_group)
        
        # 根据管理员权限显示或隐藏紧急重置组
        self.emergency_group.setVisible(self.controller.is_admin)
        
        # 设置布局的间距和边距
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)
    
    def _toggle_password_visibility(self, state):
        """切换密码可见性"""
        if state == Qt.Checked:
            self.old_password_edit.setEchoMode(QLineEdit.Normal)
            self.new_password_edit.setEchoMode(QLineEdit.Normal)
            self.confirm_password_edit.setEchoMode(QLineEdit.Normal)
        else:
            self.old_password_edit.setEchoMode(QLineEdit.Password)
            self.new_password_edit.setEchoMode(QLineEdit.Password)
            self.confirm_password_edit.setEchoMode(QLineEdit.Password)
    
    def _change_password(self):
        """修改密码"""
        try:
            # 获取输入
            old_password = self.old_password_edit.text()
            new_password = self.new_password_edit.text()
            confirm_password = self.confirm_password_edit.text()
            
            # 验证输入
            if not old_password:
                QMessageBox.warning(self, "输入错误", "请输入原密码")
                return
            
            if not new_password:
                QMessageBox.warning(self, "输入错误", "请输入新密码")
                return
            
            if new_password != confirm_password:
                QMessageBox.warning(self, "输入错误", "两次输入的新密码不一致")
                return
            
            if len(new_password) < 6:
                QMessageBox.warning(self, "密码太短", "新密码长度必须至少为6位")
                return
            
            if new_password == "123456":
                QMessageBox.warning(self, "密码太简单", "不能使用过于简单的密码")
                return
            
            # 调用控制器修改密码
            result = self.controller.change_password(old_password, new_password)
            
            if result:
                QMessageBox.information(self, "修改成功", "密码已成功修改")
                self._reset_input()
            else:
                QMessageBox.warning(self, "修改失败", "密码修改失败，请检查原密码是否正确")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"修改密码时发生错误: {str(e)}")
    
    def _reset_input(self):
        """重置输入框"""
        self.old_password_edit.clear()
        self.new_password_edit.clear()
        self.confirm_password_edit.clear()
    
    def _reset_password(self):
        """重置密码为默认值"""
        try:
            # 确认对话框
            reply = QMessageBox.question(self, '确认重置', 
                                       '确定要将密码重置为默认值"123456"吗？\n这是一个不可逆的操作！',
                                       QMessageBox.Yes | QMessageBox.No,
                                       QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                # 再次确认
                reply = QMessageBox.question(self, '再次确认', 
                                          '重置密码将使当前密码失效，确定要继续吗？',
                                          QMessageBox.Yes | QMessageBox.No,
                                          QMessageBox.No)
                
                if reply == QMessageBox.Yes and self.controller.is_admin:
                    # 调用密码管理器重置密码
                    if hasattr(self.controller.password_manager, 'reset_password'):
                        result = self.controller.password_manager.reset_password()
                        if result:
                            QMessageBox.information(self, "重置成功", "密码已重置为默认值'123456'")
                        else:
                            QMessageBox.warning(self, "重置失败", "密码重置失败")
                    else:
                        QMessageBox.warning(self, "功能不可用", "密码重置功能不可用")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"重置密码时发生错误: {str(e)}") 