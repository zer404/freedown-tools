#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import hashlib
import requests
import logging
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QLineEdit, QPushButton, QMessageBox, QGroupBox)
from PyQt5.QtCore import Qt, QSettings

# 添加停用提示
print("警告：原登录模块已停用，现已使用geziyun_kami.py中的卡密登录模块替代")

class OldLoginDialog(QDialog):
    """旧版登录对话框 - 已停用，使用geziyun_kami.py中的KamiLoginUI替代"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # 显示停用提示
        QMessageBox.warning(self, "模块已停用", 
                           "此登录模块已经停用，现已使用geziyun_kami.py中的KamiLoginUI替代。\n"
                           "请使用run.py启动程序，以使用新的卡密登录系统。")
        
        # 固定API地址
        self.api_url = "http://zer-zero.cn/api/auth"
        
        # 初始化日志记录器
        self.logger = logging.getLogger("LoginDialog")
        self._setup_logger()
        
        self.setWindowTitle("用户登录 (已停用)")
        self.setMinimumWidth(320)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        
        self.login_result = None
        
        self._create_ui()
    
    def _setup_logger(self):
        """设置日志记录器"""
        if not self.logger.handlers:
            # 创建控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            # 设置格式
            formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(formatter)
            
            # 添加处理器到日志器
            self.logger.addHandler(console_handler)
            self.logger.setLevel(logging.INFO)
    
    def _create_ui(self):
        """创建UI组件"""
        layout = QVBoxLayout(self)
        
        # 登录表单
        form_group = QGroupBox("用户登录")
        form_layout = QVBoxLayout(form_group)
        
        # 用户名输入
        username_layout = QHBoxLayout()
        username_label = QLabel("用户名:")
        username_layout.addWidget(username_label)
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("请输入用户名")
        username_layout.addWidget(self.username_edit)
        form_layout.addLayout(username_layout)
        
        # 密码输入
        password_layout = QHBoxLayout()
        password_label = QLabel("密码:")
        password_layout.addWidget(password_label)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("请输入密码")
        password_layout.addWidget(self.password_edit)
        form_layout.addLayout(password_layout)
        
        # 加载上次使用的用户名
        settings = QSettings("FirewayTools", "Login")
        last_username = settings.value("last_username", "")
        self.username_edit.setText(last_username)
        
        # 显示连接状态
        conn_layout = QHBoxLayout()
        conn_label = QLabel("API地址:")
        conn_layout.addWidget(conn_label)
        api_status = QLabel(self.api_url)
        api_status.setStyleSheet("color: blue;")
        conn_layout.addWidget(api_status)
        conn_layout.addStretch()
        test_btn = QPushButton("测试连接")
        test_btn.clicked.connect(self._test_connection)
        conn_layout.addWidget(test_btn)
        form_layout.addLayout(conn_layout)
        
        # 按钮布局
        btn_layout = QHBoxLayout()
        self.login_btn = QPushButton("登录")
        self.login_btn.clicked.connect(self._on_login)
        btn_layout.addWidget(self.login_btn)
        
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        form_layout.addLayout(btn_layout)
        
        layout.addWidget(form_group)
        
        # 版本信息和作者信息
        info_label = QLabel('版权所有 © 2024 <a href="http://zer-zero.cn">zer-zero</a>')
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setTextFormat(Qt.RichText)
        info_label.setOpenExternalLinks(True)
        layout.addWidget(info_label)
        
        self.username_edit.setFocus()
    
    def _on_login(self):
        """登录按钮点击事件"""
        username = self.username_edit.text().strip()
        password = self.password_edit.text()
        
        if not username:
            QMessageBox.warning(self, "警告", "请输入用户名")
            self.username_edit.setFocus()
            return
        
        if not password:
            QMessageBox.warning(self, "警告", "请输入密码")
            self.password_edit.setFocus()
            return
        
        # 显示正在登录
        self.login_btn.setEnabled(False)
        self.login_btn.setText("正在登录...")
        
        # 执行登录
        if self._do_login(username, password):
            # 保存上次使用的用户名
            settings = QSettings("FirewayTools", "Login")
            settings.setValue("last_username", username)
            
            self.accept()
        else:
            self.login_btn.setEnabled(True)
            self.login_btn.setText("登录")
    
    def _do_login(self, username, password):
        """执行实际登录逻辑
        
        Args:
            username: 用户名
            password: 密码
            
        Returns:
            bool: 登录是否成功
        """
        try:
            # 设置正确的API请求头和格式
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # 准备登录数据 - 使用明文密码
            data = {
                "username": username,
                "password": password  # 使用明文密码而非MD5哈希
            }
            
            # 发送登录请求
            response = requests.post(self.api_url, json=data, headers=headers, timeout=10)
            
            # 检查响应
            if response.status_code == 200:
                try:
                    resp_data = response.json()
                    
                    if resp_data.get("success") == True:  # 明确检查success为true
                        user_data = resp_data.get("user", {})
                        
                        # 保存登录结果
                        self.login_result = {
                            "success": True,
                            "username": user_data.get("username", username),
                            "real_name": user_data.get("realName", "")
                        }
                        
                        # 保存上次使用的用户名
                        settings = QSettings("FirewayTools", "Login")
                        settings.setValue("last_username", username)
                        
                        self.logger.info(f"用户 {username} 登录成功")
                        return True
                    else:
                        # 登录失败，显示错误信息
                        error_msg = resp_data.get("message", "用户名或密码错误")
                        QMessageBox.critical(self, "登录失败", error_msg)
                        return False
                except ValueError as e:
                    # JSON解析错误
                    QMessageBox.critical(self, "登录失败", f"返回数据格式错误: {str(e)}")
                    return False
            elif response.status_code == 401:
                # 401错误详细处理
                try:
                    error_msg = response.json().get("message", "身份验证失败")
                except:
                    error_msg = "服务器返回401错误：未授权"
                QMessageBox.critical(self, "登录失败", error_msg)
                return False
            else:
                # 其他服务器错误
                QMessageBox.critical(self, "登录失败", f"服务器返回错误: {response.status_code}")
                # 尝试显示更多信息以便调试
                try:
                    error_text = response.text[:200]
                    QMessageBox.critical(self, "错误详情", f"服务器返回：\n{error_text}")
                except:
                    pass
                return False
                
        except requests.exceptions.RequestException as e:
            # 网络异常
            QMessageBox.critical(self, "登录失败", f"网络连接错误: {str(e)}")
            return False
        except Exception as e:
            # 其他异常
            QMessageBox.critical(self, "登录失败", f"发生错误: {str(e)}")
            return False
    
    def get_login_result(self):
        """获取登录结果
        
        Returns:
            dict: 包含登录用户信息的字典，如果未登录则为包含 success=False 的字典
        """
        if self.login_result is None:
            # 如果 login_result 为 None，表示登录失败或取消登录
            return {"success": False, "message": "登录被取消或未完成"}
        return self.login_result
    
    def _test_connection(self):
        """测试API连接"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # 使用POST方法模拟真实登录请求格式，但使用无效凭据
            test_data = {
                "username": "test_connection",
                "password": "test_password"
            }
            
            # 发送测试请求
            response = requests.post(self.api_url, json=test_data, headers=headers, timeout=5)
            
            # 分析响应
            msg = f"连接状态: HTTP {response.status_code}\n"
            if response.status_code == 200 or response.status_code == 401:
                msg += "连接成功！服务器可用。\n\n"
                try:
                    resp_json = response.json()
                    msg += f"服务器响应: {json.dumps(resp_json, indent=2, ensure_ascii=False)[:200]}"
                except:
                    msg += f"响应内容:\n{response.text[:200]}"
                QMessageBox.information(self, "连接测试", msg)
            else:
                msg += f"服务器返回意外状态码。\n\n响应内容:\n{response.text[:200]}"
                QMessageBox.warning(self, "连接测试", msg)
        except Exception as e:
            QMessageBox.critical(self, "连接错误", f"无法连接到服务器：\n{str(e)}") 

# 为了兼容性，创建一个指向旧类的别名
LoginDialog = OldLoginDialog 