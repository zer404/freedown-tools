#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
关于标签页
显示程序相关信息
"""

import sys
import platform
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, QGroupBox, QTextBrowser)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


class AboutTab(QWidget):
    """关于标签页"""
    
    def __init__(self):
        """初始化关于标签页"""
        super().__init__()
        
        # 创建UI组件
        self._create_ui()
    
    def _create_ui(self):
        """创建UI组件"""
        # 创建主布局
        layout = QVBoxLayout(self)
        
        # 创建标题标签
        title_label = QLabel("系统安全管理工具")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title_label)
        
        # 创建版本标签
        version_label = QLabel("版本 1.0.0")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)
        
        # 创建系统信息组
        system_group = QGroupBox("系统信息")
        system_layout = QVBoxLayout(system_group)
        
        system_info = f"""
        <b>Python版本:</b> {platform.python_version()}
        <br><b>操作系统:</b> {platform.system()} {platform.version()}
        <br><b>处理器:</b> {platform.processor()}
        <br><b>平台:</b> {platform.platform()}
        """
        
        system_label = QLabel(system_info)
        system_label.setTextFormat(Qt.RichText)
        system_layout.addWidget(system_label)
        
        layout.addWidget(system_group)
        
        # 创建说明组
        description_group = QGroupBox("程序说明")
        description_layout = QVBoxLayout(description_group)
        
        description_text = QTextBrowser()
        description_text.setOpenExternalLinks(True)
        description_text.setHtml("""
        <p>本程序用于管理系统安全设置，包括：</p>
        <ul>
            <li>管理USB设备、虚拟机、命令行等限制</li>
            <li>管理系统密码</li>
            <li>管理系统启动项</li>
            <li>管理Windows服务</li>
        </ul>
        <p><b>注意：</b> 本程序需要管理员权限才能执行大部分操作。</p>
        <p><b>使用说明：</b></p>
        <p>1. 系统限制标签页：用于控制USB设备、虚拟机等限制。</p>
        <p>2. 密码管理标签页：用于修改系统管理密码。</p>
        <p>3. 启动项标签页：用于控制系统启动项。</p>
        <p>4. 服务管理标签页：用于管理Windows服务。</p>
        """)
        description_layout.addWidget(description_text)
        
        layout.addWidget(description_group)
        
        # 创建免责声明组
        disclaimer_group = QGroupBox("免责声明")
        disclaimer_layout = QVBoxLayout(disclaimer_group)
        
        disclaimer_text = QLabel("""
        本软件仅供系统管理员在合法授权的情况下使用。
        使用本软件可能会修改系统设置，请谨慎操作。
        开发者不对因使用本软件而导致的任何问题负责。
        """)
        disclaimer_text.setWordWrap(True)
        disclaimer_text.setStyleSheet("color: red;")
        disclaimer_layout.addWidget(disclaimer_text)
        
        layout.addWidget(disclaimer_group) 