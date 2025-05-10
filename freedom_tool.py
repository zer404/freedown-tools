#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自由工具 - 系统监控与限制的反制工具
专门设计用于对抗 jfglzs、przs 和 set 程序的限制
"""

import os
import sys
import logging
import threading
import time
import ctypes
import traceback
import json
import re
import psutil
import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                           QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
                           QTextEdit, QCheckBox, QGroupBox, QMessageBox,
                           QProgressBar, QSystemTrayIcon, QMenu, QAction, QStyle,
                           QFormLayout, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QDialog,
                           QStatusBar, QFileDialog, QGridLayout, QFrame, QTextBrowser,
                           QDateEdit, QLineEdit, QProgressDialog, QStyleFactory)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QEvent, QDate, QMetaObject, Q_ARG
from PyQt5.QtGui import QIcon, QFont, QTextCursor, QColor
import win32con
import win32api
import win32gui
import win32process
import shutil

# 确保src目录在路径中
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# 导入src模块
from src.integrated_countermeasure import IntegratedCountermeasure
from src.countermeasure_manager import CountermeasureManager
from src.window_freedom import WindowFreedom
from src.privilege_manager import PrivilegeManager
from src.random_process_analyzer import RandomProcessAnalyzer
from src.app_controller import AppController

# 设置基本日志配置，以便在导入模块前捕获任何错误
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('freedom_tool.log', encoding='utf-8')
    ]
)
logger = logging.getLogger("FreedomTool")

# 检查是否在Windows平台上运行
if sys.platform != 'win32':
    logger.error("此程序只能在Windows系统上运行！")
    try:
        from PyQt5.QtWidgets import QApplication, QMessageBox
        app = QApplication(sys.argv)
        QMessageBox.critical(None, "平台错误", "此程序只能在Windows系统上运行！")
    except:
        print("错误: 此程序只能在Windows系统上运行！")
    sys.exit(1)

try:
    # 导入自定义模块
    from src.app_controller import AppController
    from src.countermeasure_manager import CountermeasureManager
    from src.window_freedom import WindowFreedom
    from src.nsudo_handler import NsudoHandler
    from src.privilege_manager import PrivilegeManager
    from src.random_process_analyzer import RandomProcessAnalyzer
except Exception as e:
    logger.error(f"导入模块时出错: {e}")
    logger.error(f"详细错误信息: {traceback.format_exc()}")
    try:
        from PyQt5.QtWidgets import QApplication, QMessageBox
        app = QApplication(sys.argv)
        QMessageBox.critical(None, "模块错误", f"导入模块时出错，程序无法启动:\n{e}")
    except:
        print(f"错误: 导入模块时出错，程序无法启动: {e}")
    sys.exit(1)

# 检查是否以管理员权限运行
def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logger.error(f"检查管理员权限时出错: {e}")
        return False

def is_system():
    """检查是否以System权限运行"""
    try:
        import win32security
        import win32process
        
        # 获取当前进程的令牌
        process_token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32security.TOKEN_QUERY
        )
        
        # 获取令牌用户SID
        user_sid = win32security.GetTokenInformation(
            process_token, 
            win32security.TokenUser
        )[0]
        
        # 获取系统SID
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
        
        # 比较SID
        return user_sid == system_sid
    except Exception as e:
        logger.error(f"检查System权限时出错: {e}")
        return False

# 使用keyboard模块实现热键功能
try:
    import keyboard
    KEYBOARD_MODULE_AVAILABLE = True
except ImportError:
    KEYBOARD_MODULE_AVAILABLE = False
    print("警告: keyboard模块导入失败，将使用备用热键方法")

# 快捷键定义
class KeyboardHotKey:
    """使用keyboard模块实现的全局热键管理类"""
    
    def __init__(self):
        self.registered_hotkeys = {}
        self.is_enabled = True
        self.logger = logging.getLogger("FreedomTool.Hotkey")
        
        # 检查keyboard模块是否可用
        self.keyboard_available = KEYBOARD_MODULE_AVAILABLE
        
        if not self.keyboard_available:
            self.logger.warning("keyboard模块不可用，全局热键功能将受限")
    
    def register(self, hotkey_str, callback, description=""):
        """注册全局热键
        
        Args:
            hotkey_str: 热键字符串，如 'ctrl+alt+p'
            callback: 回调函数
            description: 热键描述
            
        Returns:
            成功返回热键ID，失败返回None
        """
        try:
            if not self.keyboard_available:
                self.logger.warning(f"无法注册热键 {hotkey_str}: keyboard模块不可用")
                return None
                
            # 检查热键是否已注册
            if hotkey_str in self.registered_hotkeys:
                # 先注销已存在的热键
                self.unregister(hotkey_str)
            
            # 注册新热键
            keyboard.add_hotkey(hotkey_str, lambda: self._handle_hotkey(hotkey_str))
            
            # 存储热键信息
            self.registered_hotkeys[hotkey_str] = {
                'callback': callback,
                'description': description,
                'active': True
            }
            
            self.logger.info(f"成功注册热键: {hotkey_str} ({description})")
            return hotkey_str
            
        except Exception as e:
            self.logger.error(f"注册热键 {hotkey_str} 失败: {e}")
            return None
    
    def _handle_hotkey(self, hotkey_str):
        """处理热键事件"""
        try:
            if not self.is_enabled:
                return
                
            if hotkey_str in self.registered_hotkeys and self.registered_hotkeys[hotkey_str]['active']:
                callback = self.registered_hotkeys[hotkey_str]['callback']
                self.logger.info(f"触发热键: {hotkey_str}")
                callback()
        except Exception as e:
            self.logger.error(f"处理热键 {hotkey_str} 事件时出错: {e}")
    
    def unregister(self, hotkey_str):
        """注销全局热键"""
        try:
            if not self.keyboard_available:
                return False
                
            if hotkey_str in self.registered_hotkeys:
                keyboard.remove_hotkey(hotkey_str)
                del self.registered_hotkeys[hotkey_str]
                self.logger.info(f"已注销热键: {hotkey_str}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"注销热键 {hotkey_str} 失败: {e}")
            return False
    
    def unregister_all(self):
        """注销所有全局热键"""
        if not self.keyboard_available:
            return
            
        for hotkey_str in list(self.registered_hotkeys.keys()):
            self.unregister(hotkey_str)
        self.logger.info("已注销所有热键")
    
    def enable(self):
        """启用所有热键"""
        self.is_enabled = True
        self.logger.info("已启用所有热键")
    
    def disable(self):
        """禁用所有热键"""
        self.is_enabled = False
        self.logger.info("已禁用所有热键")
    
    def get_registered_hotkeys(self):
        """获取已注册的热键列表"""
        return self.registered_hotkeys

class LogHandler(logging.Handler):
    """自定义日志处理器，用于将日志发送到UI"""
    
    def __init__(self, signal):
        super().__init__()
        self.signal = signal
        self.formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    def emit(self, record):
        log_message = self.formatter.format(record)
        self.signal.emit(log_message)


class FreedomTool(QMainWindow):
    """自由工具主窗口"""
    
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)
    
    # 添加静态实例变量，用于在外部访问
    instance = None
    
    def __init__(self):
        """初始化程序"""
        super(FreedomTool, self).__init__()

        super().__init__()
        
        # 保存实例到类变量
        FreedomTool.instance = self
        
        # 检查启动目录是否在C盘，若不在则自删除
        self.check_startup_directory()
        
        # 初始化日志系统
        self.setup_logging()
        
        # 初始化工具和组件
        try:
            # 先初始化一些基本组件（可能在setup_tools中会用到）
            self.app_controller = None
            self.countermeasure_manager = None
            self.window_freedom = None
            self.nsudo_handler = None
            self.privilege_manager = None
            self.random_process_analyzer = None
            
            # 设置集成反制措施和其他工具
            self.setup_tools()
            
            # 初始化其他直接组件
            if not hasattr(self, 'app_controller') or self.app_controller is None:
                try:
                    from src.app_controller import AppController
                    self.app_controller = AppController()
                except Exception as e:
                    self.logger.error(f"初始化AppController时出错: {e}")
            
            if not hasattr(self, 'countermeasure_manager') or self.countermeasure_manager is None:
                try:
                    from src.countermeasure_manager import CountermeasureManager
                    self.countermeasure_manager = CountermeasureManager()
                except Exception as e:
                    self.logger.error(f"初始化CountermeasureManager时出错: {e}")
            
            if not hasattr(self, 'window_freedom') or self.window_freedom is None:
                try:
                    from src.window_freedom import WindowFreedom
                    self.window_freedom = WindowFreedom()
                except Exception as e:
                    self.logger.error(f"初始化WindowFreedom时出错: {e}")
            
            if not hasattr(self, 'nsudo_handler') or self.nsudo_handler is None:
                try:
                    from src.nsudo_handler import NsudoHandler
                    self.nsudo_handler = NsudoHandler()
                except Exception as e:
                    self.logger.error(f"初始化NsudoHandler时出错: {e}")
            
            if not hasattr(self, 'privilege_manager') or self.privilege_manager is None:
                try:
                    from src.privilege_manager import PrivilegeManager
                    self.privilege_manager = PrivilegeManager()
                except Exception as e:
                    self.logger.error(f"初始化PrivilegeManager时出错: {e}")
        except Exception as e:
            self.logger.error(f"初始化组件时出错: {e}")
        
        # 设置窗口属性
        self.setWindowTitle("自由工具 v1.0 - By zer-zero")
        self.setGeometry(100, 100, 800, 600)
        
        # 设置窗口置顶
        self.setWindowFlag(Qt.WindowStaysOnTopHint)
        
        # 保护状态
        self.is_protection_active = False
        self.protection_thread = None
        self.protection_timer = None
        
        # 网络限制解除状态
        self.is_network_unblock_active = False
        self.network_unblock_timer = None
        
        # 先获取权限状态，以便在UI初始化后使用
        self.current_privilege_level = self.check_privilege_level()
        
        # 创建UI
        self.create_ui()
        
        # 创建系统托盘图标
        self.create_tray_icon()
        
        # 连接信号
        self.connect_signals()
        
        # 更新UI显示权限状态
        if hasattr(self, 'privilege_label'):
            self.privilege_label.setText(f"当前权限: {self.current_privilege_level}")
        
        # 保护线程
        self.protection_timer = QTimer(self)
        self.protection_timer.timeout.connect(self.check_protection_status)
        
        # 初始化全局热键
        self.hotkey_manager = KeyboardHotKey()
        self.register_hotkeys()
        
        # 安装事件过滤器
        self.installEventFilter(self)
        
        # 启动后检查权限并更新UI
        self.update_privilege_status()
        self.logger.info(f"程序启动完成，当前权限: {self.current_privilege_level}")
        self.status_signal.emit("就绪")
    
    def check_startup_directory(self):
        """检查启动目录是否在C盘，如果不在则自删除"""
        try:
            # 获取当前程序的路径
            exe_path = os.path.abspath(sys.argv[0])
            
            # 检查是否在C盘
            if not exe_path.lower().startswith('c:'):
                # 不在C盘，创建自删除批处理脚本
                batch_path = f"{exe_path}.bat"
                with open(batch_path, 'w') as f:
                    f.write(f'@echo off\n')
                    f.write(f'timeout /t 1 /nobreak >nul\n')
                    f.write(f'del "{exe_path}"\n')
                    f.write(f'del "%~f0"\n')
                
                # 启动批处理脚本
                ctypes.windll.shell32.ShellExecuteW(None, "open", batch_path, None, None, 0)
                
                # 退出程序
                sys.exit(0)
        except Exception as e:
            # 如果出现任何错误，继续执行程序
            pass
    
    def setup_logging(self):
        """设置日志系统"""
        self.logger = logging.getLogger("FreedomTool")
        self.logger.setLevel(logging.INFO)
        
        # 添加自定义处理器
        log_handler = LogHandler(self.log_signal)
        log_handler.setLevel(logging.INFO)
        self.logger.addHandler(log_handler)
        
        # 添加流处理器
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)
    
    def create_ui(self):
        """创建用户界面"""
        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 创建主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标题
        title_label = QLabel("自由工具 - 系统监控与限制的反制工具")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        main_layout.addWidget(title_label)
        
        # 创建描述
        desc_label = QLabel("此工具专门用于对抗系统监控与限制程序")
        desc_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(desc_label)
        
        # 创建标签页控件
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # 创建各标签页
        control_tab = self.create_control_tab()
        process_tab = self.create_process_tab()
        log_tab = self.create_log_tab()
        about_tab = self.create_about_tab()
        fireway_tab = self.create_fireway_tab()  # 添加新的Fireway选项卡
        password_tab = self.create_password_tab()  # 创建密码计算选项卡
        
        # 添加各标签页
        self.tab_widget.addTab(control_tab, "控制中心")
        self.tab_widget.addTab(process_tab, "进程与窗口")
        self.tab_widget.addTab(password_tab, "密码计算")  # 添加密码计算选项卡
        self.tab_widget.addTab(log_tab, "日志")
        self.tab_widget.addTab(fireway_tab, "极域防控")  # 添加新的Fireway选项卡
        self.tab_widget.addTab(about_tab, "关于")
        
        # 创建状态栏
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("就绪")
        
        # 注册窗口句柄
        self.main_window_hwnd = int(self.winId())
        if hasattr(self, 'window_freedom') and self.window_freedom:
            self.window_freedom.register_own_window(self.main_window_hwnd)
        
        # 显示窗口
        self.resize(800, 600)
        self.setWindowTitle("自由工具 v1.0 - By zer-zero")
        self.setWindowIcon(self.style().standardIcon(getattr(QStyle, 'SP_ComputerIcon')))
    
    def create_control_tab(self):
        """创建控制中心标签页"""
        control_tab = QWidget()
        layout = QVBoxLayout(control_tab)
        
        # 创建状态组
        status_group = QGroupBox("状态信息")
        status_layout = QVBoxLayout(status_group)
        
        # 当前状态
        self.status_info = QLabel("就绪")
        self.status_info.setAlignment(Qt.AlignCenter)
        self.status_info.setStyleSheet("font-weight: bold;")
        status_layout.addWidget(self.status_info)
        
        # 权限状态
        self.privilege_label = QLabel(f"当前权限: {self.current_privilege_level}")
        self.privilege_label.setAlignment(Qt.AlignCenter)
        if self.current_privilege_level == "管理员":
            self.privilege_label.setStyleSheet("color: green;")
        elif self.current_privilege_level == "System":
            self.privilege_label.setStyleSheet("color: blue;")
        else:
            self.privilege_label.setStyleSheet("color: red;")
        status_layout.addWidget(self.privilege_label)
        
        layout.addWidget(status_group)
        
        # 创建保护选项组
        protection_group = QGroupBox("保护选项")
        protection_layout = QVBoxLayout(protection_group)
        
        # 保护选项复选框
        self.enable_process_check = QCheckBox("进程检查 - 检测和处理监控进程")
        self.enable_process_check.setChecked(True)
        protection_layout.addWidget(self.enable_process_check)
        
        self.enable_window_check = QCheckBox("窗口检查 - 检测和处理锁定窗口")
        self.enable_window_check.setChecked(True)
        protection_layout.addWidget(self.enable_window_check)
        
        self.enable_registry_check = QCheckBox("注册表检查 - 禁用限制性注册表项")
        self.enable_registry_check.setChecked(True)
        protection_layout.addWidget(self.enable_registry_check)
        
        self.enable_process_relationships = QCheckBox("检测相互监控 - 分析进程间关系")
        self.enable_process_relationships.setChecked(True)
        protection_layout.addWidget(self.enable_process_relationships)
        
        self.enable_self_replication = QCheckBox("检测自我复制 - 检测监控软件自我复制行为")
        self.enable_self_replication.setChecked(True)
        protection_layout.addWidget(self.enable_self_replication)
        
        # 添加进程保护选项
        self.enable_process_protection = QCheckBox("进程保护 - 防止反监控进程被终止")
        self.enable_process_protection.setChecked(True)
        protection_layout.addWidget(self.enable_process_protection)
        
        # 添加网络限制解除选项
        self.enable_network_unblock = QCheckBox("解除网络限制 - 定期终止网络过滤服务(3分钟一次)")
        self.enable_network_unblock.setChecked(False)
        self.enable_network_unblock.toggled.connect(self.toggle_network_unblock)
        protection_layout.addWidget(self.enable_network_unblock)

        # 检查频率选择
        frequency_layout = QHBoxLayout()
        frequency_layout.addWidget(QLabel("检查频率:"))
        
        self.check_frequency_combo = QComboBox()
        self.check_frequency_combo.addItem("10 秒", 10)
        self.check_frequency_combo.addItem("30 秒", 30)
        self.check_frequency_combo.addItem("60 秒", 60)
        self.check_frequency_combo.addItem("120 秒", 120)
        self.check_frequency_combo.addItem("300 秒", 300)
        self.check_frequency_combo.setCurrentIndex(1)  # 默认30秒
        frequency_layout.addWidget(self.check_frequency_combo)
        
        protection_layout.addLayout(frequency_layout)
        
        layout.addWidget(protection_group)
        
        # 创建操作按钮组
        actions_group = QGroupBox("操作")
        actions_layout = QVBoxLayout(actions_group)
        
        # 启动/停止按钮
        self.start_stop_button = QPushButton("启动保护")
        self.start_stop_button.clicked.connect(self.toggle_protection)
        actions_layout.addWidget(self.start_stop_button)
        
        # 紧急解锁按钮
        self.emergency_button = QPushButton("紧急解锁")
        self.emergency_button.setStyleSheet("background-color: #ffeeaa;")
        self.emergency_button.clicked.connect(self.emergency_unlock)
        actions_layout.addWidget(self.emergency_button)
        
        # 添加解决网络限制按钮
        self.network_unblock_button = QPushButton("解决网络限制")
        self.network_unblock_button.setStyleSheet("background-color: #aaeeff;")
        self.network_unblock_button.clicked.connect(self.unblock_network)
        actions_layout.addWidget(self.network_unblock_button)
        
        # 终极解锁按钮
        self.ultimate_button = QPushButton("终极解锁")
        self.ultimate_button.setStyleSheet("background-color: #ffdddd; color: red; font-weight: bold;")
        self.ultimate_button.clicked.connect(self.ultimate_unlock)
        actions_layout.addWidget(self.ultimate_button)
        
        # 提升权限按钮
        self.elevate_button = QPushButton("提升至System权限")
        # 检查当前权限和NSudo可用性
        if self.current_privilege_level == "System":
            self.elevate_button.setEnabled(False)
        elif not self.nsudo_handler or not self.nsudo_handler.is_nsudo_available():
            self.elevate_button.setEnabled(False)
            self.elevate_button.setToolTip("NSudoLC.exe未找到，无法提升权限")
        self.elevate_button.clicked.connect(self.elevate_privileges)
        actions_layout.addWidget(self.elevate_button)
        
        layout.addWidget(actions_group)
        
        # 创建全局快捷键信息组
        hotkey_group = QGroupBox("全局快捷键")
        hotkey_layout = QVBoxLayout(hotkey_group)
        
        # 添加热键状态显示标签
        self.hotkey_info_label = QLabel()
        self.hotkey_info_label.setTextFormat(Qt.RichText)
        hotkey_layout.addWidget(self.hotkey_info_label)
        
        # 添加热键信息按钮
        hotkey_info_button = QPushButton("热键详情")
        hotkey_info_button.clicked.connect(self.show_hotkey_info)
        hotkey_layout.addWidget(hotkey_info_button)
        
        layout.addWidget(hotkey_group)
        
        # 添加作者信息标签
        author_label = QLabel()
        author_label.setAlignment(Qt.AlignCenter)
        author_label.setTextFormat(Qt.RichText)
        author_label.setOpenExternalLinks(True)
        author_label.setText('<div style="margin-top: 10px; color: #666;">作者: <b>zer-zero</b> | 官网: <a href="http://zer-zero.cn">http://zer-zero.cn</a></div>')
        layout.addWidget(author_label)
        
        return control_tab
    
    def show_hotkey_info(self):
        """显示快捷键信息对话框"""
        try:
            info_dialog = QMessageBox(self)
            info_dialog.setWindowTitle("快捷键信息")
            info_dialog.setIcon(QMessageBox.Information)
            
            hotkey_info = """
            <h3>全局快捷键列表:</h3>
            <p><b>Win+F1</b>: 紧急解锁 - 解除鼠标限制和关闭锁定窗口</p>
            <p><b>Win+F2</b>: 启动/停止保护 - 切换保护状态</p>
            <p><b>Win+F3</b>: 刷新保护 - 立即刷新进程监控</p>
            <p><b>Win+F4</b>: 显示/隐藏窗口 - 控制主窗口可见性</p>
            <p><b>Win+F12</b>: 终极解锁 - 终止除系统和自身外的所有进程</p>
            <p><b>Ctrl+Alt+U</b>: 启动保护 - 快速启动保护功能</p>
            
            <h3>终极解锁说明:</h3>
            <p style='color:red;'>警告: 终极解锁功能将使用最高可用权限(System或管理员)终止除系统和重要进程外的所有进程。这可能导致未保存的数据丢失，请谨慎使用!</p>
            """
            
            info_dialog.setText(hotkey_info)
            info_dialog.setStandardButtons(QMessageBox.Ok)
            
            info_dialog.exec_()
        except Exception as e:
            self.logger.error(f"显示快捷键信息时出错: {e}")
    
    def create_process_tab(self):
        """创建进程管理标签页"""
        process_tab = QWidget()
        layout = QVBoxLayout(process_tab)
        
        # 创建进程列表组
        process_group = QGroupBox("可疑进程列表")
        process_layout = QVBoxLayout(process_group)
        
        # 创建进程表格
        self.process_table = QTableWidget(0, 5)
        self.process_table.setHorizontalHeaderLabels(["PID", "进程名", "类型", "状态", "路径"])
        self.process_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)  # 路径列可伸缩
        self.process_table.setSelectionBehavior(QTableWidget.SelectRows)
        process_layout.addWidget(self.process_table)
        
        # 创建操作按钮布局
        button_layout = QHBoxLayout()
        
        # 添加刷新按钮
        refresh_button = QPushButton("刷新进程列表")
        refresh_button.clicked.connect(self.refresh_process_list)
        button_layout.addWidget(refresh_button)
        
        # 添加降低权限按钮
        lower_button = QPushButton("降低选中进程权限")
        lower_button.clicked.connect(self.lower_selected_process_privilege)
        button_layout.addWidget(lower_button)
        
        # 添加全部降权按钮
        lower_all_button = QPushButton("降低所有可疑进程权限")
        lower_all_button.clicked.connect(self.lower_all_processes_privileges)
        button_layout.addWidget(lower_all_button)
        
        process_layout.addLayout(button_layout)
        
        # 创建窗口列表组
        window_group = QGroupBox("可疑窗口列表")
        window_layout = QVBoxLayout(window_group)
        
        # 创建窗口表格
        self.window_table = QTableWidget(0, 5)
        self.window_table.setHorizontalHeaderLabels(["句柄", "标题", "类名", "PID", "状态"])
        self.window_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)  # 标题列可伸缩
        self.window_table.setSelectionBehavior(QTableWidget.SelectRows)
        window_layout.addWidget(self.window_table)
        
        # 创建窗口操作按钮布局
        window_button_layout = QHBoxLayout()
        
        # 添加刷新按钮
        window_refresh_button = QPushButton("刷新窗口列表")
        window_refresh_button.clicked.connect(self.refresh_window_list)
        window_button_layout.addWidget(window_refresh_button)
        
        # 添加关闭窗口按钮
        close_window_button = QPushButton("关闭选中窗口")
        close_window_button.clicked.connect(self.close_selected_window)
        window_button_layout.addWidget(close_window_button)
        
        # 添加取消置顶按钮
        untopmost_button = QPushButton("取消窗口置顶")
        untopmost_button.clicked.connect(self.remove_selected_window_topmost)
        window_button_layout.addWidget(untopmost_button)
        
        window_layout.addLayout(window_button_layout)
        
        # 添加到主布局
        layout.addWidget(process_group)
        layout.addWidget(window_group)
        
        return process_tab
    
    def create_log_tab(self):
        """创建日志标签页"""
        log_tab = QWidget()
        layout = QVBoxLayout(log_tab)
        
        # 创建日志文本框
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        # 创建按钮布局
        button_layout = QHBoxLayout()
        
        # 添加清除按钮
        clear_button = QPushButton("清除日志")
        clear_button.clicked.connect(self.clear_log)
        button_layout.addWidget(clear_button)
        
        # 添加保存按钮
        save_button = QPushButton("保存日志")
        save_button.clicked.connect(self.save_log)
        button_layout.addWidget(save_button)
        
        layout.addLayout(button_layout)
        
        return log_tab
    
    def save_log(self):
        """保存日志到文件"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "保存日志", "", "文本文件 (*.txt);;所有文件 (*)"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.toPlainText())
                self.status_signal.emit(f"日志已保存到 {filename}")
        except Exception as e:
            self.logger.error(f"保存日志时出错: {e}")
            self.status_signal.emit(f"保存日志失败: {e}")
    
    def create_about_tab(self):
        """创建关于标签页"""
        about_tab = QWidget()
        layout = QVBoxLayout(about_tab)
        
        # 添加关于信息
        about_text = QTextBrowser()
        about_text.setReadOnly(True)
        about_text.setHtml("""
        <h2 align="center">自由工具</h2>
        <p align="center">系统监控与限制的反制工具</p>
        <p align="center">版本: 1.0.0</p>
        <p align="center">作者: <b>zer-zero</b> | 官网: <a href="http://zer-zero.cn">http://zer-zero.cn</a></p>
        <p>此工具专门用于对抗系统监控与限制程序，如jfglzs、przs和set等。主要功能包括:</p>
        <ul>
            <li>终止监控进程：安全终止监控程序的进程</li>
            <li>禁用注册表限制：修改注册表以禁用监控限制</li>
            <li>防止窗口锁定：阻止全屏锁定窗口</li>
            <li>解除鼠标限制：恢复鼠标自由移动</li>
            <li>禁用监控服务：停止与监控相关的Windows服务</li>
            <li>禁用自启动项：阻止监控程序自动启动</li>
        </ul>
        <p><b>注意：</b>此工具仅供教育和研究目的使用。用户应确保在合法和授权的情况下使用此工具。</p>
        <p><b>使用方法：</b></p>
        <ol>
            <li>在"控制中心"标签页选择需要的保护功能</li>
            <li>点击"启动保护"按钮开始保护</li>
            <li>保护运行期间，工具将持续监控并反制限制</li>
            <li>如遇紧急情况，点击"紧急解锁"按钮快速解除限制</li>
        </ol>
        <p><b>全局快捷键：</b></p>
        <ul>
            <li><b>Win+F1</b>: 紧急解锁 - 在鼠标被限制或屏幕被锁定时使用</li>
            <li><b>Win+F2</b>: 启动/停止保护 - 快速切换保护状态</li>
            <li><b>Win+F3</b>: 刷新保护 - 立即检查并更新保护状态</li>
            <li><b>Win+F4</b>: 显示/隐藏窗口 - 快速切换窗口可见性</li>
        </ul>
        <p align="center">© 2023-2024 <a href="http://zer-zero.cn">zer-zero</a>. 保留所有权利。</p>
        """)
        about_text.setOpenExternalLinks(True)  # QTextBrowser支持这个方法
        layout.addWidget(about_text)
        
        self.about_tab = about_tab
        return about_tab
    
    def create_tray_icon(self):
        """创建系统托盘图标"""
        try:
            # 创建系统托盘图标
            self.tray_icon = QSystemTrayIcon(self)
            # 使用系统默认图标
            self.tray_icon.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_ComputerIcon')))
            
            # 创建托盘菜单
            tray_menu = QMenu()
            
            show_action = QAction("显示窗口 (Win+F4)", self)
            show_action.triggered.connect(self.show)
            tray_menu.addAction(show_action)
            
            hide_action = QAction("隐藏窗口 (Win+F4)", self)
            hide_action.triggered.connect(self.hide)
            tray_menu.addAction(hide_action)
            
            tray_menu.addSeparator()
            
            self.start_action = QAction("启动保护 (Win+F2/Ctrl+Alt+U)", self)
            self.start_action.triggered.connect(self.start_protection)
            tray_menu.addAction(self.start_action)
            
            self.stop_action = QAction("停止保护 (Win+F2)", self)
            self.stop_action.triggered.connect(self.stop_protection)
            self.stop_action.setEnabled(False)
            tray_menu.addAction(self.stop_action)
            
            emergency_action = QAction("紧急解锁 (Win+F1)", self)
            emergency_action.triggered.connect(self.emergency_unlock)
            emergency_action.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_MessageBoxWarning')))
            tray_menu.addAction(emergency_action)
            
            # 添加终极解锁菜单项
            ultimate_action = QAction("终极解锁 (Win+F12)", self)
            ultimate_action.triggered.connect(self.ultimate_unlock)
            ultimate_action.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_MessageBoxCritical')))
            # 设置红色文本
            ultimate_action_font = ultimate_action.font()
            ultimate_action_font.setBold(True)
            ultimate_action.setFont(ultimate_action_font)
            tray_menu.addAction(ultimate_action)
            
            refresh_action = QAction("刷新保护 (Win+F3)", self)
            refresh_action.triggered.connect(self.refresh_protection)
            tray_menu.addAction(refresh_action)
            
            tray_menu.addSeparator()
            
            # 快捷键子菜单
            hotkeys_menu = QMenu("快捷键信息", self)
            
            # 存储快捷键菜单项，用于后续更新
            self.hotkey_actions = {}
            
            win_f1_action = QAction("Win+F1: 紧急解锁", self)
            hotkeys_menu.addAction(win_f1_action)
            self.hotkey_actions["Win+F1"] = win_f1_action
            
            win_f2_action = QAction("Win+F2: 启动/停止保护", self)
            hotkeys_menu.addAction(win_f2_action)
            self.hotkey_actions["Win+F2"] = win_f2_action
            
            win_f3_action = QAction("Win+F3: 刷新保护", self)
            hotkeys_menu.addAction(win_f3_action)
            self.hotkey_actions["Win+F3"] = win_f3_action
            
            win_f4_action = QAction("Win+F4: 显示/隐藏窗口", self)
            hotkeys_menu.addAction(win_f4_action)
            self.hotkey_actions["Win+F4"] = win_f4_action
            
            # 添加终极解锁快捷键信息
            win_f12_action = QAction("Win+F12: 终极解锁", self)
            hotkeys_menu.addAction(win_f12_action)
            self.hotkey_actions["Win+F12"] = win_f12_action
            
            # 添加启动保护快捷键信息
            ctrl_alt_u_action = QAction("Ctrl+Alt+U: 启动保护", self)
            hotkeys_menu.addAction(ctrl_alt_u_action)
            self.hotkey_actions["Ctrl+Alt+U"] = ctrl_alt_u_action
            
            tray_menu.addMenu(hotkeys_menu)
            
            tray_menu.addSeparator()
            
            quit_action = QAction("退出", self)
            quit_action.triggered.connect(self.close)
            tray_menu.addAction(quit_action)
            
            # 设置托盘菜单
            self.tray_icon.setContextMenu(tray_menu)
            
            # 连接信号
            self.tray_icon.activated.connect(self.tray_icon_activated)
            
            # 显示系统托盘图标
            self.tray_icon.show()
            
        except Exception as e:
            self.logger.error(f"创建系统托盘图标时出错: {e}")
    
    def connect_signals(self):
        """连接信号和槽"""
        # 日志和状态信号
        self.log_signal.connect(self.update_log)
        self.status_signal.connect(self.update_status)
        
        # 连接极域防控相关的信号
        if hasattr(self, 'fw_blackscreen_check'):
            self.fw_blackscreen_check.stateChanged.connect(self.save_fireway_config)
        
        if hasattr(self, 'fw_monitoring_check'):
            self.fw_monitoring_check.stateChanged.connect(self.save_fireway_config)
        
        if hasattr(self, 'fw_process_check'):
            self.fw_process_check.stateChanged.connect(self.save_fireway_config)
        
        # 将极域防控日志连接到主日志
        if hasattr(self, 'fw_log_text'):
            self.log_signal.connect(self.add_fireway_log)
    
    def update_log(self, message):
        """更新日志显示"""
        self.log_text.append(message)
        self.log_text.moveCursor(QTextCursor.End)
    
    def update_status(self, message):
        """更新状态栏显示"""
        try:
            self.status_signal.emit(message)
            
            # 同时更新控制中心的状态信息显示
            if hasattr(self, 'status_info'):
                if "启动保护" in message:
                    self.status_info.setText("正在启动保护...")
                elif "停止保护" in message:
                    self.status_info.setText("正在停止保护...")
                elif "紧急解锁" in message:
                    self.status_info.setText("执行紧急解锁...")
                elif "终极解锁" in message:
                    # 设置红色样式表
                    self.status_info.setStyleSheet("color: red; font-weight: bold;")
                    self.status_info.setText(message)
                else:
                    # 恢复默认样式表
                    self.status_info.setStyleSheet("")
                    self.status_info.setText(message)
                    
            # 记录状态变化到日志
            self.logger.info(f"状态变化: {message}")
        except Exception as e:
            self.logger.error(f"更新状态时出错: {e}")
    
    def clear_log(self):
        """清除日志"""
        self.log_text.clear()
    
    def check_privilege_level(self):
        """检查当前权限级别"""
        try:
            if sys.platform == 'win32':
                import ctypes
                if is_system():
                    return "System"
                elif ctypes.windll.shell32.IsUserAnAdmin() != 0:
                    return "管理员"
                else:
                    return "普通用户"
            else:
                # 在Unix系统中检查是否为root
                if os.geteuid() == 0:
                    return "Root"
                else:
                    return "普通用户"
        except:
            return "未知"
    
    def update_privilege_status(self):
        """更新权限状态并刷新UI显示"""
        try:
            # 重新检查当前权限
            self.current_privilege_level = self.check_privilege_level()
            
            # 更新权限标签
            if hasattr(self, 'privilege_label') and self.privilege_label:
                self.privilege_label.setText(f"当前权限: {self.current_privilege_level}")
                
                # 根据不同权限设置不同颜色
                if self.current_privilege_level == "管理员":
                    self.privilege_label.setStyleSheet("color: green;")
                elif self.current_privilege_level == "System":
                    self.privilege_label.setStyleSheet("color: blue;")
                else:
                    self.privilege_label.setStyleSheet("color: red;")
            
            # 根据权限状态更新提权按钮
            if hasattr(self, 'elevate_button') and self.elevate_button:
                if self.current_privilege_level == "System":
                    self.elevate_button.setEnabled(False)
                    self.elevate_button.setText("已获取System权限")
                    self.elevate_button.setToolTip("已经是最高权限，无需提升")
                elif not self.nsudo_handler or not self.nsudo_handler.is_nsudo_available():
                    self.elevate_button.setEnabled(False)
                    self.elevate_button.setToolTip("NSudoLC.exe未找到，无法提升权限")
                else:
                    self.elevate_button.setEnabled(True)
                    self.elevate_button.setText("提升至System权限")
                    self.elevate_button.setToolTip("点击提升到System权限")
            
            # 记录权限变更到日志
            self.logger.info(f"权限状态已更新: {self.current_privilege_level}")
            
            # 更新状态栏
            if hasattr(self, 'statusBar') and self.statusBar:
                self.statusBar.showMessage(f"当前权限: {self.current_privilege_level}", 5000)
                
        except Exception as e:
            self.logger.error(f"更新权限状态时出错: {e}")
    
    def start_protection(self):
        """启动保护功能，使用main.py的逻辑"""
        try:
            self.logger.info("正在启动保护...")
            self.status_signal.emit("状态: 正在启动保护...")
            
            # 确保IntegratedCountermeasure对象存在
            if not hasattr(self, 'countermeasure') or self.countermeasure is None:
                self.countermeasure = IntegratedCountermeasure()
                if hasattr(self, 'main_window_hwnd') and self.main_window_hwnd:
                    self.countermeasure.register_window(self.main_window_hwnd)
                else:
                    self.countermeasure.register_window(int(self.winId()))
            
            # 获取设置选项
            protection_settings = self.get_protection_settings()
            
            # 应用设置
            if hasattr(self.countermeasure, 'countermeasure_manager') and self.countermeasure.countermeasure_manager:
                # 设置检查频率
                if hasattr(self, 'check_frequency_combo') and self.check_frequency_combo:
                    try:
                        check_frequency = int(self.check_frequency_combo.currentText().split()[0])
                        self.logger.info(f"设置检查频率: {check_frequency}秒")
                    except (ValueError, IndexError):
                        check_frequency = 30  # 默认30秒
                    
                    self.countermeasure.countermeasure_manager.check_interval = check_frequency
            
            # 启动保护
            if self.countermeasure.start_protection():
                self.is_protection_active = True
                self.status_signal.emit("保护状态: 运行中")
                
                # 更新UI
                if hasattr(self, 'start_stop_button'):
                    self.start_stop_button.setText("停止保护")
                    self.start_stop_button.setStyleSheet("background-color: #ffcccc;")
                
                # 更新托盘菜单
                if hasattr(self, 'tray_toggle_action'):
                    self.tray_toggle_action.setText("停止保护")
                
                # 设置保护状态检查定时器
                self.setup_protection_timer()
            else:
                self.status_signal.emit("保护状态: 启动失败")
                self.logger.error("保护启动失败")
                QMessageBox.warning(self, "错误", "保护启动失败，请检查权限和系统状态。")
        except Exception as e:
            self.status_signal.emit(f"保护状态: 启动出错 - {e}")
            self.logger.error(f"启动保护时出错: {e}")
            QMessageBox.warning(self, "错误", f"启动保护时出错: {e}")
        
        # 强制更新UI状态
        self.check_protection_status()
    
    def stop_protection(self):
        """停止保护，使用main.py的逻辑"""
        try:
            self.logger.info("正在停止保护...")
            self.status_signal.emit("状态: 正在停止保护...")
            
            # 确保countermeasure存在
            if not hasattr(self, 'countermeasure') or self.countermeasure is None:
                self.logger.warning("无法停止保护: countermeasure未初始化")
                self.status_signal.emit("保护状态: 未启动")
                return
            
            # 停止保护
            if self.countermeasure.stop_protection():
                self.is_protection_active = False
                self.status_signal.emit("保护状态: 已停止")
                
                # 更新UI
                if hasattr(self, 'start_stop_button'):
                    self.start_stop_button.setText("启动保护")
                    self.start_stop_button.setStyleSheet("")
                
                # 更新托盘菜单
                if hasattr(self, 'tray_toggle_action'):
                    self.tray_toggle_action.setText("启动保护")
                
                # 停止保护状态检查定时器
                if hasattr(self, 'protection_timer') and self.protection_timer:
                    self.protection_timer.stop()
            else:
                self.status_signal.emit("保护状态: 停止失败")
                self.logger.error("保护停止失败")
                QMessageBox.warning(self, "错误", "保护停止失败，可能需要手动重启程序。")
        except Exception as e:
            self.status_signal.emit(f"保护状态: 停止出错 - {e}")
            self.logger.error(f"停止保护时出错: {e}")
            QMessageBox.warning(self, "错误", f"停止保护时出错: {e}")
        
        # 强制更新UI状态
        self.check_protection_status()
    
    def get_protection_settings(self):
        """获取保护设置选项"""
        settings = {}
        
        # 从UI获取设置
        if hasattr(self, 'enable_process_check') and self.enable_process_check:
            settings["enable_process_check"] = self.enable_process_check.isChecked()
        else:
            settings["enable_process_check"] = True
        
        if hasattr(self, 'enable_window_check') and self.enable_window_check:
            settings["enable_window_check"] = self.enable_window_check.isChecked()
        else:
            settings["enable_window_check"] = True
        
        if hasattr(self, 'enable_registry_check') and self.enable_registry_check:
            settings["enable_registry_check"] = self.enable_registry_check.isChecked()
        else:
            settings["enable_registry_check"] = True
        
        if hasattr(self, 'enable_process_relationships') and self.enable_process_relationships:
            settings["enable_process_relationships"] = self.enable_process_relationships.isChecked()
        else:
            settings["enable_process_relationships"] = True
        
        if hasattr(self, 'enable_self_replication') and self.enable_self_replication:
            settings["enable_self_replication"] = self.enable_self_replication.isChecked()
        else:
            settings["enable_self_replication"] = True
            
        # 添加进程保护设置
        if hasattr(self, 'enable_process_protection') and self.enable_process_protection:
            settings["enable_process_protection"] = self.enable_process_protection.isChecked()
        else:
            settings["enable_process_protection"] = True
        
        return settings
    
    def emergency_unlock(self):
        """紧急解锁，使用main.py的逻辑"""
        try:
            self.logger.info("执行紧急解锁...")
            self.status_signal.emit("状态: 正在执行紧急解锁...")
            
            # 创建一个线程执行紧急解锁，避免主线程阻塞
            unlock_thread = threading.Thread(target=self._execute_emergency_unlock)
            unlock_thread.daemon = True
            unlock_thread.start()
            
            return True
        except Exception as e:
            self.logger.error(f"紧急解锁启动时出错: {e}")
            self.status_signal.emit(f"紧急解锁启动出错: {e}")
            return False
            
    def _execute_emergency_unlock(self):
        """在线程中执行紧急解锁操作"""
        try:
            if hasattr(self, 'countermeasure') and self.countermeasure is not None:
                try:
                    # 设置超时限制，防止卡死
                    max_time = 5  # 最多执行5秒
                    start_time = time.time()
                    
                    # 创建一个事件标志来追踪完成状态
                    completed = threading.Event()
                    result = False
                    
                    # 在另一个线程中执行实际解锁操作
                    def do_unlock():
                        try:
                            nonlocal result
                            result = self.countermeasure.emergency_unlock()
                            completed.set()  # 标记完成
                        except Exception as e:
                            self.logger.error(f"紧急解锁执行时出错: {e}")
                            completed.set()  # 标记完成但出错
                    
                    # 启动解锁线程
                    unlock_worker = threading.Thread(target=do_unlock)
                    unlock_worker.daemon = True
                    unlock_worker.start()
                    
                    # 等待完成或超时
                    completed.wait(max_time)
                    
                    # 检查是否超时
                    elapsed = time.time() - start_time
                    if not completed.is_set():
                        self.logger.warning(f"紧急解锁操作超时 ({elapsed:.2f}秒)，可能存在死锁")
                        # 在UI线程中显示超时消息
                        self.status_signal.emit("紧急解锁操作超时")
                        return False
                    
                    # 检查解锁结果
                    if result:
                        self.status_signal.emit("紧急解锁成功")
                        self.logger.info("紧急解锁成功")
                    else:
                        self.status_signal.emit("紧急解锁部分成功")
                        self.logger.warning("紧急解锁部分成功")
                    
                    return result
                    
                except Exception as e:
                    self.logger.error(f"紧急解锁线程执行出错: {e}")
                    self.status_signal.emit(f"紧急解锁线程出错: {e}")
                    return False
                
            else:
                # 使用备用方法解锁
                self.logger.warning("countermeasure未初始化，使用备用方法解锁")
                self.status_signal.emit("使用备用方法解锁")
                
                # 创建独立的WindowFreedom实例执行解锁
                try:
                    from src.window_freedom import WindowFreedom
                    window_freedom = WindowFreedom()
                    
                    # 设置超时限制，防止卡死
                    max_time = 5  # 最多执行5秒
                    results = {"cursor_freed": False, "lock_windows_count": 0, "timers_disabled": False}
                    
                    # 先强制释放鼠标
                    try:
                        # 使用超时调用
                        cursor_thread = threading.Thread(target=lambda: window_freedom.force_free_cursor())
                        cursor_thread.daemon = True
                        cursor_thread.start()
                        cursor_thread.join(2)  # 2秒超时
                        
                        # 如果线程仍在运行，说明超时了
                        if cursor_thread.is_alive():
                            self.logger.warning("释放鼠标操作超时")
                        else:
                            results["cursor_freed"] = True
                    except Exception as e:
                        self.logger.error(f"释放鼠标时出错: {e}")
                    
                    # 处理锁屏窗口
                    try:
                        # 使用超时调用
                        window_thread = threading.Thread(target=lambda: setattr(results, "lock_windows_count", window_freedom.handle_lock_windows()))
                        window_thread.daemon = True
                        window_thread.start()
                        window_thread.join(2)  # 2秒超时
                        
                        # 如果线程仍在运行，说明超时了
                        if window_thread.is_alive():
                            self.logger.warning("处理锁屏窗口操作超时")
                    except Exception as e:
                        self.logger.error(f"处理锁屏窗口时出错: {e}")
                    
                    # 禁用锁定计时器
                    try:
                        # 使用超时调用
                        timer_thread = threading.Thread(target=lambda: setattr(results, "timers_disabled", window_freedom.disable_lock_timers()))
                        timer_thread.daemon = True
                        timer_thread.start()
                        timer_thread.join(2)  # 2秒超时
                        
                        # 如果线程仍在运行，说明超时了
                        if timer_thread.is_alive():
                            self.logger.warning("禁用计时器操作超时")
                    except Exception as e:
                        self.logger.error(f"禁用计时器时出错: {e}")
                    
                    # 检查结果
                    if results["cursor_freed"] or results["lock_windows_count"] > 0 or results["timers_disabled"]:
                        self.status_signal.emit(f"备用解锁成功: 处理了{results['lock_windows_count']}个锁屏窗口")
                        self.logger.info(f"备用解锁成功: 鼠标状态={results['cursor_freed']}, 锁屏窗口={results['lock_windows_count']}, 计时器={results['timers_disabled']}")
                    else:
                        self.status_signal.emit("备用解锁未发现需要处理的限制")
                        self.logger.info("备用解锁未发现需要处理的限制")
                        
                except Exception as backup_e:
                    self.logger.error(f"备用解锁方法失败: {backup_e}")
                    self.status_signal.emit(f"备用解锁失败: {backup_e}")
            
            # 强制检查当前保护状态
            self.check_protection_status()
            
            return True
        
        except Exception as e:
            self.logger.error(f"紧急解锁执行时出错: {e}")
            self.status_signal.emit(f"紧急解锁出错: {e}")
            return False
    
    def check_protection_status(self):
        """检查保护状态"""
        if not self.is_protection_active:
            return
        
        try:
            self.logger.debug("检查保护状态...")
            
            # 检查并释放鼠标限制
            if self.mouse_protection_checkbox.isChecked():
                self.privilege_manager.free_cursor()
                self.window_freedom.free_cursor()
            
            # 检查随机进程
            if self.random_process_checkbox.isChecked():
                # 使用新的随机进程分析器检查随机进程
                suspicious_processes = self.random_process_analyzer.scan_przs_processes()
                if suspicious_processes:
                    self.logger.info(f"发现 {len(suspicious_processes)} 个可疑随机进程")
                    
                    # 检查是否需要降低权限
                    if self.process_privilege_checkbox.isChecked():
                        for proc in suspicious_processes:
                            self.random_process_analyzer.lower_process_privilege(proc['pid'])
                
                # 同时使用privilege_manager进行检查
                result = self.privilege_manager.scan_target_processes()
                if result:
                    for proc_name, pid_list in result.items():
                        self.logger.info(f"发现目标进程: {proc_name}, 共{len(pid_list)}个实例")
                        
                        # 检查是否需要降低权限
                        if self.process_privilege_checkbox.isChecked():
                            for pid in pid_list:
                                self.privilege_manager.lower_process_privilege(pid)
            
            # 检查进程树分析
            if self.random_process_checkbox.isChecked():
                self.countermeasure_manager.analyze_process_relationships()
            
            # 进程保护
            settings = self.get_protection_settings()
            if settings.get("enable_process_protection", True):
                self._protect_own_process()
            
        except Exception as e:
            self.logger.error(f"检查保护状态时出错: {e}")

    def _protect_own_process(self):
        """保护当前进程不被终止"""
        try:
            import win32api
            import win32con
            import win32process
            import win32security
            
            # 获取当前进程ID
            current_pid = os.getpid()
            
            # 打开进程
            hProcess = win32api.OpenProcess(
                win32con.PROCESS_ALL_ACCESS,
                False,
                current_pid
            )
            
            if hProcess:
                # 获取进程访问令牌
                hToken = win32security.OpenProcessToken(
                    hProcess,
                    win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
                )
                
                # 设置进程保护特权
                privilege_id = win32security.LookupPrivilegeValue(
                    None, 
                    win32security.SE_DEBUG_NAME
                )
                
                # 启用特权
                new_privileges = [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)]
                win32security.AdjustTokenPrivileges(hToken, 0, new_privileges)
                
                # 关闭句柄
                win32api.CloseHandle(hToken)
                win32api.CloseHandle(hProcess)
                
                self.logger.debug("已启用进程保护")
        except Exception as e:
            self.logger.error(f"启用进程保护时出错: {e}")
    
    def tray_icon_activated(self, reason):
        """处理托盘图标激活事件"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
    
    def closeEvent(self, event):
        """处理窗口关闭事件"""
        try:
            # 保存极域防控配置
            if hasattr(self, 'fw_config_file'):
                self.save_fireway_config()
            
            # 停止极域防控保护
            if hasattr(self, 'fw_protection_active') and self.fw_protection_active:
                self.stop_fireway_protection()
            
            # 注销所有热键
            try:
                if hasattr(self, 'hotkey_manager') and self.hotkey_manager:
                    self.hotkey_manager.unregister_all()
                    self.logger.info("已注销所有全局热键")
                    
                # 尝试清理keyboard模块
                if KEYBOARD_MODULE_AVAILABLE:
                    try:
                        keyboard.unhook_all()
                        self.logger.info("已清理keyboard模块所有钩子")
                    except Exception as ke:
                        self.logger.error(f"清理keyboard模块钩子时出错: {ke}")
            except Exception as e:
                self.logger.error(f"注销全局热键时出错: {e}")
            
            if self.is_protection_active:
                reply = QMessageBox.question(
                    self, "确认", 
                    "保护功能仍在运行中。\n\n选择'是'关闭窗口但保持保护在后台运行（可从系统托盘访问）。\n选择'否'停止保护并完全退出程序。",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                
                if reply == QMessageBox.Yes:
                    # 仅隐藏窗口
                    event.ignore()
                    self.hide()
                    
                    # 显示托盘通知
                    self.tray_icon.showMessage(
                        "自由工具", 
                        "程序已最小化到系统托盘继续运行。\n双击托盘图标可重新打开窗口。\n使用Win+F1可紧急解锁，Win+F4可显示窗口。", 
                        QSystemTrayIcon.Information, 
                        5000
                    )
                else:
                    # 停止保护并退出
                    self.stop_protection()
                    self.close_application()
            else:
                reply = QMessageBox.question(
                    self, "确认", 
                    "确定要退出程序吗？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    self.close_application()
                else:
                    event.ignore()
        except Exception as e:
            self.logger.error(f"关闭窗口时出错: {e}")
            event.accept()  # 确保在出错时还是可以关闭窗口
    
    def close_application(self):
        """关闭应用程序"""
        try:
            # 停止所有保护
            if self.is_protection_active:
                self.stop_protection()
            
            # 退出应用
            QApplication.quit()
        except Exception as e:
            self.logger.error(f"关闭应用程序时出错: {e}")
            QApplication.quit()
    
    def elevate_privileges(self):
        """提权至System权限"""
        try:
            self.logger.info("尝试提权至System权限...")
            
            # 检查当前权限
            if self.check_privilege_level() == "System":
                self.logger.info("当前已经以System权限运行，无需提升")
                self.status_signal.emit("当前已经以System权限运行，无需提升")
                return True
            
            # 检查是否以管理员权限运行
            if not is_admin():
                self.logger.warning("提升至System权限需要先以管理员身份运行程序")
                self.status_signal.emit("提升至System权限需要先以管理员身份启动程序")
                
                # 尝试重启为管理员
                if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1):
                    self.logger.info("已请求以管理员权限重启程序")
                    self.status_signal.emit("正在以管理员权限重启程序...")
                    self.close_application()
                return False
            
            # 检查NSudo是否存在
            if not self.nsudo_handler or not self.nsudo_handler.is_nsudo_available():
                self.logger.error("未找到NSudoLC.exe，无法提升权限")
                self.status_signal.emit("提权失败：未找到NSudoLC.exe")
                return False
            
            # 使用NSudo重启程序
            try:
                # 获取当前运行的命令行
                cmd_line = " ".join([f'"{arg}"' for arg in sys.argv])
                
                # 使用NSudo重启程序
                result = self.nsudo_handler.restart_as_system(cmd_line)
                
                if result:
                    self.logger.info("已使用NSudo请求System权限")
                    self.status_signal.emit("正在使用System权限重启程序...")
                    # 关闭当前实例
                    self.close_application()
                else:
                    self.logger.error("使用NSudo提升权限失败")
                    self.status_signal.emit("提升至System权限失败")
            except Exception as e:
                self.logger.error(f"提升至System权限失败：{e}")
                self.status_signal.emit(f"提升至System权限失败：{e}")
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"提升权限时出错: {e}")
            self.status_signal.emit(f"提升权限时出错: {e}")
            return False
    
    def scan_random_processes(self):
        """扫描随机命名的进程"""
        self.logger.info("开始扫描随机进程...")
        self.status_signal.emit("正在扫描随机进程...")
        
        try:
            # 清空表格
            self.process_table.setRowCount(0)
            
            # 扫描可疑进程
            processes = self.random_process_analyzer.scan_przs_processes()
            
            if not processes:
                self.logger.info("未发现任何可疑的随机命名进程")
                QMessageBox.information(self, "扫描结果", "未发现任何可疑的随机命名进程。")
                return
            
            # 填充表格
            for i, proc in enumerate(processes):
                self.process_table.insertRow(i)
                
                # PID
                pid_item = QTableWidgetItem(str(proc['pid']))
                self.process_table.setItem(i, 0, pid_item)
                
                # 进程名
                name_item = QTableWidgetItem(proc['name'])
                self.process_table.setItem(i, 1, name_item)
                
                # 路径
                path_item = QTableWidgetItem(proc.get('exe', '未知'))
                self.process_table.setItem(i, 2, path_item)
                
                # 可疑度
                score_item = QTableWidgetItem(str(proc['suspicious_score']))
                self.process_table.setItem(i, 3, score_item)
            
            self.logger.info(f"扫描完成，发现 {len(processes)} 个可疑的随机命名进程")
            self.status_signal.emit(f"发现 {len(processes)} 个可疑进程")
            
            # 更新已降权进程列表
            self.refresh_lowered_processes()
            
        except Exception as e:
            self.logger.error(f"扫描随机进程时出错: {e}")
            self.status_signal.emit("扫描随机进程失败")
            QMessageBox.critical(self, "扫描错误", f"扫描随机进程时出错: {e}")
    
    def terminate_process(self, pid, force=False, timeout=3):
        """终止指定的进程，增强的多种方法尝试
        
        Args:
            pid: 进程ID
            force: 是否强制终止进程
            timeout: 等待进程退出的超时时间（秒）
            
        Returns:
            成功返回True，失败返回False
        """
        try:
            # 尝试获取进程信息
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except psutil.NoSuchProcess:
                self.logger.info(f"进程 PID: {pid} 不存在")
                return True  # 进程已经不存在，视为成功
            except psutil.AccessDenied:
                proc_name = f"PID: {pid} (无法访问)"
            
            # 使用多种方法尝试终止进程
            success = False
            
            # 方法1: 尝试使用psutil终止/杀死进程
            if not success:
                try:
                    if force:
                        # 强制终止
                        proc.kill()
                    else:
                        # 正常终止
                        proc.terminate()
                    
                    # 等待进程退出
                    proc.wait(timeout=timeout)
                    success = True
                    self.logger.info(f"成功使用psutil方法终止进程: {proc_name} (PID: {pid})")
                except psutil.NoSuchProcess:
                    # 进程已经退出
                    success = True
                    self.logger.info(f"进程已经退止: {proc_name} (PID: {pid})")
                except psutil.TimeoutExpired:
                    # 超时，进程可能仍在运行
                    self.logger.warning(f"终止进程超时: {proc_name} (PID: {pid})")
                except Exception as e:
                    self.logger.error(f"使用psutil终止进程 {proc_name} (PID: {pid}) 失败: {e}")
            
            # 方法2: 使用windows API终止进程
            if not success and sys.platform == "win32":
                try:
                    import win32api
                    import win32con
                    import win32process
                    
                    # 获取进程句柄
                    handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, 0, pid)
                    if handle:
                        # 终止进程
                        win32process.TerminateProcess(handle, 0)
                        win32api.CloseHandle(handle)
                        success = True
                        self.logger.info(f"成功使用Win32 API终止进程: {proc_name} (PID: {pid})")
                except Exception as e:
                    self.logger.error(f"使用Win32 API终止进程 {proc_name} (PID: {pid}) 失败: {e}")
            
            # 方法3: 使用操作系统命令终止进程
            if not success and force:
                try:
                    if sys.platform == "win32":
                        # Windows上使用taskkill命令强制终止
                        os.system(f"taskkill /F /PID {pid} /T")
                    else:
                        # Unix系统使用kill命令
                        os.system(f"kill -9 {pid}")
                    
                    # 检查进程是否还在运行
                    try:
                        proc = psutil.Process(pid)
                        # 等待短暂时间，确认进程确实被终止
                        time.sleep(0.5)
                        if not proc.is_running():
                            success = True
                            self.logger.info(f"成功使用OS命令终止进程: {proc_name} (PID: {pid})")
                    except psutil.NoSuchProcess:
                        success = True
                        self.logger.info(f"确认进程已终止: {proc_name} (PID: {pid})")
                except Exception as e:
                    self.logger.error(f"使用OS命令终止进程 {proc_name} (PID: {pid}) 失败: {e}")
            
            # 检查最终结果
            try:
                proc = psutil.Process(pid)
                # 如果还能获取到进程，则终止失败
                if proc.is_running():
                    self.logger.warning(f"所有方法终止进程 {proc_name} (PID: {pid}) 失败，进程仍在运行")
                    return False
                else:
                    success = True
            except psutil.NoSuchProcess:
                # 进程不存在了，说明终止成功
                success = True
            
            return success
            
        except Exception as e:
            self.logger.error(f"终止进程 PID: {pid} 时发生未预期错误: {e}")
            return False
    
    def lower_selected_process_privilege(self):
        """降低选中进程的权限"""
        try:
            # 检查是否有选中的行
            if not self.process_table.selectedItems():
                self.status_signal.emit("请先选择要降低权限的进程")
                return
            
            # 获取选中行
            row = self.process_table.currentRow()
            if row < 0:
                return
            
            # 获取进程PID
            pid_item = self.process_table.item(row, 0)
            if not pid_item or pid_item.text() == "N/A":
                self.status_signal.emit("无效的进程PID")
                return
            
            try:
                # 转换为整数
                pid = int(pid_item.text())
                
                # 询问用户是否强制终止
                reply = QMessageBox.question(
                    self, 
                    "确认操作",
                    "是否使用强制方式终止进程？\n(强制方式可能更有效，但可能导致进程数据丢失)",
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                    QMessageBox.Yes
                )
                
                if reply == QMessageBox.Cancel:
                    return
                
                force_terminate = (reply == QMessageBox.Yes)
                
                # 使用增强的终止方法
                if self.terminate_process(pid, force=force_terminate):
                    self.status_signal.emit(f"已成功终止进程 PID: {pid}")
                else:
                    self.status_signal.emit(f"终止进程 PID: {pid} 失败")
                
                # 刷新进程列表
                self.refresh_process_list()
                
            except Exception as e:
                self.logger.error(f"降低进程权限时出错: {e}")
                self.status_signal.emit(f"降低进程权限失败: {e}")
        
        except Exception as e:
            self.logger.error(f"降低选中进程权限时出错: {e}")
            self.status_signal.emit(f"降低选中进程权限操作失败: {e}")
    
    def lower_all_processes_privileges(self):
        """降低所有可疑进程的权限"""
        try:
            # 确认对话框
            reply = QMessageBox.question(
                self, 
                "确认操作", 
                "确定要终止所有可疑进程吗？\n这可能会影响系统稳定性。",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                return
            
            # 询问用户是否强制终止
            force_reply = QMessageBox.question(
                self, 
                "终止方式",
                "是否使用强制方式终止进程？\n(强制方式可能更有效，但可能导致进程数据丢失)",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            force_terminate = (force_reply == QMessageBox.Yes)
            
            success_count = 0
            total_count = 0
            
            # 使用IntegratedCountermeasure终止所有可疑进程
            if hasattr(self, 'countermeasure') and self.countermeasure:
                # 调用执行全面反制
                if hasattr(self.countermeasure, 'countermeasure_manager') and self.countermeasure.countermeasure_manager:
                    self.status_signal.emit("正在执行全面反制措施...")
                    result = self.countermeasure.countermeasure_manager.execute_full_countermeasure()
                    
                    if result:
                        self.status_signal.emit("全面反制措施执行成功")
                    else:
                        self.status_signal.emit("全面反制措施执行部分成功")
                    
                    # 刷新进程列表
                    self.refresh_process_list()
                    return
            
            # 如果无法通过countermeasure执行，尝试遍历进程表格
            rows = self.process_table.rowCount()
            
            # 创建进度对话框
            progress = QProgressBar(self)
            progress.setMinimum(0)
            progress.setMaximum(rows)
            progress.setValue(0)
            progress.setWindowTitle("正在终止进程")
            progress.setAlignment(Qt.AlignCenter)
            
            # 显示进度对话框
            progress_dialog = QDialog(self)
            progress_dialog.setWindowTitle("进程终止进度")
            progress_layout = QVBoxLayout(progress_dialog)
            progress_layout.addWidget(QLabel("正在终止所有可疑进程，请稍候..."))
            progress_layout.addWidget(progress)
            progress_dialog.setFixedSize(300, 100)
            progress_dialog.show()
            
            # 处理每个进程
            for row in range(rows):
                pid_item = self.process_table.item(row, 0)
                if pid_item and pid_item.text() != "N/A":
                    try:
                        pid = int(pid_item.text())
                        total_count += 1
                        
                        # 使用增强的终止方法终止进程
                        if self.terminate_process(pid, force=force_terminate):
                            success_count += 1
                    except:
                        pass
                
                # 更新进度
                progress.setValue(row + 1)
                QApplication.processEvents()  # 确保UI响应
            
            # 关闭进度对话框
            progress_dialog.close()
            
            self.status_signal.emit(f"成功终止 {success_count}/{total_count} 个可疑进程")
            
            # 刷新进程列表
            self.refresh_process_list()
            
        except Exception as e:
            self.logger.error(f"终止所有进程时出错: {e}")
            self.status_signal.emit(f"终止所有进程操作失败: {e}")
    
    def refresh_lowered_processes(self):
        """刷新已降权进程列表"""
        try:
            lowered_processes = self.random_process_analyzer.lowered_processes
            
            text = ""
            if lowered_processes:
                for pid in lowered_processes:
                    try:
                        proc = psutil.Process(pid)
                        text += f"PID: {pid}, 名称: {proc.name()}, 路径: {proc.exe() if hasattr(proc, 'exe') else '未知'}\n"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        text += f"PID: {pid}, 名称: 未知 (进程可能已结束)\n"
            else:
                text = "当前没有已降权的进程。"
            
            self.lowered_process_text.setText(text)
            
        except Exception as e:
            self.logger.error(f"刷新已降权进程列表时出错: {e}")
            self.lowered_process_text.setText(f"刷新列表时出错: {e}")
    
    def register_hotkeys(self):
        """注册全局快捷键，使用KeyboardHotKey类提供更可靠的热键管理"""
        try:
            # 确保热键管理器实例存在
            if not hasattr(self, 'hotkey_manager') or self.hotkey_manager is None:
                self.hotkey_manager = KeyboardHotKey()
                self.logger.info("已创建新的热键管理器")
            
            # 在注册新热键前先注销所有现有热键
            self.hotkey_manager.unregister_all()
            self.logger.info("已注销所有现有热键，准备重新注册")
            
            # 用于跟踪热键注册状态
            hotkeys_status = {
                "Win+F1": False,  # 紧急解锁
                "Win+F2": False,  # 启动/停止保护
                "Win+F3": False,  # 刷新保护
                "Win+F4": False,  # 显示/隐藏窗口
                "Win+F12": False  # 终极解锁
            }
            
            # 注册每个热键
            hotkey_id = self.hotkey_manager.register("win+f1", self.emergency_unlock, "紧急解锁")
            if hotkey_id:
                hotkeys_status["Win+F1"] = True
                self.logger.info("已注册Win+F1热键 (紧急解锁)")
            
            hotkey_id = self.hotkey_manager.register("win+f2", self.toggle_protection, "启动/停止保护")
            if hotkey_id:
                hotkeys_status["Win+F2"] = True
                self.logger.info("已注册Win+F2热键 (启动/停止保护)")
            
            hotkey_id = self.hotkey_manager.register("win+f3", self.refresh_protection, "刷新保护")
            if hotkey_id:
                hotkeys_status["Win+F3"] = True
                self.logger.info("已注册Win+F3热键 (刷新保护)")
            
            hotkey_id = self.hotkey_manager.register("win+f4", self.toggle_window_visibility, "显示/隐藏窗口")
            if hotkey_id:
                hotkeys_status["Win+F4"] = True
                self.logger.info("已注册Win+F4热键 (显示/隐藏窗口)")
            
            hotkey_id = self.hotkey_manager.register("win+f12", self.ultimate_unlock, "终极解锁")
            if hotkey_id:
                hotkeys_status["Win+F12"] = True
                self.logger.info("已注册Win+F12热键 (终极解锁)")
            
            # 更新UI显示热键状态
            self.update_hotkey_status_ui(hotkeys_status)
            
            # 在状态栏显示热键注册结果摘要
            registered_count = sum(1 for status in hotkeys_status.values() if status)
            total_count = len(hotkeys_status)
            self.status_signal.emit(f"热键注册: {registered_count}/{total_count} 个成功")
            
            return True
        except Exception as e:
            self.logger.error(f"注册全局热键时出错: {e}")
            self.status_signal.emit("热键注册失败，某些功能可能无法通过快捷键触发")
            return False
    
    def update_hotkey_status_ui(self, hotkeys_status):
        """更新热键状态UI显示"""
        try:
            # 如果是控制选项卡中显示热键状态
            if hasattr(self, 'hotkey_info_label'):
                hotkey_info = "<b>全局热键状态：</b><br>"
                
                for hotkey, status in hotkeys_status.items():
                    color = "green" if status else "red"
                    icon = "✓" if status else "✗"
                    hotkey_info += f'<span style="color:{color}">{hotkey}: {icon}</span><br>'
                
                if hasattr(self, 'hotkey_info_label'):
                    self.hotkey_info_label.setText(hotkey_info)
                    
                # 更新状态栏
                registered_count = sum(1 for status in hotkeys_status.values() if status)
                total_count = len(hotkeys_status)
                if registered_count < total_count:
                    self.status_signal.emit(f"警告: 部分热键注册失败 ({registered_count}/{total_count})")
            
        except Exception as e:
            self.logger.error(f"更新热键状态UI时出错: {e}")
    
    def toggle_protection(self):
        """切换保护状态"""
        if self.is_protection_active:
            self.stop_protection()
        else:
            self.start_protection()
    
    def refresh_protection(self):
        """刷新保护检查"""
        try:
            self.logger.info("手动触发保护状态检查...")
            self.check_protection_status()
            self.status_signal.emit("已手动刷新保护状态")
        except Exception as e:
            self.logger.error(f"手动刷新保护状态时出错: {e}")
    
    def toggle_window_visibility(self):
        """切换窗口可见性"""
        if self.isVisible():
            self.hide()
            self.status_signal.emit("窗口已隐藏")
        else:
            self.show()
            self.status_signal.emit("窗口已显示")
    
    def update_about_tab_with_hotkeys(self):
        """更新关于页面显示快捷键信息"""
        try:
            hotkey_html = """
            <p><b>全局快捷键：</b></p>
            <ul>
                <li><b>Win+F1</b>: 紧急解锁 - 在鼠标被限制或屏幕被锁定时使用</li>
                <li><b>Win+F2</b>: 启动/停止保护 - 快速切换保护状态</li>
                <li><b>Win+F3</b>: 刷新保护 - 立即检查并更新保护状态</li>
                <li><b>Win+F4</b>: 显示/隐藏窗口 - 快速切换窗口可见性</li>
            </ul>
            """
            
            # 获取现有内容
            current_html = self.about_tab.findChild(QTextEdit).toHtml()
            
            # 在</ol>标签后添加快捷键信息
            if "</ol>" in current_html:
                new_html = current_html.replace("</ol>", "</ol>" + hotkey_html)
                self.about_tab.findChild(QTextEdit).setHtml(new_html)
        except Exception as e:
            self.logger.error(f"更新快捷键信息时出错: {e}")
    
    def nativeEvent(self, eventType, message):
        """处理原生窗口事件"""
        # 该方法不再处理热键，由keyboard模块负责
        # 但我们保留它用于其他窗口消息处理
        try:
            # 使用pywin32解析窗口消息
            if sys.platform == 'win32':
                import win32gui
                msg = ctypes.wintypes.MSG.from_address(int(message))
                
                # 窗口激活消息
                if msg.message == win32con.WM_ACTIVATEAPP:
                    if msg.wParam:  # 窗口被激活
                        self.on_window_activated()
                        
            return False, 0
        except Exception as e:
            self.logger.error(f"处理窗口事件时出错: {e}")
            return False, 0

    # 添加事件过滤器以监控窗口激活
    def eventFilter(self, obj, event):
        """事件过滤器，用于监控窗口激活等事件"""
        try:
            # 使用QEvent枚举而不是Qt
            if event.type() == QEvent.WindowActivate:
                # 窗口被激活
                self.on_window_activated()
            
            return super().eventFilter(obj, event)
        except Exception as e:
            self.logger.error(f"处理事件过滤器时出错: {e}")
            return False

    def on_window_activated(self):
        """窗口被激活时的处理函数"""
        try:
            # 窗口激活时检查权限状态并更新
            self.update_privilege_status()
            
            # 添加检查以避免过于频繁的热键注册尝试
            current_time = time.time()
            if not hasattr(self, '_last_hotkey_check_time') or current_time - self._last_hotkey_check_time > 30:
                self._last_hotkey_check_time = current_time
                # 检查是否需要重新注册热键
                self.check_hotkeys()
            
            # 窗口置顶逻辑
            if self.isVisible():
                base_to_local = self.frameGeometry()
                current_frame = self.geometry()
                margin_size = base_to_local.height() - current_frame.height()
                base_to_local.moveTop(current_frame.top() - margin_size)
                self.move(base_to_local.topLeft())
                
        except Exception as e:
            self.logger.error(f"窗口激活处理时出错: {e}")
    
    def check_hotkeys(self):
        """检查热键注册状态，如果热键数量不足则尝试重新注册"""
        try:
            if hasattr(self, 'hotkey_manager') and self.hotkey_manager:
                # 获取已注册的热键数量
                registered_count = len(self.hotkey_manager.get_registered_hotkeys())
                total_expected = 5  # 期望注册的热键数量：Win+F1, Win+F2, Win+F3, Win+F4, Win+F12
                
                if registered_count < total_expected:  
                    self.logger.info(f"检测到已注册热键数量不足({registered_count}/{total_expected})，尝试重新注册...")
                    self.register_hotkeys()
                    
                    # 更新热键状态UI
                    hotkey_status = self.get_hotkey_status()
                    self.update_hotkey_status_ui(hotkey_status)
                
                return registered_count, total_expected
            return 0, 0
        except Exception as e:
            self.logger.error(f"检查热键时出错: {e}")
            return 0, 0

    def get_hotkey_status(self):
        """获取热键状态"""
        try:
            hotkeys_status = {
                "Win+F1": False,  # 紧急解锁
                "Win+F2": False,  # 启动/停止保护
                "Win+F3": False,  # 刷新保护
                "Win+F4": False,  # 显示/隐藏窗口
                "Win+F12": False  # 终极解锁
            }
            
            if hasattr(self, 'hotkey_manager'):
                registered_hotkeys = self.hotkey_manager.get_registered_hotkeys()
                for hotkey_str in registered_hotkeys:
                    if hotkey_str in hotkeys_status:
                        hotkeys_status[hotkey_str] = True
            
            return hotkeys_status
        except Exception as e:
            self.logger.error(f"获取热键状态时出错: {e}")
            return {}
    
    def ultimate_unlock(self):
        """终极解锁功能，结束除系统和自身以外的所有进程"""
        try:
            self.log_signal.emit("<span style='color:red'>正在执行终极解锁，请等待...</span>")
            self.update_status("正在执行终极解锁...")
            
            # 确定权限级别
            is_system = self.privilege_manager.is_running_as_system()
            is_admin = self.privilege_manager.is_running_as_admin()
            
            if not (is_system or is_admin):
                self.log_signal.emit("<span style='color:orange'>执行终极解锁需要管理员或System权限</span>")
                self.status_signal.emit("权限不足，无法执行终极解锁")
                # 自动提升权限
                self.elevate_privileges()
                return False
            
            # 在新线程中执行终止进程操作
            self.ultimate_thread = threading.Thread(target=self._execute_ultimate_unlock)
            self.ultimate_thread.daemon = True
            self.ultimate_thread.start()
            
            # 添加超时保护，防止程序卡死
            # 设置终极解锁超时标志
            self._ultimate_timeout = False
            
            # 创建一个监控计时器，检查终极解锁线程状态
            monitor_timer = QTimer(self)
            
            def check_thread_status():
                if not self.ultimate_thread.is_alive():
                    # 线程已完成
                    monitor_timer.stop()
                    self.log_signal.emit("<span style='color:green'>终极解锁操作完成</span>")
                elif hasattr(self, '_ultimate_timeout') and self._ultimate_timeout:
                    # 超时了
                    monitor_timer.stop()
                    self.log_signal.emit("<span style='color:orange'>终极解锁操作超时，已停止</span>")
                    self.status_signal.emit("终极解锁操作超时，已停止")
            
            # 每500毫秒检查一次
            monitor_timer.timeout.connect(check_thread_status)
            monitor_timer.start(500)
            
            # 创建超时计时器，20秒后自动终止操作
            timeout_timer = QTimer(self)
            timeout_timer.setSingleShot(True)
            timeout_timer.timeout.connect(lambda: setattr(self, '_ultimate_timeout', True))
            timeout_timer.start(20000)  # 20秒超时
            
            return True
            
        except Exception as e:
            self.log_signal.emit(f"<span style='color:red'>终极解锁时出错: {e}</span>")
            self.update_status(f"终极解锁失败: {e}")
            return False
    
    def _execute_ultimate_unlock(self):
        """在后台线程中执行终极解锁操作"""
        try:
            # 获取当前进程ID
            current_pid = os.getpid()
            
            # 获取所有进程
            all_processes = list(psutil.process_iter(['pid', 'name', 'username', 'exe']))
            
            # 创建线程池，每个线程终止一部分进程
            num_threads = min(20, len(all_processes) // 10 + 1)  # 最多20个线程
            thread_pool = []
            processes_per_thread = len(all_processes) // num_threads + 1
            
            # 将进程分组
            process_groups = [all_processes[i:i+processes_per_thread] 
                            for i in range(0, len(all_processes), processes_per_thread)]
            
            # 为每组进程创建一个线程
            for i, process_group in enumerate(process_groups):
                thread = threading.Thread(
                    target=self._terminate_processes_group,
                    args=(process_group, current_pid, i)
                )
                thread_pool.append(thread)
                thread.daemon = True
                thread.start()
            
            # 等待所有线程完成，但设置超时保护
            start_time = time.time()
            max_wait_time = 15  # 最多等待15秒
            
            for thread in thread_pool:
                # 计算剩余等待时间
                remaining_time = max_wait_time - (time.time() - start_time)
                if remaining_time <= 0:
                    # 超时了，不再等待其他线程
                    self.log_signal.emit("<span style='color:orange'>终止进程操作超时，跳过剩余进程...</span>")
                    break
                
                # 如果已经设置了超时标志，不再等待
                if hasattr(self, '_ultimate_timeout') and self._ultimate_timeout:
                    self.log_signal.emit("<span style='color:orange'>检测到终极解锁操作已超时，停止执行</span>")
                    return
                
                # 等待线程完成，但最多等待剩余时间
                thread.join(remaining_time)
                
            # 检查是否仍有未完成的线程
            running_threads = [t for t in thread_pool if t.is_alive()]
            if running_threads:
                self.log_signal.emit(f"<span style='color:orange'>有{len(running_threads)}个线程未完成，但将继续执行</span>")
            
            # 再次进行紧急解锁，但不要卡在这里
            self.log_signal.emit("<span style='color:green'>终止进程完成，执行紧急解锁...</span>")
            
            # 如果已经设置了超时标志，不再执行紧急解锁
            if hasattr(self, '_ultimate_timeout') and self._ultimate_timeout:
                self.log_signal.emit("<span style='color:orange'>检测到终极解锁操作已超时，跳过紧急解锁</span>")
                return
            
            # 使用带超时保护的紧急解锁方法
            try:
                # 创建一个事件标志来追踪完成状态
                emergency_completed = threading.Event()
                
                # 在另一个线程中执行紧急解锁
                def do_emergency_unlock():
                    try:
                        self._execute_emergency_unlock()
                        emergency_completed.set()
                    except Exception as e:
                        self.logger.error(f"终极解锁中的紧急解锁步骤出错: {e}")
                        emergency_completed.set()
                
                # 启动紧急解锁线程
                emergency_thread = threading.Thread(target=do_emergency_unlock)
                emergency_thread.daemon = True
                emergency_thread.start()
                
                # 最多等待5秒
                emergency_completed.wait(5)
                
                if not emergency_completed.is_set():
                    self.log_signal.emit("<span style='color:orange'>紧急解锁操作超时，已中断</span>")
            except Exception as e:
                self.logger.error(f"启动紧急解锁线程时出错: {e}")
            
            self.log_signal.emit("<span style='color:green'>终极解锁完成！</span>")
            self.status_signal.emit("终极解锁完成")
            
        except Exception as e:
            self.log_signal.emit(f"<span style='color:red'>执行终极解锁时出错: {e}</span>")
    
    def _terminate_processes_group(self, processes, current_pid, thread_id):
        """终止一组进程"""
        try:
            terminated_count = 0
            skipped_count = 0
            
            for proc in processes:
                try:
                    # 跳过当前进程
                    if proc.info['pid'] == current_pid:
                        continue
                        
                    # 跳过关键系统进程
                    if self._is_system_critical_process(proc):
                        skipped_count += 1
                        continue
                    
                    # 尝试终止进程
                    proc.terminate()
                    terminated_count += 1
                    
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    # 跳过无法终止的进程
                    skipped_count += 1
                except Exception:
                    # 忽略其他错误，继续处理下一个进程
                    pass
            
            self.log_signal.emit(f"线程 {thread_id}: 终止了 {terminated_count} 个进程，跳过 {skipped_count} 个进程")
            
        except Exception as e:
            self.log_signal.emit(f"<span style='color:red'>线程 {thread_id} 终止进程时出错: {e}</span>")
    
    def _is_system_critical_process(self, proc):
        """检查是否是系统关键进程
        
        Args:
            proc: psutil.Process 对象
        
        Returns:
            如果是系统关键进程返回True，否则返回False
        """
        try:
            # 系统关键进程的名称列表
            critical_processes = [
                "system", "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", 
                "winlogon.exe", "services.exe", "wininit.exe", "explorer.exe",
                "ntoskrnl.exe", "System", "Registry", "Memory Compression"
            ]
            
            # 获取进程名称
            try:
                name = proc.name().lower()
            except:
                # 如果无法获取名称，假设为非关键进程
                return False
            
            # 检查名称是否在关键进程列表中
            for critical in critical_processes:
                if critical.lower() == name:
                    return True
                    
            # 检查是否为系统进程 (PID <= 4)
            if proc.pid <= 4:
                return True
                
            # 检查进程是否为Windows服务主机进程，并且是否有系统服务
            if name == "svchost.exe":
                try:
                    # 检查用户
                    username = proc.username()
                    if username and ("SYSTEM" in username.upper() or "LOCAL SERVICE" in username.upper() or "NETWORK SERVICE" in username.upper()):
                        return True
                except:
                    pass
                    
            # 检查进程是否为Microsoft签名进程（可选，但需要额外的库）
            try:
                if sys.platform == "win32" and self._is_microsoft_signed(proc.exe()):
                    # 这里为了安全，我们不将所有Microsoft签名的进程视为关键
                    # 而是只排除一些明显是系统组件的进程
                    if "\\Windows\\" in proc.exe() or "\\Microsoft\\" in proc.exe():
                        # 系统目录下的微软签名进程，可能是关键进程
                        return True
            except:
                pass
                
            # 不是关键进程
            return False
        except Exception as e:
            # 出错时保守处理，认为不是关键进程
            self.logger.error(f"检查关键进程时出错: {e}")
            return False
        
    def _is_microsoft_signed(self, exe_path):
        """检查可执行文件是否为Microsoft签名
        
        Args:
            exe_path: 可执行文件路径
        
        Returns:
            如果是Microsoft签名返回True，否则返回False
        """
        try:
            # 基本检查，不使用额外库
            if "\\Windows\\" in exe_path or "\\Microsoft\\" in exe_path:
                # 简单的路径检查
                return True
                
            # 进阶检查需要使用额外库，如win32security或wintrust
            # 这里使用简单的检查方法
            return False
        except Exception as e:
            self.logger.error(f"检查Microsoft签名时出错: {e}")
            return False

    def refresh_process_list(self):
        """刷新进程列表，使用main.py的逻辑"""
        try:
            # 清空现有项
            if hasattr(self, 'process_table') and self.process_table:
                self.process_table.setRowCount(0)
            else:
                self.logger.warning("无法刷新进程表: 进程表未初始化")
                return
            
            # 确保countermeasure存在
            if not hasattr(self, 'countermeasure') or self.countermeasure is None:
                # 显示错误信息
                self.process_table.setRowCount(1)
                self.process_table.setItem(0, 0, QTableWidgetItem("N/A"))
                self.process_table.setItem(0, 1, QTableWidgetItem("反制度量对象未初始化"))
                self.process_table.setItem(0, 2, QTableWidgetItem("N/A"))
                self.process_table.setItem(0, 3, QTableWidgetItem("未初始化"))
                self.process_table.setItem(0, 4, QTableWidgetItem("N/A"))
                # 设置行背景色为红色
                for col in range(5):
                    item = self.process_table.item(0, col)
                    if item:
                        item.setBackground(QColor(255, 200, 200))
                return
            
            # 获取当前状态，并强制扫描进程以获取最新数据
            try:
                # 先触发一次进程扫描以确保数据最新
                if hasattr(self.countermeasure, 'countermeasure_manager'):
                    # 触发一次进程扫描
                    self.countermeasure.countermeasure_manager.scan_target_processes()
                    self.status_signal.emit("已刷新进程数据")
                
                # 获取状态
                status = self.countermeasure.get_status()
                found_targets = status.get('found_targets', [])
                
                # 如果没有找到目标，显示提示信息
                if not found_targets:
                    self.process_table.setRowCount(1)
                    self.process_table.setItem(0, 0, QTableWidgetItem("N/A"))
                    self.process_table.setItem(0, 1, QTableWidgetItem("未发现可疑进程"))
                    self.process_table.setItem(0, 2, QTableWidgetItem("N/A"))
                    self.process_table.setItem(0, 3, QTableWidgetItem("正常"))
                    self.process_table.setItem(0, 4, QTableWidgetItem("N/A"))
                    # 设置行背景色为绿色
                    for col in range(5):
                        item = self.process_table.item(0, col)
                        if item:
                            item.setBackground(QColor(200, 255, 200))
                    return
                
                # 添加进程项
                self.process_table.setRowCount(len(found_targets))
                for row, target in enumerate(found_targets):
                    pid = str(target.get('pid', ''))
                    name = target.get('name', '')
                    type_name = target.get('type', '')
                    status_text = target.get('status', '')
                    path = target.get('path', '')
                    
                    self.process_table.setItem(row, 0, QTableWidgetItem(pid))
                    self.process_table.setItem(row, 1, QTableWidgetItem(name))
                    self.process_table.setItem(row, 2, QTableWidgetItem(type_name))
                    self.process_table.setItem(row, 3, QTableWidgetItem(status_text))
                    self.process_table.setItem(row, 4, QTableWidgetItem(path))
                    
                    # 为不同类型设置不同颜色
                    row_color = None
                    if type_name == 'known_target':
                        row_color = QColor(255, 200, 200)  # 红色
                    elif type_name == 'random_name':
                        row_color = QColor(255, 255, 200)  # 黄色
                    elif type_name == 'self_replication':
                        row_color = QColor(200, 255, 200)  # 绿色
                    
                    if row_color:
                        for col in range(5):
                            item = self.process_table.item(row, col)
                            if item:
                                item.setBackground(row_color)
            
                # 自动调整列宽
                self.process_table.resizeColumnsToContents()
                
            except Exception as inner_e:
                self.logger.error(f"获取进程数据时出错: {inner_e}")
                self.process_table.setRowCount(1)
                self.process_table.setItem(0, 0, QTableWidgetItem("N/A"))
                self.process_table.setItem(0, 1, QTableWidgetItem(f"获取进程数据失败: {inner_e}"))
                self.process_table.setItem(0, 2, QTableWidgetItem("N/A"))
                self.process_table.setItem(0, 3, QTableWidgetItem("错误"))
                self.process_table.setItem(0, 4, QTableWidgetItem("N/A"))
                # 设置行背景色为红色
                for col in range(5):
                    item = self.process_table.item(0, col)
                    if item:
                        item.setBackground(QColor(255, 200, 200))
        
        except Exception as e:
            self.logger.error(f"刷新进程列表时出错: {e}")
            try:
                # 显示错误信息
                self.process_table.setRowCount(1)
                self.process_table.setItem(0, 0, QTableWidgetItem("N/A"))
                self.process_table.setItem(0, 1, QTableWidgetItem(f"刷新进程列表错误: {e}"))
                self.process_table.setItem(0, 2, QTableWidgetItem("N/A"))
                self.process_table.setItem(0, 3, QTableWidgetItem("错误"))
                self.process_table.setItem(0, 4, QTableWidgetItem("N/A"))
                # 设置行背景色为红色
                for col in range(5):
                    item = self.process_table.item(0, col)
                    if item:
                        item.setBackground(QColor(255, 200, 200))
            except:
                pass
    
    def refresh_window_list(self):
        """刷新窗口列表，使用main.py的逻辑"""
        try:
            # 清空现有项
            if hasattr(self, 'window_table') and self.window_table:
                self.window_table.setRowCount(0)
            else:
                self.logger.warning("无法刷新窗口表: 窗口表未初始化")
                return
            
            # 检查countermeasure和window_freedom是否有效
            if not hasattr(self, 'countermeasure') or self.countermeasure is None:
                # 显示错误信息
                self.window_table.setRowCount(1)
                self.window_table.setItem(0, 0, QTableWidgetItem("N/A"))
                self.window_table.setItem(0, 1, QTableWidgetItem("反制度量对象未初始化"))
                self.window_table.setItem(0, 2, QTableWidgetItem("N/A"))
                self.window_table.setItem(0, 3, QTableWidgetItem("N/A"))
                self.window_table.setItem(0, 4, QTableWidgetItem("错误"))
                # 设置行背景色为红色
                for col in range(5):
                    item = self.window_table.item(0, col)
                    if item:
                        item.setBackground(QColor(255, 200, 200))
                self.logger.warning("刷新窗口列表：反制度量对象未初始化")
                return
            
            # 检查window_freedom是否有效
            if not hasattr(self.countermeasure, 'window_freedom') or self.countermeasure.window_freedom is None:
                try:
                    self.logger.info("刷新窗口列表：初始化窗口自由模块...")
                    from src.window_freedom import WindowFreedom
                    self.countermeasure.window_freedom = WindowFreedom()
                except Exception as e:
                    self.logger.error(f"初始化窗口自由模块失败: {e}")
                    # 显示错误信息
                    self.window_table.setRowCount(1)
                    self.window_table.setItem(0, 0, QTableWidgetItem("N/A"))
                    self.window_table.setItem(0, 1, QTableWidgetItem(f"无法初始化窗口自由模块: {e}"))
                    self.window_table.setItem(0, 2, QTableWidgetItem("N/A"))
                    self.window_table.setItem(0, 3, QTableWidgetItem("N/A"))
                    self.window_table.setItem(0, 4, QTableWidgetItem("错误"))
                    # 设置行背景色为红色
                    for col in range(5):
                        item = self.window_table.item(0, col)
                        if item:
                            item.setBackground(QColor(255, 200, 200))
                    return
            
            try:
                # 获取所有窗口（强制刷新）
                windows = self.countermeasure.window_freedom.find_lock_windows(force_refresh=True)
                
                # 如果没有找到窗口，显示提示信息
                if not windows:
                    self.window_table.setRowCount(1)
                    self.window_table.setItem(0, 0, QTableWidgetItem("N/A"))
                    self.window_table.setItem(0, 1, QTableWidgetItem("未发现可疑窗口"))
                    self.window_table.setItem(0, 2, QTableWidgetItem("N/A"))
                    self.window_table.setItem(0, 3, QTableWidgetItem("N/A"))
                    self.window_table.setItem(0, 4, QTableWidgetItem("正常"))
                    # 设置行背景色为绿色
                    for col in range(5):
                        item = self.window_table.item(0, col)
                        if item:
                            item.setBackground(QColor(200, 255, 200))
                    return
                
                # 添加窗口项到表格中
                self.window_table.setRowCount(len(windows))
                for row, window in enumerate(windows):
                    hwnd = str(window.get('hwnd', ''))
                    title = window.get('title', '')
                    class_name = window.get('class', '')
                    pid = str(window.get('pid', ''))
                    status = window.get('status', '') + (f" ({window.get('reason', '')})" if 'reason' in window else '')
                    
                    self.window_table.setItem(row, 0, QTableWidgetItem(hwnd))
                    self.window_table.setItem(row, 1, QTableWidgetItem(title))
                    self.window_table.setItem(row, 2, QTableWidgetItem(class_name))
                    self.window_table.setItem(row, 3, QTableWidgetItem(pid))
                    self.window_table.setItem(row, 4, QTableWidgetItem(status))
                    
                    # 为不同状态设置不同颜色
                    row_color = None
                    if window.get('status') == 'lock':
                        row_color = QColor(255, 180, 180)  # 红色
                    elif window.get('status') == 'topmost':
                        row_color = QColor(255, 255, 180)  # 黄色
                    elif window.get('status') == 'fullscreen':
                        row_color = QColor(255, 220, 180)  # 橙色
                    
                    if row_color:
                        for col in range(5):
                            item = self.window_table.item(row, col)
                            if item:
                                item.setBackground(row_color)
            
                # 自动调整列宽
                self.window_table.resizeColumnsToContents()
                
                # 更新状态栏
                self.status_signal.emit(f"刷新了 {len(windows)} 个窗口")
                
            except Exception as inner_e:
                self.logger.error(f"获取窗口数据时出错: {inner_e}")
                self.window_table.setRowCount(1)
                self.window_table.setItem(0, 0, QTableWidgetItem("N/A"))
                self.window_table.setItem(0, 1, QTableWidgetItem(f"获取窗口数据失败: {inner_e}"))
                self.window_table.setItem(0, 2, QTableWidgetItem("N/A"))
                self.window_table.setItem(0, 3, QTableWidgetItem("N/A"))
                self.window_table.setItem(0, 4, QTableWidgetItem("错误"))
                # 设置行背景色为红色
                for col in range(5):
                    item = self.window_table.item(0, col)
                    if item:
                        item.setBackground(QColor(255, 200, 200))
        
        except Exception as e:
            self.logger.error(f"刷新窗口列表时出错: {e}")
            try:
                # 显示错误信息
                self.window_table.setRowCount(1)
                self.window_table.setItem(0, 0, QTableWidgetItem("N/A"))
                self.window_table.setItem(0, 1, QTableWidgetItem(f"刷新窗口列表错误: {e}"))
                self.window_table.setItem(0, 2, QTableWidgetItem("N/A"))
                self.window_table.setItem(0, 3, QTableWidgetItem("N/A"))
                self.window_table.setItem(0, 4, QTableWidgetItem("错误"))
                # 设置行背景色为红色
                for col in range(5):
                    item = self.window_table.item(0, col)
                    if item:
                        item.setBackground(QColor(255, 200, 200))
            except:
                pass
    
    def update_status(self, message):
        """更新状态显示，防止重复消息"""
        try:
            # 防止重复消息
            if hasattr(self, '_last_status_message') and self._last_status_message == message:
                return
            
            # 保存最后一条消息
            self._last_status_message = message
            
            # 显示在状态栏
            if hasattr(self, 'statusBar'):
                self.statusBar.showMessage(message)
            
            # 记录到日志
            self.logger.info(f"状态变化: {message}")
            
            # 显示在日志文本框
            if hasattr(self, 'log_text') and self.log_text:
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_line = f"{now} - 状态: {message}"
                
                # 获取当前文本并检查是否包含该消息
                current_text = self.log_text.toPlainText()
                if log_line not in current_text.split('\n')[-5:]:  # 只检查最近的5行
                    self.log_text.append(log_line)
                    cursor = self.log_text.textCursor()
                    cursor.movePosition(QTextCursor.End)
                    self.log_text.setTextCursor(cursor)
        except Exception as e:
            print(f"更新状态显示时出错: {e}")
    
    def update_log(self, message):
        """更新日志文本，防止重复日志"""
        try:
            # 检查最近的日志，避免重复添加
            if hasattr(self, 'log_text') and self.log_text:
                current_text = self.log_text.toPlainText()
                # 仅检查消息的主体部分，忽略时间戳
                msg_core = message.split(' - ')[-1] if ' - ' in message else message
                
                # 检查最近添加的几行是否已包含此消息
                recent_lines = current_text.split('\n')[-10:]  # 检查最近10行
                for line in recent_lines:
                    if msg_core in line:
                        return  # 如果找到相同消息，不再添加
                
                # 添加到日志
                self.log_text.append(message)
                cursor = self.log_text.textCursor()
                cursor.movePosition(QTextCursor.End)
                self.log_text.setTextCursor(cursor)
        except Exception as e:
            print(f"更新日志文本时出错: {e}")
    
    def setup_protection_timer(self):
        """设置保护定时器，根据用户选择的频率进行检查"""
        try:
            # 获取选定的检查频率
            if hasattr(self, 'check_frequency_combo') and self.check_frequency_combo:
                try:
                    interval = int(self.check_frequency_combo.currentText().split()[0])
                except (ValueError, IndexError):
                    interval = 30  # 默认30秒
            else:
                interval = 30  # 默认30秒
            
            # 设置定时器间隔
            interval_ms = interval * 1000  # 转换为毫秒
            
            # 启动或重新启动定时器
            if hasattr(self, 'protection_timer'):
                if self.protection_timer.isActive():
                    self.protection_timer.stop()
                self.protection_timer.setInterval(interval_ms)
                self.protection_timer.start()
                
                # 启动广播窗口检测定时器
                self.start_broadcast_window_check()
                
                self.status_signal.emit(f"保护定时器已设置为 {interval} 秒")
            else:
                self.logger.error("保护定时器未初始化")
                self.status_signal.emit("无法设置保护定时器")
        
        except Exception as e:
            self.logger.error(f"设置保护定时器时出错: {e}")
            self.status_signal.emit(f"设置保护定时器失败: {e}")

    def start_broadcast_window_check(self):
        """启动广播窗口检测定时器"""
        try:
            if not hasattr(self, 'broadcast_window_timer'):
                self.broadcast_window_timer = QTimer(self)
                self.broadcast_window_timer.timeout.connect(self.check_broadcast_windows)
            
            if not self.broadcast_window_timer.isActive():
                self.broadcast_window_timer.start(3000)  # 每3秒检查一次
                self.logger.info("广播窗口检测定时器已启动")
        except Exception as e:
            self.logger.error(f"启动广播窗口检测定时器时出错: {e}")

    def check_broadcast_windows(self):
        """检查并处理含有'广播'关键词的窗口"""
        try:
            import win32gui
            import win32con
            import win32process
            import ctypes
            
            def enum_child_windows_proc(hwnd_child, broadcast_windows):
                """枚举子窗口查找全屏切换按钮"""
                try:
                    # 获取菜单句柄
                    hmenu = win32gui.GetMenu(hwnd_child)
                    # 检查是否为全屏切换按钮（菜单值为1004）
                    if ctypes.c_long(hmenu).value == 1004:
                        self.logger.info(f"找到全屏切换按钮: {hwnd_child}")
                        # 如果按钮被禁用，则启用
                        if not win32gui.IsWindowEnabled(hwnd_child):
                            win32gui.EnableWindow(hwnd_child, True)
                            self.logger.info("已启用全屏切换按钮")
                        else:
                            # 按钮已启用，模拟按下按钮切换全屏状态
                            win32gui.SendMessage(hwnd_child, win32con.BM_CLICK, 0, 0)
                            self.logger.info("已点击全屏切换按钮")
                        
                        # 找到按钮后停止枚举
                        return False
                except Exception as e:
                    self.logger.error(f"枚举子窗口查找全屏按钮时出错: {e}")
                
                # 继续枚举
                return True
                
            def enum_windows_callback(hwnd, broadcast_windows):
                """枚举窗口回调函数"""
                try:
                    # 检查窗口是否可见
                    if not win32gui.IsWindowVisible(hwnd):
                        return True
                    
                    # 获取窗口标题
                    title = win32gui.GetWindowText(hwnd)
                    
                    # 检查是否含有"广播"关键词或"屏幕共享"关键词
                    if "广播" in title or "屏幕共享" in title or "屏幕广播" in title:
                        # 获取窗口类名
                        class_name = win32gui.GetClassName(hwnd)
                        
                        # 获取窗口进程ID
                        _, pid = win32process.GetWindowThreadProcessId(hwnd)
                        
                        # 检查是否已经处理过该窗口
                        if not hasattr(self, '_processed_broadcast_windows'):
                            self._processed_broadcast_windows = set()
                        
                        # 如果已经处理过该窗口，则跳过
                        if hwnd in self._processed_broadcast_windows:
                            return True
                        
                        self.logger.info(f"发现广播/屏幕共享窗口: hwnd={hwnd}, 标题='{title}', 类名='{class_name}', pid={pid}")
                        
                        # 将窗口添加到已处理列表
                        self._processed_broadcast_windows.add(hwnd)
                        
                        # 解除鼠标限制和卸载钩子
                        self._handle_broadcast_restrictions(hwnd, pid)
                        
                        # 查找并操作全屏切换按钮 - 新方法
                        self.logger.info("尝试查找全屏切换按钮...")
                        button_found = False
                        try:
                            # 枚举子窗口查找全屏切换按钮
                            win32gui.EnumChildWindows(hwnd, enum_child_windows_proc, None)
                            button_found = True
                        except Exception as e:
                            self.logger.error(f"枚举子窗口查找全屏按钮时出错: {e}")
                        
                        # 如果找不到全屏切换按钮，则使用原有的最小化方法作为备选
                        if not button_found:
                            self.logger.warning("未找到全屏切换按钮，使用最小化方法处理广播窗口")
                            # 最小化窗口
                            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
                        
                        # 移除置顶状态
                        style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
                        if style & win32con.WS_EX_TOPMOST:
                            win32gui.SetWindowPos(
                                hwnd, 
                                win32con.HWND_NOTOPMOST,
                                0, 0, 0, 0,
                                win32con.SWP_NOMOVE | win32con.SWP_NOSIZE
                            )
                        
                        # 添加到广播窗口列表
                        broadcast_windows.append({
                            'hwnd': hwnd,
                            'title': title,
                            'class_name': class_name,
                            'pid': pid
                        })
                        
                except Exception as e:
                    self.logger.error(f"枚举广播窗口时出错: {e}")
                
                return True
            
            # 枚举所有窗口
            broadcast_windows = []
            win32gui.EnumWindows(enum_windows_callback, broadcast_windows)
            
            # 如果发现广播窗口，弹出选择对话框并设置自动结束计时器
            for window in broadcast_windows:
                self.show_broadcast_window_dialog(window)
                # 创建自动结束计时器
                if not hasattr(self, '_auto_terminate_timers'):
                    self._auto_terminate_timers = {}
                
                # 如果已经有这个进程的计时器，先清除
                pid = window['pid']
                if pid in self._auto_terminate_timers and self._auto_terminate_timers[pid]['timer'].isActive():
                    self._auto_terminate_timers[pid]['timer'].stop()
                
                # 创建新的计时器和计数器
                timer = QTimer()
                self._auto_terminate_timers[pid] = {
                    'timer': timer, 
                    'count': 0,
                    'window': window
                }
                
                # 设置计时器回调
                timer.timeout.connect(lambda p=pid: self._auto_terminate_broadcast(p))
                
                # 启动计时器 - 5秒后触发（减少等待时间）
                timer.start(5000)
                self.logger.info(f"已设置PID {pid}的自动结束计时器，将在5秒后触发")
            
        except Exception as e:
            self.logger.error(f"检查广播窗口时出错: {e}")
            
    def _handle_broadcast_restrictions(self, hwnd, pid):
        """处理广播窗口的限制，解除鼠标限制并卸载钩子"""
        try:
            results = []
            self.logger.info(f"处理广播窗口限制: hwnd={hwnd}, pid={pid}")
            
            # 1. 解除鼠标限制
            if hasattr(self, 'countermeasure') and self.countermeasure and hasattr(self.countermeasure, 'window_freedom'):
                # 先解除鼠标限制
                self.countermeasure.window_freedom.force_free_cursor()
                results.append("已解除鼠标限制")
                
                # 卸载广播进程的键盘鼠标钩子
                if self.countermeasure.window_freedom.unhook_process_hooks(pid):
                    results.append(f"已卸载PID {pid}的钩子")
                
                # 卸载所有键盘鼠标钩子
                if self.countermeasure.window_freedom.unhook_keyboard_mouse():
                    results.append("已卸载所有钩子")
            
            # 2. 卸载钩子检查广播进程及其相关进程的钩子
            try:
                # 检查广播进程的相关进程钩子
                import psutil
                try:
                    # 主进程
                    process = psutil.Process(pid)
                    self.logger.info(f"广播主进程: {pid} ({process.name()})")
                    
                    # 查找父进程
                    try:
                        parent = process.parent()
                        if parent and parent.pid > 4:  # 忽略系统进程
                            parent_pid = parent.pid
                            self.logger.info(f"广播父进程: {parent_pid} ({parent.name()})")
                            
                            # 卸载父进程钩子
                            if hasattr(self, 'countermeasure') and self.countermeasure and \
                               hasattr(self.countermeasure, 'window_freedom'):
                                if self.countermeasure.window_freedom.unhook_process_hooks(parent_pid):
                                    results.append(f"已卸载父进程 {parent_pid} 的钩子")
                    except:
                        pass
                    
                    # 查找子进程
                    try:
                        children = process.children(recursive=True)
                        for child in children:
                            child_pid = child.pid
                            self.logger.info(f"广播子进程: {child_pid} ({child.name()})")
                            
                            # 卸载子进程钩子
                            if hasattr(self, 'countermeasure') and self.countermeasure and \
                               hasattr(self.countermeasure, 'window_freedom'):
                                if self.countermeasure.window_freedom.unhook_process_hooks(child_pid):
                                    results.append(f"已卸载子进程 {child_pid} 的钩子")
                    except:
                        pass
                        
                except psutil.NoSuchProcess:
                    pass
            except Exception as e:
                self.logger.error(f"卸载广播相关进程钩子时出错: {e}")
            
            # 3. 尝试找到并终止进程关联的其他进程
            try:
                import psutil
                try:
                    process = psutil.Process(pid)
                    
                    # 尝试终止子进程
                    children = []
                    try:
                        children = process.children(recursive=True)
                        for child in children:
                            try:
                                self.logger.info(f"尝试终止子进程: {child.pid}")
                                child.terminate()
                            except:
                                pass
                        results.append(f"已尝试终止 {len(children)} 个子进程")
                    except:
                        pass
                    
                    # 尝试找到父进程并处理
                    try:
                        parent = process.parent()
                        if parent and parent.pid > 4:  # 忽略系统进程
                            self.logger.info(f"发现广播进程的父进程: {parent.pid}，名称: {parent.name()}")
                            if any(keyword in parent.name().lower() for keyword in ['broadcast', 'cast', 'share', '广播', '共享']):
                                self.logger.info(f"尝试终止父进程: {parent.pid}")
                                parent.terminate()
                                results.append(f"已终止广播父进程: {parent.pid}")
                    except:
                        pass
                        
                except psutil.NoSuchProcess:
                    pass
            except Exception as e:
                self.logger.error(f"处理广播相关进程时出错: {e}")
            
            self.logger.info(f"广播限制处理结果: {', '.join(results)}")
            self.status_signal.emit(f"已处理广播窗口限制: {', '.join(results)}")
            
        except Exception as e:
            self.logger.error(f"处理广播窗口限制时出错: {e}")
            
    def _auto_terminate_broadcast(self, pid):
        """自动结束广播进程的计时器回调"""
        try:
            if not hasattr(self, '_auto_terminate_timers') or pid not in self._auto_terminate_timers:
                return
            
            timer_info = self._auto_terminate_timers[pid]
            
            # 增加计数
            timer_info['count'] += 1
            window = timer_info['window']
            
            self.logger.info(f"自动结束计时器触发: PID={pid}, 计数={timer_info['count']}/3")
            
            # 再次解除鼠标限制和卸载钩子
            self._handle_broadcast_restrictions(window['hwnd'], pid)
            
            # 结束进程
            self.terminate_broadcast_process(pid)
            self.status_signal.emit(f"已自动结束广播进程 (PID: {pid}, 窗口: {window['title']})")
            
            # 如果已经尝试了三次，停止计时器
            if timer_info['count'] >= 3:
                timer_info['timer'].stop()
                self.logger.info(f"已停止PID {pid}的自动结束计时器")
            else:
                # 将间隔改为5秒
                timer_info['timer'].setInterval(5000)
                self.logger.info(f"PID {pid}的自动结束计时器将在5秒后再次触发")
                
        except Exception as e:
            self.logger.error(f"自动结束广播进程时出错: {e}")
            
    def show_broadcast_window_dialog(self, window):
        """显示广播窗口处理对话框"""
        try:
            # 创建对话框
            dialog = QMessageBox(self)
            dialog.setWindowTitle("发现广播窗口")
            dialog.setIcon(QMessageBox.Warning)
            dialog.setText(f"<b>发现广播窗口:</b>")
            dialog.setInformativeText(f"标题: {window['title']}\n类名: {window['class_name']}\n进程ID: {window['pid']}\n注意: 如5秒内不选择，将自动结束进程")
            
            # 添加按钮
            terminate_button = dialog.addButton("结束进程", QMessageBox.ActionRole)
            ignore_button = dialog.addButton("忽略", QMessageBox.RejectRole)
            
            # 设置窗口为置顶并启动置顶保持定时器
            dialog.setWindowFlags(dialog.windowFlags() | Qt.WindowStaysOnTopHint)
            
            # 创建置顶保持定时器
            topmost_timer = QTimer(dialog)
            
            def keep_topmost():
                """保持对话框置顶"""
                try:
                    if dialog.isVisible():
                        hwnd = int(dialog.winId())
                        import win32gui
                        import win32con
                        # 重新设置置顶状态
                        win32gui.SetWindowPos(
                            hwnd,
                            win32con.HWND_TOPMOST,
                            0, 0, 0, 0,
                            win32con.SWP_NOMOVE | win32con.SWP_NOSIZE
                        )
                except:
                    pass
            
            # 启动定时器，每500毫秒确保一次置顶
            topmost_timer.timeout.connect(keep_topmost)
            topmost_timer.start(500)
            
            # 显示对话框
            dialog.exec_()
            
            # 停止定时器
            topmost_timer.stop()
            
            # 处理按钮点击
            if dialog.clickedButton() == terminate_button:
                self.terminate_broadcast_process(window['pid'])
                # 如果用户手动选择了结束进程，取消自动结束计时器
                if hasattr(self, '_auto_terminate_timers') and window['pid'] in self._auto_terminate_timers:
                    self._auto_terminate_timers[window['pid']]['timer'].stop()
            elif dialog.clickedButton() == ignore_button:
                # 如果用户选择了忽略，取消自动结束计时器
                if hasattr(self, '_auto_terminate_timers') and window['pid'] in self._auto_terminate_timers:
                    self._auto_terminate_timers[window['pid']]['timer'].stop()
                    self.logger.info(f"用户选择忽略，已取消PID {window['pid']}的自动结束计时器")
            
        except Exception as e:
            self.logger.error(f"显示广播窗口对话框时出错: {e}")
            
    def terminate_broadcast_process(self, pid):
        """终止广播窗口相关进程"""
        try:
            # 再次解除鼠标限制和卸载钩子
            if hasattr(self, 'countermeasure') and self.countermeasure and hasattr(self.countermeasure, 'window_freedom'):
                # 先解除鼠标限制
                self.countermeasure.window_freedom.force_free_cursor()
                # 卸载当前进程钩子
                self.countermeasure.window_freedom.unhook_process_hooks(pid)
                # 卸载所有钩子
                self.countermeasure.window_freedom.unhook_keyboard_mouse()
                
            # 首先尝试通过countermeasure终止进程
            if hasattr(self, 'countermeasure') and self.countermeasure:
                try:
                    if hasattr(self.countermeasure, 'terminate_suspicious_process'):
                        result = self.countermeasure.terminate_suspicious_process(pid)
                        if result:
                            self.logger.info(f"已终止广播进程 (PID: {pid})")
                            self.status_signal.emit(f"已终止广播进程 (PID: {pid})")
                            return True
                except Exception as e:
                    self.logger.error(f"使用countermeasure终止广播进程时出错: {e}")
            
            # 其次，直接尝试杀死进程
            try:
                import psutil
                import win32api
                import win32process
                import win32con
                
                process = psutil.Process(pid)
                
                # 尝试终止进程
                try:
                    # 卸载进程使用的钩子
                    if hasattr(self, 'countermeasure') and self.countermeasure and hasattr(self.countermeasure, 'window_freedom'):
                        # 查找该进程的所有子进程
                        try:
                            children = process.children(recursive=True)
                            for child in children:
                                # 卸载子进程钩子
                                self.countermeasure.window_freedom.unhook_process_hooks(child.pid)
                                self.logger.info(f"已卸载子进程 {child.pid} 的钩子")
                        except:
                            pass
                        
                        # 检查父进程
                        try:
                            parent = process.parent()
                            if parent and parent.pid > 4:  # 排除系统进程
                                # 卸载父进程钩子
                                self.countermeasure.window_freedom.unhook_process_hooks(parent.pid)
                                self.logger.info(f"已卸载父进程 {parent.pid} 的钩子")
                        except:
                            pass
                    
                    # 首先尝试正常终止
                    process.terminate()
                    process.wait(1)  # 等待最多1秒
                    self.logger.info(f"已终止广播进程 (PID: {pid})")
                except Exception as e:
                    self.logger.warning(f"正常终止进程失败，尝试强制终止: {e}")
                    
                    # 再尝试强制终止 - 使用WinAPI
                    try:
                        handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
                        win32api.TerminateProcess(handle, 1)
                        win32api.CloseHandle(handle)
                        self.logger.info(f"已强制终止广播进程 (PID: {pid})")
                    except Exception as force_error:
                        # 最后使用psutil强制杀死
                        try:
                            process.kill()
                            self.logger.info(f"通过psutil强制终止广播进程 (PID: {pid})")
                        except Exception as kill_error:
                            self.logger.error(f"强制终止广播进程失败: {kill_error}")
                            return False
                
                # 再次解除鼠标限制
                if hasattr(self, 'countermeasure') and self.countermeasure and hasattr(self.countermeasure, 'window_freedom'):
                    self.countermeasure.window_freedom.force_free_cursor()
                
                self.status_signal.emit(f"已终止广播进程 (PID: {pid})")
                return True
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                self.logger.error(f"终止广播进程时出错: {e}")
                self.status_signal.emit(f"终止广播进程失败: {e}")
                return False
        
        except Exception as e:
            self.logger.error(f"终止广播进程时出错: {e}")
            self.status_signal.emit(f"终止广播进程失败: {e}")
            return False

    def close_selected_window(self):
        """关闭选中的窗口"""
        try:
            # 检查是否有选中的行
            if not self.window_table.selectedItems():
                self.status_signal.emit("请先选择要关闭的窗口")
                return
            
            # 获取选中行
            row = self.window_table.currentRow()
            if row < 0:
                return
            
            # 获取窗口句柄
            hwnd_item = self.window_table.item(row, 0)
            if not hwnd_item:
                self.status_signal.emit("无法获取窗口句柄")
                return
            
            try:
                # 转换为整数
                hwnd = int(hwnd_item.text())
                
                # 如果countermeasure对象存在，使用它来关闭窗口
                if hasattr(self, 'countermeasure') and self.countermeasure and hasattr(self.countermeasure, 'window_freedom'):
                    if self.countermeasure.window_freedom.close_window(hwnd):
                        self.status_signal.emit("窗口已关闭")
                        
                        # 刷新窗口列表
                        self.refresh_window_list()
                    else:
                        self.status_signal.emit("关闭窗口失败")
                else:
                    # 备用方法：直接使用win32gui
                    import win32gui
                    import win32con
                    if win32gui.IsWindow(hwnd):
                        win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                        self.status_signal.emit("已发送关闭命令")
                        
                        # 刷新窗口列表
                        self.refresh_window_list()
                    else:
                        self.status_signal.emit("无效的窗口句柄")
            
            except Exception as e:
                self.logger.error(f"关闭窗口时出错: {e}")
                self.status_signal.emit(f"关闭窗口失败: {e}")
        
        except Exception as e:
            self.logger.error(f"关闭选中窗口时出错: {e}")
            self.status_signal.emit(f"关闭选中窗口操作失败: {e}")

    def remove_selected_window_topmost(self):
        """移除选中窗口的置顶属性"""
        try:
            # 检查是否有选中的行
            if not self.window_table.selectedItems():
                self.status_signal.emit("请先选择要取消置顶的窗口")
                return
            
            # 获取选中行
            row = self.window_table.currentRow()
            if row < 0:
                return
            
            # 获取窗口句柄
            hwnd_item = self.window_table.item(row, 0)
            if not hwnd_item:
                self.status_signal.emit("无法获取窗口句柄")
                return
            
            try:
                # 转换为整数
                hwnd = int(hwnd_item.text())
                
                # 如果countermeasure对象存在，使用它来移除置顶
                if hasattr(self, 'countermeasure') and self.countermeasure and hasattr(self.countermeasure, 'window_freedom'):
                    if self.countermeasure.window_freedom.remove_window_topmost(hwnd):
                        self.status_signal.emit("已移除窗口置顶属性")
                        
                        # 刷新窗口列表
                        self.refresh_window_list()
                    else:
                        self.status_signal.emit("移除窗口置顶属性失败")
                else:
                    # 备用方法：直接使用win32gui
                    import win32gui
                    import win32con
                    if win32gui.IsWindow(hwnd):
                        # 获取当前窗口样式
                        style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
                        
                        # 移除置顶标志
                        if style & win32con.WS_EX_TOPMOST:
                            win32gui.SetWindowPos(
                                hwnd, 
                                win32con.HWND_NOTOPMOST,
                                0, 0, 0, 0,
                                win32con.SWP_NOMOVE | win32con.SWP_NOSIZE
                            )
                            self.status_signal.emit("已移除窗口置顶属性")
                        else:
                            self.status_signal.emit("该窗口不是置顶窗口")
                        
                        # 刷新窗口列表
                        self.refresh_window_list()
                    else:
                        self.status_signal.emit("无效的窗口句柄")
            
            except Exception as e:
                self.logger.error(f"移除窗口置顶属性时出错: {e}")
                self.status_signal.emit(f"移除窗口置顶属性失败: {e}")
        
        except Exception as e:
            self.logger.error(f"移除选中窗口置顶属性时出错: {e}")
            self.status_signal.emit(f"移除选中窗口置顶属性操作失败: {e}")

    def setup_tools(self):
        """设置工具和辅助类"""
        try:
            self.logger.info("正在初始化集成反制措施...")
            
            # 创建IntegratedCountermeasure实例
            try:
                from src.integrated_countermeasure import IntegratedCountermeasure
                self.countermeasure = IntegratedCountermeasure()
                self.logger.info("成功创建IntegratedCountermeasure实例")
                
                # 注册主窗口句柄
                try:
                    if hasattr(self, 'main_window_hwnd') and self.main_window_hwnd:
                        self.countermeasure.register_window(self.main_window_hwnd)
                    else:
                        self.countermeasure.register_window(int(self.winId()))
                    self.logger.info("成功注册窗口句柄到IntegratedCountermeasure")
                except Exception as e:
                    self.logger.error(f"注册窗口句柄时出错: {e}")
            except ImportError as e:
                self.logger.error(f"导入IntegratedCountermeasure模块失败: {e}")
                # 创建一个空的countermeasure实现
                class EmptyCountermeasure:
                    def __init__(self):
                        self.logger = logging.getLogger("FreedomTool")
                        self.logger.warning("使用空的IntegratedCountermeasure实现")
                        self.countermeasure_manager = None
                        self.window_freedom = None
                    
                    def start_protection(self):
                        self.logger.warning("使用空的IntegratedCountermeasure.start_protection")
                        return False
                    
                    def stop_protection(self):
                        self.logger.warning("使用空的IntegratedCountermeasure.stop_protection")
                        return True
                    
                    def emergency_unlock(self):
                        self.logger.warning("使用空的IntegratedCountermeasure.emergency_unlock")
                        return False
                    
                    def register_window(self, hwnd):
                        self.logger.warning(f"使用空的IntegratedCountermeasure.register_window: {hwnd}")
                        pass
                
                self.countermeasure = EmptyCountermeasure()
                self.logger.warning("初始化了一个空的IntegratedCountermeasure实现")
            except Exception as e:
                self.logger.error(f"创建IntegratedCountermeasure实例时出错: {e}")
                self.countermeasure = None
            
            # 创建随机进程分析器实例
            try:
                from src.random_process_analyzer import RandomProcessAnalyzer
                self.random_process_analyzer = RandomProcessAnalyzer()
                self.logger.info("成功创建RandomProcessAnalyzer实例")
            except Exception as e:
                self.logger.error(f"创建RandomProcessAnalyzer实例时出错: {e}")
                self.random_process_analyzer = None
        
        except Exception as e:
            self.logger.error(f"设置工具和辅助类时出错: {e}")
            self.random_process_analyzer = None
            self.countermeasure = None

    def create_fireway_tab(self):
        """创建极域防控选项卡，集成repython功能"""
        fireway_tab = QWidget()
        layout = QVBoxLayout(fireway_tab)
        
        # 创建标题
        title_label = QLabel("极域防控工具")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title_label)
        
        # 创建状态显示框架
        status_group = QGroupBox("保护状态")
        status_layout = QGridLayout(status_group)
        
        # 状态显示
        self.fw_blackscreen_status_label = QLabel("未启用")
        self.fw_monitoring_status_label = QLabel("未启用")
        self.fw_process_status_label = QLabel("未启用")
        
        status_layout.addWidget(QLabel("防黑屏:"), 0, 0, alignment=Qt.AlignRight)
        status_layout.addWidget(self.fw_blackscreen_status_label, 0, 1, alignment=Qt.AlignLeft)
        status_layout.addWidget(QLabel("防监视:"), 1, 0, alignment=Qt.AlignRight)
        status_layout.addWidget(self.fw_monitoring_status_label, 1, 1, alignment=Qt.AlignLeft)
        status_layout.addWidget(QLabel("进程保护:"), 2, 0, alignment=Qt.AlignRight)
        status_layout.addWidget(self.fw_process_status_label, 2, 1, alignment=Qt.AlignLeft)
        
        layout.addWidget(status_group)
        
        # 创建配置框架
        config_group = QGroupBox("保护设置")
        config_layout = QVBoxLayout(config_group)
        
        # 保护选项
        self.fw_blackscreen_check = QCheckBox("防黑屏 - 防止屏幕被监控或锁定")
        self.fw_monitoring_check = QCheckBox("防监视 - 防止电脑被远程监控")
        self.fw_process_check = QCheckBox("进程保护 - 防止重要程序被关闭")
        
        self.fw_blackscreen_check.setChecked(True)
        self.fw_monitoring_check.setChecked(True)
        self.fw_process_check.setChecked(True)
        
        config_layout.addWidget(self.fw_blackscreen_check)
        config_layout.addWidget(self.fw_monitoring_check)
        config_layout.addWidget(self.fw_process_check)
        
        layout.addWidget(config_group)
        
        # 创建按钮区域
        button_frame = QFrame()
        button_layout = QHBoxLayout(button_frame)
        
        # 启动/停止按钮
        self.fw_start_stop_button = QPushButton("启动保护")
        self.fw_start_stop_button.clicked.connect(self.toggle_fireway_protection)
        button_layout.addWidget(self.fw_start_stop_button)
        
        # 设置按钮
        self.fw_settings_button = QPushButton("高级设置")
        self.fw_settings_button.clicked.connect(self.show_fireway_settings)
        button_layout.addWidget(self.fw_settings_button)
        
        # 禁止名单按钮
        self.fw_blocklist_button = QPushButton("管理禁止名单")
        self.fw_blocklist_button.clicked.connect(self.manage_fireway_blocklist)
        button_layout.addWidget(self.fw_blocklist_button)
        
        layout.addWidget(button_frame)
        
        # 创建日志显示区域
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_group)
        
        self.fw_log_text = QTextEdit()
        self.fw_log_text.setReadOnly(True)
        log_layout.addWidget(self.fw_log_text)
        
        # 日志按钮
        log_buttons = QFrame()
        log_buttons_layout = QHBoxLayout(log_buttons)
        
        self.fw_clear_log_button = QPushButton("清除日志")
        self.fw_clear_log_button.clicked.connect(self.clear_fireway_log)
        log_buttons_layout.addWidget(self.fw_clear_log_button)
        
        self.fw_save_log_button = QPushButton("保存日志")
        self.fw_save_log_button.clicked.connect(self.save_fireway_log)
        log_buttons_layout.addWidget(self.fw_save_log_button)
        
        log_layout.addWidget(log_buttons)
        layout.addWidget(log_group)
        
        # 添加初始日志
        self.add_fireway_log("极域防控工具已加载")
        self.add_fireway_log("准备就绪")
        
        # 初始化fireway核心功能对象
        self._init_fireway_core()
        
        # 设置布局的间距
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)
        
        return fireway_tab

    def _init_fireway_core(self):
        """初始化极域防控工具核心功能"""
        try:
            self.fw_protection_active = False
            
            # 创建配置目录
            self.fw_config_dir = os.path.join(os.path.expanduser("~"), ".fireway")
            if not os.path.exists(self.fw_config_dir):
                os.makedirs(self.fw_config_dir)
            
            # 配置文件路径
            self.fw_config_file = os.path.join(self.fw_config_dir, "config.json")
            
            # 禁止名单
            self.fw_blocklist = [
                "StudentMain.exe", 
                "CenterServer.exe", 
                "ClassManager.exe",
                "TopDomain.exe",
                "MasterHelper.exe",
                "Student.exe"
            ]
            
            # 从配置文件加载禁止名单（如果存在）
            self.load_fireway_config()
            
            # 创建定时器，用于更新状态
            self.fw_status_timer = QTimer()
            self.fw_status_timer.timeout.connect(self.update_fireway_status)
            
            # 添加日志
            self.add_fireway_log("极域防控核心功能已初始化")
        except Exception as e:
            self.logger.error(f"初始化极域防控功能时出错: {e}")
            self.add_fireway_log(f"初始化极域防控功能时出错: {e}")

    def toggle_fireway_protection(self):
        """切换极域防控保护状态"""
        if not self.fw_protection_active:
            # 启动保护
            self.start_fireway_protection()
        else:
            # 停止保护
            self.stop_fireway_protection()

    def start_fireway_protection(self):
        """启动极域防控保护"""
        try:
            self.add_fireway_log("正在启动保护...")
            
            # 更新状态
            self.fw_protection_active = True
            self.fw_start_stop_button.setText("停止保护")
            
            # 禁用设置选项
            self.fw_blackscreen_check.setEnabled(False)
            self.fw_monitoring_check.setEnabled(False)
            self.fw_process_check.setEnabled(False)
            
            # 启动状态更新定时器
            self.fw_status_timer.start(1000)  # 每秒更新一次
            
            # 更新状态标签
            self.update_fireway_status()
            
            # 开始实际保护
            self._start_fireway_protection_thread()
            
            self.add_fireway_log("保护已启动")
        except Exception as e:
            self.logger.error(f"启动极域防控保护时出错: {e}")
            self.add_fireway_log(f"启动保护出错: {e}")

    def stop_fireway_protection(self):
        """停止极域防控保护"""
        try:
            self.add_fireway_log("正在停止保护...")
            
            # 更新状态
            self.fw_protection_active = False
            self.fw_start_stop_button.setText("启动保护")
            
            # 启用设置选项
            self.fw_blackscreen_check.setEnabled(True)
            self.fw_monitoring_check.setEnabled(True)
            self.fw_process_check.setEnabled(True)
            
            # 停止状态更新定时器
            self.fw_status_timer.stop()
            
            # 更新状态标签
            self.update_fireway_status()
            
            # 停止实际保护
            self._stop_fireway_protection_thread()
            
            self.add_fireway_log("保护已停止")
        except Exception as e:
            self.logger.error(f"停止极域防控保护时出错: {e}")
            self.add_fireway_log(f"停止保护出错: {e}")

    def _start_fireway_protection_thread(self):
        """启动保护线程"""
        # 在实际集成中，这里会启动极域防控的核心功能线程
        # 由于我们是简化集成，实际功能已被实现在 freedom_tool 中
        # 这里只是为了演示界面
        self.add_fireway_log("启动保护线程...")

    def _stop_fireway_protection_thread(self):
        """停止保护线程"""
        # 在实际集成中，这里会停止极域防控的核心功能线程
        self.add_fireway_log("停止保护线程...")

    def update_fireway_status(self):
        """更新极域防控状态显示"""
        if self.fw_protection_active:
            # 根据设置更新状态
            self.fw_blackscreen_status_label.setText("已启用" if self.fw_blackscreen_check.isChecked() else "未启用")
            self.fw_monitoring_status_label.setText("已启用" if self.fw_monitoring_check.isChecked() else "未启用")
            self.fw_process_status_label.setText("已启用" if self.fw_process_check.isChecked() else "未启用")
            
            # 设置样式
            self.fw_blackscreen_status_label.setStyleSheet("color: green; font-weight: bold;" if self.fw_blackscreen_check.isChecked() else "color: gray;")
            self.fw_monitoring_status_label.setStyleSheet("color: green; font-weight: bold;" if self.fw_monitoring_check.isChecked() else "color: gray;")
            self.fw_process_status_label.setStyleSheet("color: green; font-weight: bold;" if self.fw_process_check.isChecked() else "color: gray;")
        else:
            # 未启动保护时，所有状态都为"未启用"
            self.fw_blackscreen_status_label.setText("未启用")
            self.fw_monitoring_status_label.setText("未启用")
            self.fw_process_status_label.setText("未启用")
            
            # 重置样式
            self.fw_blackscreen_status_label.setStyleSheet("color: gray;")
            self.fw_monitoring_status_label.setStyleSheet("color: gray;")
            self.fw_process_status_label.setStyleSheet("color: gray;")

    def add_fireway_log(self, message):
        """添加日志到极域防控日志区域"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        self.fw_log_text.append(log_entry)
        # 滚动到底部
        cursor = self.fw_log_text.textCursor()
        cursor.movePosition(cursor.End)
        self.fw_log_text.setTextCursor(cursor)

    def clear_fireway_log(self):
        """清除极域防控日志"""
        self.fw_log_text.clear()
        self.add_fireway_log("日志已清除")

    def save_fireway_log(self):
        """保存极域防控日志到文件"""
        try:
            # 选择保存文件
            file_path, _ = QFileDialog.getSaveFileName(
                self, "保存日志", "", "文本文件 (*.txt);;所有文件 (*)"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.fw_log_text.toPlainText())
                self.add_fireway_log(f"日志已保存到 {file_path}")
        except Exception as e:
            self.logger.error(f"保存极域防控日志时出错: {e}")
            self.add_fireway_log(f"保存日志出错: {e}")

    def show_fireway_settings(self):
        """显示极域防控高级设置对话框"""
        # 在实际集成中，这里会显示设置对话框
        # 这里只是简单提示
        QMessageBox.information(self, "高级设置", "极域防控高级设置功能正在开发中...")
        self.add_fireway_log("打开高级设置对话框")

    def manage_fireway_blocklist(self):
        """管理极域防控禁止名单"""
        # 简单实现，显示当前禁止名单
        blocklist_str = "\n".join(self.fw_blocklist)
        QMessageBox.information(self, "禁止名单", f"当前禁止名单:\n{blocklist_str}")
        self.add_fireway_log("查看禁止名单")

    def load_fireway_config(self):
        """加载极域防控配置"""
        try:
            if os.path.exists(self.fw_config_file):
                with open(self.fw_config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                    # 加载禁止名单
                    if 'blocklist' in config:
                        self.fw_blocklist = config['blocklist']
                        
                    # 加载其他设置
                    if 'settings' in config:
                        settings = config['settings']
                        
                        # 更新复选框状态
                        if 'blackscreen' in settings:
                            self.fw_blackscreen_check.setChecked(settings['blackscreen'])
                        if 'monitoring' in settings:
                            self.fw_monitoring_check.setChecked(settings['monitoring'])
                        if 'process' in settings:
                            self.fw_process_check.setChecked(settings['process'])
                    
                    self.add_fireway_log("配置已加载")
        except Exception as e:
            self.logger.error(f"加载极域防控配置时出错: {e}")
            self.add_fireway_log(f"加载配置出错: {e}")

    def save_fireway_config(self):
        """保存极域防控配置"""
        try:
            # 创建配置对象
            config = {
                'blocklist': self.fw_blocklist,
                'settings': {
                    'blackscreen': self.fw_blackscreen_check.isChecked(),
                    'monitoring': self.fw_monitoring_check.isChecked(),
                    'process': self.fw_process_check.isChecked()
                }
            }
            
            # 保存到文件
            with open(self.fw_config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=4)
                
            self.add_fireway_log("配置已保存")
        except Exception as e:
            self.logger.error(f"保存极域防控配置时出错: {e}")
            self.add_fireway_log(f"保存配置出错: {e}")

    def convert_hotkey_string(self, modifiers, key):
        """将修饰键和虚拟键码转换为keyboard模块使用的热键字符串
        
        Args:
            modifiers: win32con修饰键组合
            key: win32con虚拟键码
            
        Returns:
            str: keyboard模块使用的热键字符串，如'ctrl+alt+p'
        """
        # 创建空列表存储修饰键
        parts = []
        
        # 检查修饰键
        if modifiers & win32con.MOD_ALT:
            parts.append("alt")
        if modifiers & win32con.MOD_CONTROL:
            parts.append("ctrl")
        if modifiers & win32con.MOD_SHIFT:
            parts.append("shift")
        if modifiers & win32con.MOD_WIN:
            parts.append("win")
        
        # 转换虚拟键码
        key_char = ""
        
        # 函数键
        if key >= win32con.VK_F1 and key <= win32con.VK_F24:
            key_char = f"f{key - win32con.VK_F1 + 1}"
        # 数字键
        elif key >= ord('0') and key <= ord('9'):
            key_char = chr(key)
        # 字母键
        elif key >= ord('A') and key <= ord('Z'):
            key_char = chr(key).lower()
        # 其他常用键
        elif key == win32con.VK_ESCAPE:
            key_char = "esc"
        elif key == win32con.VK_RETURN:
            key_char = "enter"
        elif key == win32con.VK_SPACE:
            key_char = "space"
        elif key == win32con.VK_TAB:
            key_char = "tab"
        elif key == win32con.VK_BACK:
            key_char = "backspace"
        # 如果没有匹配项，使用键码直接表示
        else:
            key_char = f"<{key}>"
        
        parts.append(key_char)
        
        # 使用 + 连接所有部分
        return "+".join(parts)

    def create_password_tab(self):
        """创建密码计算选项卡"""
        password_tab = QWidget()
        layout = QVBoxLayout(password_tab)
        
        # 创建说明标签
        info_label = QLabel("此功能用于计算PRZS和JFGLZS程序的特殊管理密码")
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setStyleSheet("font-weight: bold; color: blue;")
        layout.addWidget(info_label)
        
        # 创建日期选择组
        date_group = QGroupBox("选择日期")
        date_layout = QHBoxLayout(date_group)
        
        # 创建日期选择控件
        self.date_picker = QDateEdit()
        self.date_picker.setCalendarPopup(True)
        self.date_picker.setDate(QDate.currentDate())
        self.date_picker.setDisplayFormat("yyyy-MM-dd")
        date_layout.addWidget(QLabel("日期:"))
        date_layout.addWidget(self.date_picker)
        
        layout.addWidget(date_group)
        
        # 创建计算按钮
        calc_button = QPushButton("计算密码")
        calc_button.clicked.connect(self.calculate_special_password)
        layout.addWidget(calc_button)
        
        # 创建结果显示区域
        result_group = QGroupBox("计算结果")
        result_layout = QVBoxLayout(result_group)
        
        self.password_result = QLineEdit()
        self.password_result.setReadOnly(True)
        self.password_result.setAlignment(Qt.AlignCenter)
        self.password_result.setStyleSheet("font-size: 16pt; font-weight: bold;")
        result_layout.addWidget(self.password_result)
        
        # 添加复制按钮
        copy_button = QPushButton("复制密码")
        copy_button.clicked.connect(self.copy_password_to_clipboard)
        result_layout.addWidget(copy_button)
        
        layout.addWidget(result_group)
        
        # 添加使用说明
        help_text = """
        <p><b>使用说明:</b></p>
        <p>1. 选择您需要计算密码的日期（默认为今天）</p>
        <p>2. 点击"计算密码"按钮</p>
        <p>3. 在监控程序的密码输入框中输入计算得到的密码</p>
        <p>4. 此密码可用于PRZS、JFGLZS等监控程序的紧急退出</p>
        <p><font color='red'>注意: 密码每天都会变化，请确保选择正确的日期</font></p>
        """
        
        help_label = QLabel()
        help_label.setText(help_text)
        help_label.setTextFormat(Qt.RichText)
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        
        layout.addStretch()
        return password_tab
    
    def calculate_special_password(self):
        """计算特殊密码"""
        try:
            # 获取选定的日期
            selected_date = self.date_picker.date()
            year = selected_date.year()
            month = selected_date.month()
            day = selected_date.day()
            
            # 计算密码值 (月份 * 13 + 日期 * 57 + 年份 * 91) * 16
            password_value = (month * 13 + day * 57 + year * 91) * 16
            
            # 特殊密码格式: 8 + 计算值
            special_password = f"8{password_value}"
            
            # 更新结果显示
            self.password_result.setText(special_password)
            self.logger.info(f"已计算日期 {year}-{month}-{day} 的特殊密码")
            
        except Exception as e:
            self.logger.error(f"计算特殊密码时出错: {e}")
            self.password_result.setText("计算错误")
    
    def copy_password_to_clipboard(self):
        """将密码复制到剪贴板"""
        try:
            password = self.password_result.text()
            if password and password != "计算错误":
                clipboard = QApplication.clipboard()
                clipboard.setText(password)
                self.logger.info("密码已复制到剪贴板")
                QMessageBox.information(self, "复制成功", "密码已复制到剪贴板")
            else:
                QMessageBox.warning(self, "复制失败", "请先计算密码")
        except Exception as e:
            self.logger.error(f"复制密码到剪贴板时出错: {e}")

    def toggle_network_unblock(self, enabled):
        """启用或禁用网络限制解除功能"""
        if enabled:
            self.start_network_unblock()
        else:
            self.stop_network_unblock()
    
    def start_network_unblock(self):
        """启动网络限制解除定时器"""
        try:
            if hasattr(self, 'is_network_unblock_active') and self.is_network_unblock_active:
                self.logger.warning("网络限制解除功能已经在运行")
                return
            
            self.is_network_unblock_active = True
            
            # 立即执行一次
            self.unblock_network()
            
            # 创建定时器，每3分钟执行一次
            if not hasattr(self, 'network_unblock_timer') or self.network_unblock_timer is None:
                self.network_unblock_timer = QTimer(self)
                self.network_unblock_timer.timeout.connect(self.unblock_network)
            
            # 设置定时器间隔为3分钟
            self.network_unblock_timer.start(3 * 60 * 1000)
            
            self.logger.info("已启动网络限制解除功能，每3分钟自动执行一次")
            self.status_signal.emit("已启动网络限制解除功能")
            
            # 确保复选框状态一致
            if hasattr(self, 'enable_network_unblock') and not self.enable_network_unblock.isChecked():
                self.enable_network_unblock.blockSignals(True)
                self.enable_network_unblock.setChecked(True)
                self.enable_network_unblock.blockSignals(False)
                
        except Exception as e:
            self.logger.error(f"启动网络限制解除功能时出错: {e}")
            self.status_signal.emit(f"启动网络限制解除功能失败: {e}")
    
    def stop_network_unblock(self):
        """停止网络限制解除定时器"""
        try:
            if not hasattr(self, 'is_network_unblock_active') or not self.is_network_unblock_active:
                return
            
            self.is_network_unblock_active = False
            
            if hasattr(self, 'network_unblock_timer') and self.network_unblock_timer:
                self.network_unblock_timer.stop()
            
            self.logger.info("已停止网络限制解除功能")
            self.status_signal.emit("已停止网络限制解除功能")
            
            # 确保复选框状态一致
            if hasattr(self, 'enable_network_unblock') and self.enable_network_unblock.isChecked():
                self.enable_network_unblock.blockSignals(True)
                self.enable_network_unblock.setChecked(False)
                self.enable_network_unblock.blockSignals(False)
                
        except Exception as e:
            self.logger.error(f"停止网络限制解除功能时出错: {e}")
    
    def unblock_network(self):
        """解除网络限制，杀死MasterHelper.exe进程，停止tdnetfilter服务"""
        try:
            self.logger.info("正在执行网络限制解除...")
            self.status_signal.emit("正在解除网络限制...")
            
            # 搜索并终止MasterHelper.exe进程
            killed_count = 0
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'].lower() == 'masterhelper.exe':
                        self.logger.info(f"发现MasterHelper.exe进程，PID: {proc.info['pid']}")
                        try:
                            self.terminate_process(proc.info['pid'], force=True)
                            killed_count += 1
                            self.logger.info(f"已终止MasterHelper.exe进程 (PID: {proc.info['pid']})")
                        except Exception as e:
                            self.logger.error(f"终止MasterHelper.exe进程失败: {e}")
            except Exception as e:
                self.logger.error(f"查找MasterHelper.exe进程时出错: {e}")
            
            # 停止tdnetfilter服务
            try:
                self.logger.info("尝试停止tdnetfilter服务...")
                
                # 使用subprocess执行命令
                import subprocess
                
                # 使用管理员权限执行命令
                if self.current_privilege_level == "管理员" or self.current_privilege_level == "System":
                    result = subprocess.run(
                        ['sc', 'stop', 'tdnetfilter'],
                        capture_output=True,
                        text=True,
                        shell=True  # 使用shell执行
                    )
                    
                    if "SUCCESS" in result.stdout or "成功" in result.stdout:
                        self.logger.info("成功停止tdnetfilter服务")
                    else:
                        self.logger.warning(f"停止tdnetfilter服务返回: {result.stdout}")
                        
                    if result.stderr:
                        self.logger.error(f"停止tdnetfilter服务错误: {result.stderr}")
                else:
                    self.logger.warning("停止tdnetfilter服务需要管理员权限，当前权限不足")
                    
            except Exception as e:
                self.logger.error(f"停止tdnetfilter服务时出错: {e}")
            
            # 记录执行结果
            if killed_count > 0:
                self.logger.info(f"已终止 {killed_count} 个MasterHelper.exe进程")
                
            self.status_signal.emit(f"网络限制解除完成: 终止了{killed_count}个MasterHelper.exe进程，尝试停止tdnetfilter服务")
            
            return True
        except Exception as e:
            self.logger.error(f"解除网络限制时出错: {e}")
            self.status_signal.emit(f"解除网络限制失败: {e}")
            return False
    
    def closeEvent(self, event):
        """窗口关闭事件处理"""
        try:
            # 停止网络限制解除定时器
            if hasattr(self, 'network_unblock_timer') and self.network_unblock_timer:
                self.network_unblock_timer.stop()
            
            # 处理原有的关闭逻辑
            if hasattr(self, 'is_protection_active') and self.is_protection_active:
                reply = QMessageBox.question(
                    self, "确认", "保护功能仍在运行中，确定要退出吗？\n退出后将无法保护系统免受监控",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                
                if reply == QMessageBox.Yes:
                    self.stop_protection()
                    event.accept()
                else:
                    event.ignore()
            else:
                # 询问是否退出
                reply = QMessageBox.question(
                    self, "确认", "确定要退出吗？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    event.accept()
                else:
                    event.ignore()
        except Exception as e:
            self.logger.error(f"处理窗口关闭事件时出错: {e}")
            event.accept()  # 发生错误时接受关闭事件


def main():
    """主函数"""
    # 设置异常钩子，捕获未处理的异常
    def exception_hook(exctype, value, traceback):
        logger.error(f"未捕获的异常: {exctype.__name__}: {value}")
        sys.__excepthook__(exctype, value, traceback)
        
        # 显示错误对话框
        try:
            app = QApplication.instance() or QApplication(sys.argv)
            QMessageBox.critical(None, "程序错误", f"程序遇到了未处理的错误:\n{exctype.__name__}: {value}")
        except:
            pass
    
    sys.excepthook = exception_hook
    
    # 检查是否以管理员权限运行
    if sys.platform == 'win32' and not is_admin():
        logger.info("请求管理员权限...")
        # 请求管理员权限
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            return
        except Exception as e:
            logger.warning(f"请求管理员权限失败: {e}")
            # 显示警告，但继续以普通权限运行
            try:
                app = QApplication(sys.argv)
                result = QMessageBox.warning(
                    None, 
                    "权限警告", 
                    "此程序建议以管理员权限运行以获得完整功能。\n请求管理员权限失败。\n\n是否继续以普通权限运行？",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes
                )
                if result == QMessageBox.No:
                    return
            except:
                # 如果无法显示对话框，继续尝试运行
                pass
    
    # 创建应用
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # 使用Fusion风格，跨平台一致性好
    
    # 设置应用程序图标
    app_icon = QIcon()
    try:
        # 尝试从资源目录加载图标
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "icons", "shield.ico")
        if os.path.exists(icon_path):
            app_icon = QIcon(icon_path)
        else:
            # 使用系统图标
            app_icon = app.style().standardIcon(getattr(QStyle, 'SP_ComputerIcon'))
        
        app.setWindowIcon(app_icon)
    except Exception as e:
        logger.warning(f"设置应用图标时出错: {e}")
    
    # 创建主窗口
    try:
        logger.info("初始化主窗口...")
        window = FreedomTool()
        window.show()
        
        # 执行应用
        logger.info("启动主循环...")
        return app.exec_()
    except Exception as e:
        logger.error(f"启动程序时发生错误: {e}")
        logger.error(f"详细错误信息: {traceback.format_exc()}")
        
        # 显示错误对话框
        QMessageBox.critical(None, "启动错误", f"启动程序时发生错误:\n{e}\n\n请尝试以管理员身份运行程序。")
        return 1

def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_system():
    """检查是否以System权限运行"""
    try:
        import win32security
        import win32process
        
        # 获取当前进程的令牌
        process_token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32security.TOKEN_QUERY
        )
        
        # 获取令牌用户SID
        user_sid = win32security.GetTokenInformation(
            process_token, 
            win32security.TokenUser
        )[0]
        
        # 获取系统SID
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
        
        # 比较SID
        return user_sid == system_sid
    except Exception as e:
        print(f"检查System权限时出错: {e}")
        return False


if __name__ == "__main__":
    sys.exit(main()) 