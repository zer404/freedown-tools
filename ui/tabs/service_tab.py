#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
服务管理标签页
管理Windows服务
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QGroupBox, QPushButton, 
                           QLabel, QTableWidget, QTableWidgetItem, QHBoxLayout,
                           QLineEdit, QMessageBox, QHeaderView)
from PyQt5.QtCore import Qt


class ServiceTab(QWidget):
    """服务管理标签页"""
    
    def __init__(self, controller):
        """初始化服务管理标签页"""
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
        title_label = QLabel("服务管理")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # 创建描述标签
        desc_label = QLabel("此页面用于管理Windows服务")
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        # 创建zmserv服务组
        zmserv_group = QGroupBox("zmserv服务管理")
        zmserv_layout = QVBoxLayout(zmserv_group)
        
        self.zmserv_status_label = QLabel("状态: 加载中...")
        zmserv_layout.addWidget(self.zmserv_status_label)
        
        zmserv_button_layout = QHBoxLayout()
        
        self.delete_zmserv_button = QPushButton("删除zmserv服务")
        self.delete_zmserv_button.clicked.connect(self._delete_zmserv)
        zmserv_button_layout.addWidget(self.delete_zmserv_button)
        
        zmserv_layout.addLayout(zmserv_button_layout)
        
        layout.addWidget(zmserv_group)
        
        # 创建服务搜索组
        search_group = QGroupBox("服务搜索")
        search_layout = QHBoxLayout(search_group)
        
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("输入服务名称关键字")
        search_layout.addWidget(self.search_edit)
        
        self.search_button = QPushButton("搜索")
        self.search_button.clicked.connect(self._search_services)
        search_layout.addWidget(self.search_button)
        
        layout.addWidget(search_group)
        
        # 创建服务列表组
        services_group = QGroupBox("服务列表")
        services_layout = QVBoxLayout(services_group)
        
        self.services_table = QTableWidget(0, 3)
        self.services_table.setHorizontalHeaderLabels(["服务名称", "显示名称", "状态"])
        self.services_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.services_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.services_table.setEditTriggers(QTableWidget.NoEditTriggers)
        services_layout.addWidget(self.services_table)
        
        # 创建操作按钮布局
        button_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("刷新")
        self.refresh_button.clicked.connect(self.refresh)
        button_layout.addWidget(self.refresh_button)
        
        self.start_button = QPushButton("启动")
        self.start_button.clicked.connect(self._start_service)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("停止")
        self.stop_button.clicked.connect(self._stop_service)
        button_layout.addWidget(self.stop_button)
        
        self.restart_button = QPushButton("重启")
        self.restart_button.clicked.connect(self._restart_service)
        button_layout.addWidget(self.restart_button)
        
        services_layout.addLayout(button_layout)
        
        layout.addWidget(services_group)
        
        # 根据管理员权限设置控件状态
        self._update_controls()
    
    def refresh(self):
        """刷新显示"""
        try:
            # 获取zmserv服务状态
            zmserv_status = self.controller.service_manager.get_service_status("zmserv")
            self.zmserv_status_label.setText(f"状态: {zmserv_status}")
            
            if zmserv_status == "未安装":
                self.zmserv_status_label.setStyleSheet("color: gray;")
                self.delete_zmserv_button.setEnabled(False)
            elif zmserv_status == "正在运行":
                self.zmserv_status_label.setStyleSheet("color: green;")
                self.delete_zmserv_button.setEnabled(True)
            elif zmserv_status == "已停止":
                self.zmserv_status_label.setStyleSheet("color: red;")
                self.delete_zmserv_button.setEnabled(True)
            else:
                self.zmserv_status_label.setStyleSheet("color: orange;")
                self.delete_zmserv_button.setEnabled(True)
            
            # 刷新服务列表
            self._search_services()
            
            # 更新控件状态
            self._update_controls()
        except Exception as e:
            QMessageBox.warning(self, "刷新失败", f"刷新服务状态失败: {str(e)}")
    
    def _update_controls(self):
        """根据管理员权限更新控件状态"""
        is_admin = self.controller.is_admin
        
        # 服务管理组件只有管理员可用
        self.delete_zmserv_button.setEnabled(is_admin)
        self.start_button.setEnabled(is_admin)
        self.stop_button.setEnabled(is_admin)
        self.restart_button.setEnabled(is_admin)
    
    def _search_services(self):
        """搜索服务"""
        try:
            # 获取搜索关键字
            filter_name = self.search_edit.text().strip()
            
            # 获取服务列表
            services = self.controller.service_manager.list_services(filter_name)
            
            # 更新表格
            self.services_table.setRowCount(0)
            
            for service in services:
                row = self.services_table.rowCount()
                self.services_table.insertRow(row)
                
                self.services_table.setItem(row, 0, QTableWidgetItem(service.get('name', '')))
                self.services_table.setItem(row, 1, QTableWidgetItem(service.get('display_name', '')))
                
                state_item = QTableWidgetItem(service.get('state', ''))
                if service.get('state') == "RUNNING":
                    state_item.setText("正在运行")
                    state_item.setForeground(Qt.green)
                elif service.get('state') == "STOPPED":
                    state_item.setText("已停止")
                    state_item.setForeground(Qt.red)
                
                self.services_table.setItem(row, 2, state_item)
        except Exception as e:
            QMessageBox.warning(self, "搜索失败", f"搜索服务失败: {str(e)}")
    
    def _get_selected_service(self):
        """获取选中的服务名称"""
        selected_rows = self.services_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "未选择服务", "请先选择一个服务")
            return None
        
        row = selected_rows[0].row()
        service_name = self.services_table.item(row, 0).text()
        return service_name
    
    def _start_service(self):
        """启动选中的服务"""
        try:
            # 检查是否有管理员权限
            if not self.controller.is_admin:
                QMessageBox.warning(self, "权限不足", "需要管理员权限才能管理服务")
                return
            
            # 获取选中的服务
            service_name = self._get_selected_service()
            if not service_name:
                return
            
            # 启动服务
            result = self.controller.service_manager.start_service(service_name)
            
            if result:
                QMessageBox.information(self, "启动成功", f"服务 {service_name} 已启动")
                self.refresh()
            else:
                QMessageBox.warning(self, "启动失败", f"无法启动服务 {service_name}")
        except Exception as e:
            QMessageBox.warning(self, "启动失败", f"启动服务失败: {str(e)}")
    
    def _stop_service(self):
        """停止选中的服务"""
        try:
            # 检查是否有管理员权限
            if not self.controller.is_admin:
                QMessageBox.warning(self, "权限不足", "需要管理员权限才能管理服务")
                return
            
            # 获取选中的服务
            service_name = self._get_selected_service()
            if not service_name:
                return
            
            # 确认对话框
            reply = QMessageBox.question(self, '确认停止', 
                                       f'确定要停止服务 {service_name} 吗？这可能会影响系统功能。',
                                       QMessageBox.Yes | QMessageBox.No,
                                       QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                # 停止服务
                result = self.controller.service_manager.stop_service(service_name)
                
                if result:
                    QMessageBox.information(self, "停止成功", f"服务 {service_name} 已停止")
                    self.refresh()
                else:
                    QMessageBox.warning(self, "停止失败", f"无法停止服务 {service_name}")
        except Exception as e:
            QMessageBox.warning(self, "停止失败", f"停止服务失败: {str(e)}")
    
    def _restart_service(self):
        """重启选中的服务"""
        try:
            # 检查是否有管理员权限
            if not self.controller.is_admin:
                QMessageBox.warning(self, "权限不足", "需要管理员权限才能管理服务")
                return
            
            # 获取选中的服务
            service_name = self._get_selected_service()
            if not service_name:
                return
            
            # 确认对话框
            reply = QMessageBox.question(self, '确认重启', 
                                       f'确定要重启服务 {service_name} 吗？',
                                       QMessageBox.Yes | QMessageBox.No,
                                       QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                # 重启服务
                result = self.controller.restart_service(service_name)
                
                if result:
                    QMessageBox.information(self, "重启成功", f"服务 {service_name} 已重启")
                    self.refresh()
                else:
                    QMessageBox.warning(self, "重启失败", f"无法重启服务 {service_name}")
        except Exception as e:
            QMessageBox.warning(self, "重启失败", f"重启服务失败: {str(e)}")
    
    def _delete_zmserv(self):
        """删除zmserv服务"""
        try:
            # 检查是否有管理员权限
            if not self.controller.is_admin:
                QMessageBox.warning(self, "权限不足", "需要管理员权限才能删除服务")
                return
            
            # 确认对话框
            reply = QMessageBox.question(self, '确认删除', 
                                       '确定要删除zmserv服务吗？这将移除监控服务。',
                                       QMessageBox.Yes | QMessageBox.No,
                                       QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                # 删除服务
                result = self.controller.service_manager.delete_zmserv_service()
                
                if result:
                    QMessageBox.information(self, "删除成功", "zmserv服务已删除")
                    self.refresh()
                else:
                    QMessageBox.warning(self, "删除失败", "无法删除zmserv服务")
        except Exception as e:
            QMessageBox.warning(self, "删除失败", f"删除zmserv服务失败: {str(e)}") 