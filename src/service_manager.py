#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
服务管理器
处理Windows服务管理
"""

import sys
import logging
import subprocess

class ServiceManager:
    """管理Windows服务的类"""
    
    def __init__(self):
        """初始化服务管理器"""
        self.logger = logging.getLogger("SystemDiagnosticTool.ServiceManager")
        
        # 检查平台是否为Windows
        if sys.platform != 'win32':
            self.logger.warning("当前不是Windows平台，服务管理功能将不可用")
    
    def get_service_status(self, service_name):
        """获取服务状态"""
        try:
            if sys.platform != 'win32':
                return "不支持的平台"
            
            # 使用SC命令查询服务状态
            result = subprocess.run(['sc', 'query', service_name], 
                                   capture_output=True, text=True)
            
            if "RUNNING" in result.stdout:
                return "正在运行"
            elif "STOPPED" in result.stdout:
                return "已停止"
            elif "指定的服务未安装" in result.stdout or "specified service does not exist" in result.stdout.lower():
                return "未安装"
            else:
                return "未知"
        except Exception as e:
            self.logger.error(f"获取服务{service_name}状态时出错: {e}")
            return "错误"
    
    def start_service(self, service_name):
        """启动服务"""
        try:
            if sys.platform != 'win32':
                return False
            
            # 检查服务状态
            status = self.get_service_status(service_name)
            if status == "未安装":
                self.logger.error(f"服务{service_name}未安装")
                return False
            
            if status == "正在运行":
                return True
            
            # 使用SC命令启动服务
            result = subprocess.run(['sc', 'start', service_name], 
                                   capture_output=True, text=True)
            
            return "正在启动" in result.stdout or "START_PENDING" in result.stdout
        except Exception as e:
            self.logger.error(f"启动服务{service_name}时出错: {e}")
            return False
    
    def stop_service(self, service_name):
        """停止服务"""
        try:
            if sys.platform != 'win32':
                return False
            
            # 检查服务状态
            status = self.get_service_status(service_name)
            if status == "未安装":
                self.logger.error(f"服务{service_name}未安装")
                return False
            
            if status == "已停止":
                return True
            
            # 使用SC命令停止服务
            result = subprocess.run(['sc', 'stop', service_name], 
                                   capture_output=True, text=True)
            
            return "正在停止" in result.stdout or "STOP_PENDING" in result.stdout
        except Exception as e:
            self.logger.error(f"停止服务{service_name}时出错: {e}")
            return False
    
    def restart_service(self, service_name):
        """重启服务"""
        try:
            # 先停止服务
            if not self.stop_service(service_name):
                return False
            
            # 等待服务完全停止
            import time
            time.sleep(2)
            
            # 再启动服务
            return self.start_service(service_name)
        except Exception as e:
            self.logger.error(f"重启服务{service_name}时出错: {e}")
            return False
    
    def delete_service(self, service_name):
        """删除服务"""
        try:
            if sys.platform != 'win32':
                return False
            
            # 检查服务状态
            status = self.get_service_status(service_name)
            if status == "未安装":
                return True
            
            # 先停止服务
            self.stop_service(service_name)
            
            # 使用SC命令删除服务
            result = subprocess.run(['sc', 'delete', service_name], 
                                   capture_output=True, text=True)
            
            return "SUCCESS" in result.stdout
        except Exception as e:
            self.logger.error(f"删除服务{service_name}时出错: {e}")
            return False
    
    def delete_zmserv_service(self):
        """删除zmserv服务（原系统中特定的服务）"""
        return self.delete_service("zmserv")
    
    def list_services(self, filter_name=None):
        """列出所有服务"""
        try:
            if sys.platform != 'win32':
                return []
            
            # 使用SC命令列出所有服务
            result = subprocess.run(['sc', 'query', 'state=', 'all'], 
                                   capture_output=True, text=True, encoding='gbk')
            
            # 解析输出
            services = []
            service_info = {}
            
            for line in result.stdout.splitlines():
                line = line.strip()
                
                if line.startswith("SERVICE_NAME:"):
                    # 新服务开始
                    if service_info and 'name' in service_info:
                        services.append(service_info)
                    
                    service_info = {'name': line.split(":", 1)[1].strip()}
                elif line.startswith("DISPLAY_NAME:"):
                    service_info['display_name'] = line.split(":", 1)[1].strip()
                elif line.startswith("STATE"):
                    state_part = line.split(":", 1)[1].strip()
                    service_info['state'] = state_part.split(" ", 1)[0].strip()
            
            # 添加最后一个服务
            if service_info and 'name' in service_info:
                services.append(service_info)
            
            # 过滤服务
            if filter_name:
                filter_name = filter_name.lower()
                services = [s for s in services if filter_name in s.get('name', '').lower() or 
                           filter_name in s.get('display_name', '').lower()]
            
            return services
        except Exception as e:
            self.logger.error(f"列出服务时出错: {e}")
            return [] 