#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
NsudoLC处理模块
用于下载NsudoLC并使用它提升程序权限至System级别
"""

import os
import sys
import logging
import tempfile
import zipfile
import urllib.request
import subprocess
import shutil
import ctypes
import time
from threading import Thread

class NsudoHandler:
    """处理NsudoLC下载和权限提升"""
    
    # NsudoLC国内镜像下载地址
    NSUDO_DOWNLOAD_URLS = [
        "https://ghproxy.com/https://github.com/M2Team/NSudo/releases/download/8.2/NSudo_8.2_Release_x64.zip",
        "https://hub.fastgit.xyz/M2Team/NSudo/releases/download/8.2/NSudo_8.2_Release_x64.zip",
        "https://download.fastgit.org/M2Team/NSudo/releases/download/8.2/NSudo_8.2_Release_x64.zip",
        "https://gitee.com/mirrors/nsudo/raw/master/Download/NSudo_8.2_Release_x64.zip"
    ]
    
    def __init__(self):
        """初始化NsudoHandler"""
        self.logger = logging.getLogger("FreedomProtector.NsudoHandler")
        
        # NsudoLC文件路径
        self.nsudo_path = None
        
        # 程序根目录
        self.program_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # 下载目录
        self.download_dir = os.path.join(self.program_dir, "tools")
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)
    
    def is_admin(self) -> bool:
        """检查是否拥有管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            self.logger.error(f"检查管理员权限时出错: {e}")
            return False
    
    def is_nsudo_available(self) -> bool:
        """检查NsudoLC是否已下载并可用"""
        # 1. 检查程序根目录中是否有NSudoLC.exe
        nsudo_path = os.path.join(self.program_dir, "NSudoLC.exe")
        if os.path.exists(nsudo_path) and os.path.isfile(nsudo_path):
            self.logger.info(f"在程序根目录找到NSudoLC: {nsudo_path}")
            self.nsudo_path = nsudo_path
            return True
        
        # 2. 检查当前工作目录是否有NSudoLC.exe
        nsudo_path = os.path.join(os.getcwd(), "NSudoLC.exe")
        if os.path.exists(nsudo_path) and os.path.isfile(nsudo_path):
            self.logger.info(f"在当前工作目录找到NSudoLC: {nsudo_path}")
            self.nsudo_path = nsudo_path
            return True
            
        # 3. 检查tools目录中是否有NSudoLC.exe
        nsudo_path = os.path.join(self.download_dir, "NSudoLC.exe")
        if os.path.exists(nsudo_path) and os.path.isfile(nsudo_path):
            self.logger.info(f"在tools目录找到NSudoLC: {nsudo_path}")
            self.nsudo_path = nsudo_path
            return True
        
        # 4. 检查NSudo_8.2_Release目录下是否有NSudoLC.exe
        nsudo_dir = os.path.join(self.download_dir, "NSudo_8.2_Release")
        if os.path.exists(nsudo_dir):
            for root, _, files in os.walk(nsudo_dir):
                for file in files:
                    if file.lower() == "nsudolc.exe":
                        self.nsudo_path = os.path.join(root, file)
                        self.logger.info(f"在NSudo_8.2_Release目录找到NSudoLC: {self.nsudo_path}")
                        return True
        
        # 如果在所有位置都没找到NSudoLC.exe
        self.logger.warning("未找到NSudoLC.exe")
        return False
    
    def download_nsudo(self) -> bool:
        """从国内镜像下载NsudoLC"""
        if self.is_nsudo_available():
            self.logger.info("NsudoLC已存在，无需下载")
            return True
        
        self.logger.info("开始下载NsudoLC...")
        
        # 创建临时目录保存下载的文件
        temp_dir = tempfile.mkdtemp()
        zip_file_path = os.path.join(temp_dir, "nsudo.zip")
        
        # 尝试从不同镜像下载
        success = False
        for url in self.NSUDO_DOWNLOAD_URLS:
            try:
                self.logger.info(f"尝试从 {url} 下载NsudoLC...")
                
                # 配置下载请求
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                request = urllib.request.Request(url, headers=headers)
                
                # 下载文件
                with urllib.request.urlopen(request, timeout=30) as response:
                    with open(zip_file_path, 'wb') as out_file:
                        out_file.write(response.read())
                
                # 检查文件是否下载成功
                if os.path.exists(zip_file_path) and os.path.getsize(zip_file_path) > 0:
                    success = True
                    self.logger.info(f"NsudoLC下载成功: {zip_file_path}")
                    break
            except Exception as e:
                self.logger.warning(f"从 {url} 下载失败: {e}")
        
        if not success:
            self.logger.error("无法从任何镜像下载NsudoLC")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False
        
        # 解压文件
        try:
            self.logger.info(f"解压NsudoLC到 {self.download_dir}...")
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(self.download_dir)
            
            # 查找NSudoLC.exe
            for root, _, files in os.walk(self.download_dir):
                for file in files:
                    if file.lower() == "nsudolc.exe":
                        self.nsudo_path = os.path.join(root, file)
                        self.logger.info(f"成功找到NSudoLC: {self.nsudo_path}")
                        
                        # 复制一份到程序根目录，方便以后使用
                        try:
                            target_path = os.path.join(self.program_dir, "NSudoLC.exe")
                            shutil.copy2(self.nsudo_path, target_path)
                            self.logger.info(f"已复制NSudoLC到程序根目录: {target_path}")
                            self.nsudo_path = target_path  # 使用复制后的路径
                        except Exception as copy_err:
                            self.logger.warning(f"无法复制NSudoLC到程序根目录: {copy_err}")
                        
                        break
                if self.nsudo_path:
                    break
            
            if not self.nsudo_path:
                self.logger.error("解压后未找到NSudoLC.exe")
                return False
            
            # 清理临时目录
            shutil.rmtree(temp_dir, ignore_errors=True)
            return True
        except Exception as e:
            self.logger.error(f"解压NsudoLC时出错: {e}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False
    
    def elevate_to_system(self, cmd=None) -> bool:
        """使用NsudoLC将程序提升至System权限运行"""
        # 如果没有指定命令，使用当前Python解释器重新运行当前脚本
        if cmd is None:
            python_exe = sys.executable
            script_path = os.path.abspath(sys.argv[0])
            cmd = f"{python_exe} {script_path}"
        
        # 确保NsudoLC可用
        if not self.is_nsudo_available() and not self.download_nsudo():
            self.logger.error("无法获取NsudoLC，无法提升权限")
            return False
        
        try:
            # 构建NsudoLC命令
            nsudo_cmd = f'"{self.nsudo_path}" -U:S -P:E -Wait {cmd}'
            self.logger.info(f"执行NsudoLC命令: {nsudo_cmd}")
            
            # 使用subprocess执行命令
            subprocess.Popen(nsudo_cmd, shell=True)
            
            # 提示已经启动新进程
            self.logger.info("已启动System权限的新进程，当前进程将退出")
            
            # 返回成功
            return True
        except Exception as e:
            self.logger.error(f"使用NsudoLC提升权限时出错: {e}")
            return False
    
    def async_elevate_and_exit(self, cmd=None, exit_delay=2):
        """异步提升权限并退出当前进程"""
        def _elevate_and_exit():
            if self.elevate_to_system(cmd):
                time.sleep(exit_delay)  # 等待新进程启动
                os._exit(0)  # 强制退出当前进程
        
        # 启动异步线程
        thread = Thread(target=_elevate_and_exit)
        thread.daemon = True
        thread.start()
        
        return thread 