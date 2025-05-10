#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
密码管理器
处理密码验证和修改
"""

import os
import sys
import base64
import logging
import winreg
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

class PasswordManager:
    """管理密码的类"""
    
    # 注册表键路径
    PD_KEY_PATH = r"Software\pd"
    M360_KEY_PATH = r"Software\360m"
    
    # 加密常量
    KEY_SIZE = 8
    BLOCK_SIZE = 8
    
    def __init__(self):
        """初始化密码管理器"""
        self.logger = logging.getLogger("SystemDiagnosticTool.PasswordManager")
        
        # 检查平台是否为Windows
        if sys.platform != 'win32':
            self.logger.warning("当前不是Windows平台，密码功能将不可用")
    
    def _get_windows_dir(self):
        """获取Windows目录作为加密密钥"""
        try:
            if sys.platform == 'win32':
                return os.environ.get('WINDIR', r'C:\WINDOWS')
            return r'C:\WINDOWS'  # 默认值
        except Exception as e:
            self.logger.error(f"获取Windows目录时出错: {e}")
            return r'C:\WINDOWS'
    
    def _get_encryption_key(self):
        """获取加密密钥"""
        try:
            # 使用Windows目录的前8个字符作为密钥
            win_dir = self._get_windows_dir()
            key = win_dir[:self.KEY_SIZE].encode('utf-8')
            # 确保长度为8字节
            if len(key) < self.KEY_SIZE:
                key = key + b'\0' * (self.KEY_SIZE - len(key))
            return key
        except Exception as e:
            self.logger.error(f"获取加密密钥时出错: {e}")
            # 返回默认密钥
            return b'C:\WINDO'
    
    def _get_encryption_iv(self):
        """获取加密IV"""
        try:
            # 使用Windows目录的第2-9个字符作为IV
            win_dir = self._get_windows_dir()
            iv = win_dir[1:self.KEY_SIZE+1].encode('utf-8')
            # 确保长度为8字节
            if len(iv) < self.KEY_SIZE:
                iv = iv + b'\0' * (self.KEY_SIZE - len(iv))
            return iv
        except Exception as e:
            self.logger.error(f"获取加密IV时出错: {e}")
            # 返回默认IV
            return b':\WINDOW'
    
    def _encrypt_password(self, password):
        """加密密码"""
        try:
            # 获取加密密钥和IV
            key = self._get_encryption_key()
            iv = self._get_encryption_iv()
            
            # 创建DES加密器
            cipher = DES.new(key, DES.MODE_CBC, iv)
            
            # 加密密码
            padded_data = pad(password.encode('utf-8'), self.BLOCK_SIZE)
            encrypted_data = cipher.encrypt(padded_data)
            
            # 使用Base64编码
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            self.logger.error(f"加密密码时出错: {e}")
            return ""
    
    def _decrypt_password(self, encrypted_password):
        """解密密码"""
        try:
            # 获取加密密钥和IV
            key = self._get_encryption_key()
            iv = self._get_encryption_iv()
            
            # 创建DES解密器
            cipher = DES.new(key, DES.MODE_CBC, iv)
            
            # 解密密码
            encrypted_data = base64.b64decode(encrypted_password)
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # 移除填充
            return unpad(decrypted_data, self.BLOCK_SIZE).decode('utf-8')
        except Exception as e:
            self.logger.error(f"解密密码时出错: {e}")
            return ""
    
    def _get_password_from_registry(self):
        """从注册表获取加密的密码"""
        try:
            # 打开密码注册表键
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.PD_KEY_PATH, 0, winreg.KEY_READ)
            
            # 读取值
            value, _ = winreg.QueryValueEx(key, "")
            winreg.CloseKey(key)
            
            return value
        except FileNotFoundError:
            # 如果注册表键不存在，返回默认密文
            return "cds+7IOcda43kkig"
        except Exception as e:
            self.logger.error(f"从注册表获取密码时出错: {e}")
            return ""
    
    def _set_password_to_registry(self, encrypted_password):
        """将加密的密码存储到注册表"""
        try:
            # 创建或打开密码注册表键
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, self.PD_KEY_PATH, 0, winreg.KEY_WRITE)
            
            # 设置值
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, encrypted_password)
            winreg.CloseKey(key)
            
            # 同时更新360m键
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, self.M360_KEY_PATH, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "+7IOcdaerrorg78cs")
            winreg.CloseKey(key)
            
            return True
        except Exception as e:
            self.logger.error(f"将密码存储到注册表时出错: {e}")
            return False
    
    def verify_password(self, password):
        """验证密码是否正确"""
        try:
            # 获取注册表中的加密密码
            stored_encrypted_password = self._get_password_from_registry()
            
            # 加密输入的密码
            input_encrypted_password = self._encrypt_password(password)
            
            # 比较加密后的密码
            return input_encrypted_password == stored_encrypted_password
        except Exception as e:
            self.logger.error(f"验证密码时出错: {e}")
            return False
    
    def change_password(self, old_password, new_password):
        """更改密码"""
        try:
            # 首先验证旧密码
            if not self.verify_password(old_password):
                return False
            
            # 加密新密码
            new_encrypted_password = self._encrypt_password(new_password)
            
            # 将新密码存储到注册表
            return self._set_password_to_registry(new_encrypted_password)
        except Exception as e:
            self.logger.error(f"更改密码时出错: {e}")
            return False
    
    def reset_password(self, new_password="123456"):
        """重置密码（仅在紧急情况下使用）"""
        try:
            # 加密新密码
            new_encrypted_password = self._encrypt_password(new_password)
            
            # 将新密码存储到注册表
            return self._set_password_to_registry(new_encrypted_password)
        except Exception as e:
            self.logger.error(f"重置密码时出错: {e}")
            return False
    
    def get_default_encrypted_password(self):
        """获取默认密码'123456'加密后的值，用于调试"""
        return self._encrypt_password("123456") 