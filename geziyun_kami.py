#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
统一验证系统 - 鸽子云卡密验证模块
提供卡密登录、解绑和公告获取功能
"""

import requests
import hashlib
import time
import warnings
import json
import threading
from typing import Dict, Any, Optional, Union, Tuple
from urllib3.exceptions import InsecureRequestWarning

# tkinter UI相关导入
import tkinter as tk
from tkinter import ttk, messagebox
import threading

# 兼容PyQt5，提供与旧LoginDialog相同的接口
try:
    from PyQt5.QtWidgets import QDialog
    from PyQt5.QtCore import Qt
    
    # 兼容旧版LoginDialog的类，用于无缝替换
    class LoginDialog(QDialog):
        """兼容旧版LoginDialog的接口，内部使用KamiLoginUI"""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("卡密登录")
            self.login_result = None
            
            # 创建内部鸽子云卡密登录界面
            self.root = tk.Tk()
            self.root.withdraw()  # 隐藏主窗口
            self.kami_ui = KamiLoginUI(self.root)
            
            # 覆盖登录结果处理函数
            original_handle = self.kami_ui._handle_login_result
            
            def custom_handle(success, message, data):
                if success:
                    vip_time = data.get('vip', '永久')
                    username = ""
                    # 存储登录结果，格式与旧版相同
                    self.login_result = {
                        "success": True,
                        "username": data.get('kami', username),
                        "real_name": vip_time
                    }
                    # 关闭tkinter窗口
                    self.root.after(500, self.root.destroy)
                else:
                    self.login_result = {
                        "success": False,
                        "message": message
                    }
                # 调用原来的处理函数
                original_handle(success, message, data)
            
            # 替换处理方法
            self.kami_ui._handle_login_result = custom_handle
        
        def exec_(self):
            """显示登录对话框并等待结果"""
            self.root.deiconify()  # 显示主窗口
            self.kami_ui.run()  # 运行tkinter主循环
            return self.login_result and self.login_result.get('success', False)
        
        def get_login_result(self):
            """获取登录结果"""
            if not self.login_result:
                return {"success": False, "message": "登录被取消或未完成"}
            return self.login_result
except ImportError:
    pass  # 如果没有PyQt5，则忽略兼容类

# 禁用不安全请求的警告
warnings.simplefilter('ignore', InsecureRequestWarning)

# 调试模式标志
DEBUG_MODE = False

def debug_print(*args, **kwargs):
    """调试信息打印函数"""
    if DEBUG_MODE:
        print("[DEBUG]", *args, **kwargs)

class GeziyunKami:
    """鸽子云卡密验证模块"""
    
    # 使用HTTP而非HTTPS，避免证书问题
    BASE_URL = "http://geziyun.cn/api.php"
    DEFAULT_APP_ID = "2216"  # 应用ID
    DEFAULT_APP_KEY = "LiSRYlgmOCRYl8RG"  # 应用密钥
    
    def __init__(self, app_id: str = DEFAULT_APP_ID, app_key: str = DEFAULT_APP_KEY):
        """
        初始化鸽子云卡密验证客户端
        
        Args:
            app_id: 应用ID，默认为2216
            app_key: 应用密钥，用于数据签名校验
        """
        self.app_id = app_id
        self.app_key = app_key
    
    def _calculate_check(self, server_timestamp: str) -> str:
        """
        计算二次验证码 (check)
        
        Args:
            server_timestamp: 服务器返回的时间戳
            
        Returns:
            二次验证码 (md5(timestamp+APPKEY))
        """
        if not self.app_key or not server_timestamp:
            return ""
            
        # 计算规则为md5(服务器返回的时间戳+APPKEY)
        check_str = f"{server_timestamp}{self.app_key}"
        check = hashlib.md5(check_str.encode('utf-8')).hexdigest().lower()
        
        debug_print(f"二次验证前字符串: {check_str}")
        debug_print(f"生成的二次验证码: {check}")
        
        return check

    def _parse_response(self, response_text: str, api_type: str = "default") -> Dict[str, Any]:
        """
        解析API响应
        
        Args:
            response_text: API返回的文本
            api_type: API类型，用于特殊处理
            
        Returns:
            解析后的JSON数据
        """
        debug_print(f"开始解析API响应，API类型: {api_type}")
        debug_print(f"原始响应: {response_text[:200]}..." if len(response_text) > 200 else f"原始响应: {response_text}")
        
        try:
            # 鸽子云API可能返回带有前缀的JSON，需要处理
            if response_text.startswith("鸽子云验证"):
                debug_print("检测到前缀'鸽子云验证'，已移除")
                response_text = response_text.replace("鸽子云验证", "", 1)
            
            # 尝试查找JSON开始位置
            json_start = response_text.find('{')
            if json_start >= 0 and json_start > 0:
                debug_print(f"找到JSON开始位置: {json_start}")
                response_text = response_text[json_start:]
            
            # 尝试解析JSON
            debug_print("尝试解析为JSON")
            result = json.loads(response_text)
            debug_print(f"JSON解析成功: {json.dumps(result, ensure_ascii=False)}")
            
            # 如果解析成功且响应中包含时间戳字段，计算二次验证码
            if 'timestamp' in result:
                check = self._calculate_check(str(result['timestamp']))
                debug_print(f"已计算二次验证码 (check): {check}")
                result['check'] = check
            
            return result
            
        except json.JSONDecodeError as e:
            debug_print(f"JSON解析失败: {str(e)}")
            debug_print(f"原始响应内容: {response_text[:200]}..." if len(response_text) > 200 else response_text)
            
            # 处理特殊情况
            if api_type == "kmlogon" and "成功" in response_text:
                debug_print("检测到登录成功关键词，构造成功响应")
                return {
                    "code": 200,
                    "msg": {
                        "kami": "验证通过",
                        "vip": "永久"
                    }
                }
            
            debug_print("构造JSON解析错误响应")
            return {
                "code": 500, 
                "msg": f"JSON解析错误: {str(e)}",
                "raw_response": response_text[:200] + "..." if len(response_text) > 200 else response_text
            }
    
    def _api_request(self, api: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        发送API请求
        
        Args:
            api: API名称
            params: 额外请求参数
            
        Returns:
            API响应结果的字典
        """
        debug_print(f"\n{'='*50}")
        debug_print(f"发起API请求: {api}")
        
        if params is None:
            params = {}
            
        # 构建请求参数
        request_params = {
            "api": api,
            "app": self.app_id,
            **params
        }
        
        debug_print(f"基础请求参数: {request_params}")
        
        # 添加时间戳，但不添加签名
        request_params["t"] = int(time.time())
        
        debug_print(f"最终请求参数: {request_params}")
        
        try:
            # 尝试使用HTTP和HTTPS两种方式
            try:
                # 先尝试使用HTTP
                debug_print(f"尝试HTTP请求: {self.BASE_URL}")
                full_url = f"{self.BASE_URL}?{'&'.join([f'{k}={v}' for k, v in request_params.items()])}"
                debug_print(f"完整请求URL: {full_url}")
                
                response = requests.get(self.BASE_URL, params=request_params, timeout=10)
                debug_print(f"HTTP请求响应状态码: {response.status_code}")
                response.raise_for_status()  # 检查HTTP错误
            except (requests.RequestException, requests.ConnectionError) as e:
                debug_print(f"HTTP请求失败: {str(e)}，尝试HTTPS")
                # 如果HTTP失败，尝试HTTPS但禁用验证
                https_url = self.BASE_URL.replace("http://", "https://")
                debug_print(f"尝试HTTPS请求: {https_url}")
                response = requests.get(https_url, params=request_params, verify=False, timeout=10)
                debug_print(f"HTTPS请求响应状态码: {response.status_code}")
                response.raise_for_status()
            
            # 检查是否有内容返回
            if not response.text:
                debug_print(f"警告: API返回空响应 (URL: {response.url})")
                return {"code": 500, "msg": "API返回空响应"}
            
            debug_print(f"API响应内容: {response.text[:200]}..." if len(response.text) > 200 else f"API响应内容: {response.text}")
            
            # 解析响应，传入API类型以进行特殊处理
            result = self._parse_response(response.text, api)
            debug_print(f"API响应解析结果: {json.dumps(result, ensure_ascii=False)}")
            debug_print(f"{'='*50}\n")
            return result
                
        except Exception as e:
            debug_print(f"API请求过程发生异常: {str(e)}")
            debug_print(f"{'='*50}\n")
            return {"code": 500, "msg": f"API请求失败: {str(e)}"}
    
    def get_config(self) -> Tuple[bool, Dict[str, Any], Dict[str, Any]]:
        """
        获取应用配置
        
        Returns:
            元组 (成功状态, 配置数据, 响应数据)
        """
        debug_print("调用获取应用配置API")
        response = self._api_request("ini")
        
        if response.get("code") == 200:
            debug_print("获取应用配置成功")
            return True, response.get("msg", {}), response
        else:
            debug_print(f"获取应用配置失败: {response.get('msg')}")
            return False, {}, response
    
    def login(self, kami: str, mark_code: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        卡密登录
        
        Args:
            kami: 卡密
            mark_code: 设备码/机器码
            
        Returns:
            元组 (成功状态, 提示消息, 响应数据)
        """
        debug_print(f"调用卡密登录API，卡密: {kami}, 机器码: {mark_code}")
        params = {
            "kami": kami,
            "markcode": mark_code
        }
        
        response = self._api_request("kmlogon", params)
        
        if response.get("code") == 200:
            debug_print("卡密登录成功")
            return True, "登录成功", response.get("msg", {})
        else:
            debug_print(f"卡密登录失败: {self._get_error_message(response.get('code', 0))}")
            return False, self._get_error_message(response.get("code", 0)), response
    
    def unbind_machine(self, mark_code: str, kami: str = "") -> Tuple[bool, str, Dict[str, Any]]:
        """
        解绑卡密机器码及IP
        
        Args:
            mark_code: 设备码/机器码
            kami: 卡密（可选）
            
        Returns:
            元组 (成功状态, 提示消息, 响应数据)
        """
        debug_print(f"调用解绑机器码API，机器码: {mark_code}, 卡密: {kami}")
        params = {
            "markcode": mark_code
        }
        
        # 如果提供了卡密，添加到请求参数中
        if kami:
            params["kami"] = kami
        
        response = self._api_request("kmunmachine", params)
        
        if response.get("code") == 200:
            debug_print("解绑机器码成功")
            return True, "卡密解绑成功", response
        else:
            debug_print(f"解绑机器码失败: {self._get_error_message(response.get('code', 0))}")
            return False, self._get_error_message(response.get("code", 0)), response
    
    def get_notice(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        获取应用公告
        
        Returns:
            元组 (成功状态, 公告内容, 响应数据)
        """
        debug_print("调用获取应用公告API")
        response = self._api_request("notice")
        
        if response.get("code") == 200:
            notice = response.get("msg", {}).get("app_gg", "")
            debug_print(f"获取应用公告成功: {notice}")
            return True, notice, response
        else:
            debug_print(f"获取应用公告失败: {self._get_error_message(response.get('code', 0))}")
            return False, self._get_error_message(response.get("code", 0)), response
    
    def _get_error_message(self, code: int) -> str:
        """
        获取错误码对应的错误信息
        
        Args:
            code: 错误码
            
        Returns:
            错误信息
        """
        error_codes = {
            101: "应用不存在",
            102: "应用已关闭",
            104: "签名为空",
            105: "数据过期",
            106: "签名有误",
            112: "请填写机械码",
            148: "卡密为空",
            149: "卡密不存在",
            151: "卡密禁用",
            169: "IP不一致",
            171: "接口维护中",
            172: "接口未添加或不存在",
            500: "系统内部错误"
        }
        
        message = error_codes.get(code, f"未知错误 (代码: {code})")
        debug_print(f"错误码 {code} 对应的错误信息: {message}")
        return message


def get_machine_code() -> str:
    """
    获取机器码
    
    Returns:
        机器码字符串
    """
    import platform
    import uuid
    
    system_info = platform.system() + platform.version() + platform.machine()
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 2)][::-1])
    
    machine_code = system_info + mac_address
    result = hashlib.md5(machine_code.encode()).hexdigest()
    debug_print(f"生成机器码: {result}")
    return result


class KamiLoginUI:
    """卡密登录UI界面"""
    
    def __init__(self, master=None):
        """
        初始化登录界面
        
        Args:
            master: tkinter主窗口
        """
        if not master:
            self.root = tk.Tk()
            self.root.title("firedowntools - 卡密登录")
            # 设置图标
            try:
                self.root.iconbitmap("icon.ico")
            except:
                pass  # 如果图标不存在，忽略
        else:
            self.root = master
            
        # 创建客户端实例
        self.client = GeziyunKami()
        
        # 获取机器码
        self.machine_code = get_machine_code()
        
        # 创建UI组件
        self._create_widgets()
        
        # 加载公告
        self._load_notice()
    
    def _create_widgets(self):
        """创建UI组件"""
        # 设置样式
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("微软雅黑", 10))
        self.style.configure("TEntry", font=("微软雅黑", 10))
        self.style.configure("TButton", font=("微软雅黑", 10))
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="20", style="TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        ttk.Label(self.main_frame, text="firedowntools v2.0 - 卡密登录", font=("微软雅黑", 14, "bold")).pack(pady=(0, 20))
        
        # 机器码显示
        machine_frame = ttk.Frame(self.main_frame)
        machine_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(machine_frame, text="设备码:").pack(side=tk.LEFT)
        ttk.Label(machine_frame, text=self.machine_code).pack(side=tk.LEFT, padx=(5, 0))
        
        # 卡密输入框
        kami_frame = ttk.Frame(self.main_frame)
        kami_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(kami_frame, text="卡密:").pack(side=tk.LEFT)
        self.kami_entry = ttk.Entry(kami_frame, width=30)
        self.kami_entry.pack(side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True)
        
        # 登录按钮
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 20))
        self.login_btn = ttk.Button(btn_frame, text="登录", command=self._login)
        self.login_btn.pack(side=tk.LEFT, padx=(0, 10))
        self.unbind_btn = ttk.Button(btn_frame, text="解绑机器码", command=self._unbind)
        self.unbind_btn.pack(side=tk.LEFT)
        
        # 日志和公告显示区域
        ttk.Label(self.main_frame, text="系统公告:", anchor=tk.W).pack(fill=tk.X)
        self.log_text = tk.Text(self.main_frame, height=10, width=40, wrap=tk.WORD, font=("微软雅黑", 12))
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.log_text.config(state=tk.DISABLED, foreground="red")  # 设为只读，文字颜色为红色
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 窗口设置
        self.root.geometry("480x400")
        self.root.minsize(400, 350)
        
        # 绑定回车键登录
        self.kami_entry.bind("<Return>", lambda event: self._login())
    
    def _login(self):
        """执行登录操作"""
        kami = self.kami_entry.get().strip()
        if not kami:
            messagebox.showerror("错误", "请输入卡密")
            return
        
        self.status_var.set("正在登录...")
        self.login_btn.config(state=tk.DISABLED)
        
        # 使用线程执行登录，避免界面卡住
        def login_thread():
            try:
                success, message, data = self.client.login(kami, self.machine_code)
                
                # 回到主线程更新UI
                self.root.after(0, lambda: self._handle_login_result(success, message, data))
            except Exception as e:
                self.root.after(0, lambda: self._handle_login_error(str(e)))
        
        threading.Thread(target=login_thread).start()
    
    def _handle_login_result(self, success, message, data):
        """处理登录结果"""
        self.login_btn.config(state=tk.NORMAL)
        
        if success:
            self.status_var.set("登录成功")
            vip_time = data.get('vip', '永久')
            try:
                # 如果vip是时间戳，转换为可读格式
                if vip_time and vip_time.isdigit() and len(vip_time) >= 10:
                    vip_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(vip_time)))
            except:
                pass
            
            messagebox.showinfo("登录成功", f"卡密验证通过!\n到期时间: {vip_time}")
        else:
            self.status_var.set(f"登录失败: {message}")
            messagebox.showerror("登录失败", message)
    
    def _handle_login_error(self, error_msg):
        """处理登录过程中的异常"""
        self.login_btn.config(state=tk.NORMAL)
        self.status_var.set(f"登录错误: {error_msg}")
        messagebox.showerror("登录错误", f"登录过程中出现错误:\n{error_msg}")
    
    def _unbind(self):
        """执行解绑操作"""
        kami = self.kami_entry.get().strip()
        if not kami:
            messagebox.showerror("错误", "请输入卡密")
            return
            
        if messagebox.askyesno("确认解绑", "确定要解绑当前设备码吗?"):
            self.status_var.set("正在解绑...")
            self.unbind_btn.config(state=tk.DISABLED)
            
            # 使用线程执行解绑，避免界面卡住
            def unbind_thread():
                try:
                    success, message, _ = self.client.unbind_machine(self.machine_code, kami)
                    
                    # 回到主线程更新UI
                    self.root.after(0, lambda: self._handle_unbind_result(success, message))
                except Exception as e:
                    self.root.after(0, lambda: self._handle_unbind_error(str(e)))
            
            threading.Thread(target=unbind_thread).start()
    
    def _handle_unbind_result(self, success, message):
        """处理解绑结果"""
        self.unbind_btn.config(state=tk.NORMAL)
        
        if success:
            self.status_var.set("解绑成功")
            messagebox.showinfo("解绑成功", "设备码已成功解绑")
        else:
            self.status_var.set(f"解绑失败: {message}")
            messagebox.showerror("解绑失败", message)
    
    def _handle_unbind_error(self, error_msg):
        """处理解绑过程中的异常"""
        self.unbind_btn.config(state=tk.NORMAL)
        self.status_var.set(f"解绑错误: {error_msg}")
        messagebox.showerror("解绑错误", f"解绑过程中出现错误:\n{error_msg}")
    
    def _load_notice(self):
        """加载应用公告"""
        self.status_var.set("正在获取公告...")
        
        # 使用线程加载公告，避免界面卡住
        def notice_thread():
            try:
                success, notice, _ = self.client.get_notice()
                
                # 回到主线程更新UI
                self.root.after(0, lambda: self._update_notice(success, notice))
            except Exception as e:
                self.root.after(0, lambda: self._update_notice(False, f"获取公告出错: {str(e)}"))
        
        threading.Thread(target=notice_thread).start()
    
    def _update_notice(self, success, notice):
        """更新公告显示"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        
        if success:
            self.log_text.insert(tk.END, notice or "暂无公告")
            self.status_var.set("公告获取完成")
        else:
            self.log_text.insert(tk.END, f"公告获取失败: {notice}")
            self.status_var.set("公告获取失败")
        
        self.log_text.config(state=tk.DISABLED)
    
    def run(self):
        """运行界面"""
        self.root.mainloop()


# 使用示例
if __name__ == "__main__":
    # 直接启动图形界面
    app = KamiLoginUI()
    app.run()