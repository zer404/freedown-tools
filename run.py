#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自由工具 - 启动脚本
"""

import sys
import os
import traceback

if __name__ == "__main__":
    try:
        # 添加当前目录到搜索路径
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        
        # 初始化 PyQt 应用
        from PyQt5.QtWidgets import QApplication
        app = QApplication(sys.argv) if not QApplication.instance() else QApplication.instance()
        
        # 直接导入并运行主程序
        from freedom_tool import main
        sys.exit(main())
            
    except Exception as e:
        print(f"启动程序时出错: {e}")
        print(f"详细错误信息: {traceback.format_exc()}")
        
        try:
            # 尝试显示错误对话框
            from PyQt5.QtWidgets import QApplication, QMessageBox
            app = QApplication(sys.argv) if not QApplication.instance() else QApplication.instance()
            QMessageBox.critical(None, "启动错误", f"启动程序时出错:\n{e}")
        except:
            pass
        
        sys.exit(1) 