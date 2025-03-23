import os
import webview
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from backend.api.routes import router
from backend.utils.logger import logger
import asyncio
import threading

app = FastAPI(title="USB设备病毒扫描工具")

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(router)

def start_server(host="127.0.0.1", port=8000):
    """启动FastAPI服务器"""
    logger.info(f"启动服务器 http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)

def create_window():
    """创建PyWebView窗口"""
    webview.create_window(
        "USB设备病毒扫描工具",
        "http://localhost:3000",
        width=1200,
        height=800,
        resizable=True,
        text_select=True
    )
    webview.start()

def run_as_desktop():
    """以桌面应用模式运行"""
    # 启动FastAPI服务器（在单独的线程中）
    server_thread = threading.Thread(
        target=start_server,
        kwargs={'host': '127.0.0.1', 'port': 8000}
    )
    server_thread.daemon = True
    server_thread.start()
    
    # 创建和启动PyWebView窗口
    create_window()

def run_as_api(host=None, port=None):
    """以API服务模式运行"""
    host = host or os.getenv('API_HOST', '127.0.0.1')
    port = port or int(os.getenv('API_PORT', '8000'))
    start_server(host, port)

if __name__ == "__main__":
    # 默认以API模式运行
    run_as_api() 