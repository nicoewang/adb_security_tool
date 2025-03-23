import os
import sys
import subprocess
import shutil
import zipfile
import requests
from pathlib import Path
from .logger import logger

class PlatformTools:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        self.tools_dir = os.path.join(self.base_dir, 'tools')
        self.platform_tools_dir = os.path.join(self.tools_dir, 'platform-tools')
        
        # 根据操作系统设置可执行文件扩展名和下载URL
        self.exe_ext = '.exe' if sys.platform == 'win32' else ''
        self.download_url = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
        
        # 设置工具路径
        self.adb_path = os.path.join(self.platform_tools_dir, f'adb{self.exe_ext}')
        self.aapt_path = os.path.join(self.platform_tools_dir, f'aapt{self.exe_ext}')
        
        # 确保工具目录存在
        os.makedirs(self.tools_dir, exist_ok=True)

    def download_and_install(self):
        """下载并安装Platform Tools"""
        try:
            # 下载文件
            logger.info("正在下载 Platform Tools...")
            zip_path = os.path.join(self.tools_dir, "platform-tools.zip")
            
            response = requests.get(self.download_url, stream=True)
            total_size = int(response.headers.get('content-length', 0))
            
            with open(zip_path, 'wb') as f:
                if total_size == 0:
                    f.write(response.content)
                else:
                    downloaded = 0
                    for data in response.iter_content(chunk_size=8192):
                        downloaded += len(data)
                        f.write(data)
                        done = int(50 * downloaded / total_size)
                        sys.stdout.write('\r[{}{}] {}%'.format(
                            '=' * done, ' ' * (50-done), int(100 * downloaded / total_size)))
                        sys.stdout.flush()
            print()
            
            # 解压文件
            logger.info("正在解压文件...")
            if os.path.exists(self.platform_tools_dir):
                shutil.rmtree(self.platform_tools_dir)
                
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.tools_dir)
            
            # 删除zip文件
            os.remove(zip_path)
            
            # 检查文件权限
            if sys.platform != 'win32':
                os.chmod(self.adb_path, 0o755)
                os.chmod(self.aapt_path, 0o755)
            
            logger.info("Platform Tools 安装成功！")
            return True
            
        except Exception as e:
            logger.error(f"下载或安装 Platform Tools 时出错: {e}")
            return False

    def get_tool_path(self, tool_name: str) -> str:
        """获取工具的完整路径"""
        if tool_name == 'adb':
            return self.adb_path
        elif tool_name == 'aapt':
            return self.aapt_path
        return ''

    def is_tool_available(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        tool_path = self.get_tool_path(tool_name)
        if not tool_path:
            return False
        return os.path.exists(tool_path) and os.access(tool_path, os.X_OK)

    def run_command(self, tool_name: str, args: list, **kwargs) -> subprocess.CompletedProcess:
        """运行工具命令"""
        tool_path = self.get_tool_path(tool_name)
        if not tool_path:
            raise FileNotFoundError(f"工具 {tool_name} 未找到")
        
        cmd = [tool_path] + args
        return subprocess.run(cmd, **kwargs)

    def check_and_add_to_path(self):
        """将工具目录添加到环境变量PATH中"""
        if self.platform_tools_dir not in os.environ['PATH']:
            os.environ['PATH'] = f"{self.platform_tools_dir}{os.pathsep}{os.environ['PATH']}"

# 创建全局实例
platform_tools = PlatformTools() 