import os
import sys
import subprocess
import shutil
import platform
import time
from pathlib import Path
import winreg

# 首先尝试导入必要的基础包
try:
    from dotenv import load_dotenv
except ImportError:
    print("正在安装必要的基础依赖...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-dotenv"])
    from dotenv import load_dotenv

from backend.utils.logger import logger
from backend.utils.platform_tools import platform_tools

def check_system_requirements():
    """检查系统要求"""
    logger.info("正在检查系统要求...")
    
    # 检查Python版本
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
        logger.error("需要Python 3.8或更高版本")
        return False
    
    # 检查操作系统
    system = platform.system().lower()
    if system not in ['windows', 'linux']:
        logger.error("仅支持Windows和Linux操作系统")
        return False
    
    return True

def install_python_dependencies():
    """安装Python依赖"""
    logger.info("正在安装Python依赖...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        return True
    except Exception as e:
        logger.error(f"安装Python依赖失败: {str(e)}")
        return False

def start_clamav_service_windows():
    """在Windows上启动ClamAV服务"""
    try:
        # 检查本地目录下的ClamAV
        current_dir = os.path.dirname(os.path.abspath(__file__))
        clamav_dir = os.path.join(current_dir, 'ClamAV')
        clamd_path = os.path.join(clamav_dir, 'clamd.exe')
        freshclam_path = os.path.join(clamav_dir, 'freshclam.exe')
        
        if not os.path.exists(clamd_path) or not os.path.exists(freshclam_path):
            logger.error(f"未在 {clamav_dir} 目录下找到ClamAV文件")
            return False

        # 确保没有其他ClamAV进程在运行
        try:
            subprocess.run(['taskkill', '/F', '/IM', 'clamd.exe'], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE)
            time.sleep(1)
        except:
            pass

        # 更新病毒库
        logger.info("正在更新病毒库...")
        try:
            subprocess.run(
                [freshclam_path, '--config-file', os.path.join(clamav_dir, 'freshclam.conf')],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=clamav_dir
            )
            logger.info("病毒库更新成功")
        except subprocess.CalledProcessError as e:
            logger.warning(f"病毒库更新失败: {e.stderr.decode('utf-8', errors='ignore')}")

        # 直接运行clamd
        try:
            logger.info("正在启动ClamAV服务...")
            process = subprocess.Popen(
                [clamd_path, '--config-file', os.path.join(clamav_dir, 'clamd.conf')],
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=clamav_dir
            )
            
            # 等待服务启动并尝试连接
            max_retries = 10
            retry_interval = 1
            
            import socket
            for i in range(max_retries):
                time.sleep(retry_interval)
                
                # 检查进程是否还在运行
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    error_msg = stderr.decode('utf-8', errors='ignore')
                    logger.error(f"ClamAV进程已退出: {error_msg}")
                    return False
                
                # 尝试连接服务
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(('127.0.0.1', 3310))
                    sock.close()
                    
                    if result == 0:
                        logger.info(f"ClamAV服务启动成功（尝试 {i + 1}/{max_retries}）")
                        return True
                except:
                    pass
                
                logger.info(f"等待服务启动...（尝试 {i + 1}/{max_retries}）")
            
            logger.error("ClamAV服务启动超时")
            return False
            
        except Exception as e:
            logger.error(f"启动ClamAV失败: {str(e)}")
            return False
    except Exception as e:
        logger.error(f"ClamAV启动错误: {str(e)}")
        return False

def check_clamav_service():
    """检查ClamAV服务状态"""
    try:
        import clamd
        try:
            cd = clamd.ClamdNetworkSocket(host='127.0.0.1', port=3310, timeout=5)
            cd.ping()
            logger.info("ClamAV服务正在运行")
            return True
        except:
            # 如果是Windows系统，尝试启动服务
            if platform.system().lower() == 'windows':
                if start_clamav_service_windows():
                    try:
                        cd = clamd.ClamdNetworkSocket(host='127.0.0.1', port=3310, timeout=5)
                        cd.ping()
                        return True
                    except Exception as e:
                        logger.error(f"无法连接到ClamAV服务: {str(e)}")
                        return False
            return False
    except ImportError:
        logger.error("未安装pyclamd包")
        return False

def print_installation_guide(missing_deps):
    """打印安装指南"""
    logger.info("\n安装说明:")
    if 'Android SDK Platform Tools' in missing_deps:
        logger.info("1. Android SDK Platform Tools (包含adb和aapt):")
        logger.info("   - 自动下载失败，请手动下载: https://developer.android.com/studio/releases/platform-tools")
        logger.info("   - 解压到 tools/platform-tools 目录下")
    
    if 'ClamAV服务未运行' in missing_deps:
        logger.info("2. ClamAV:")
        logger.info("   - Windows:")
        logger.info("     1. 下载并安装 ClamAV: https://www.clamav.net/downloads")
        logger.info("     2. 安装ClamAV，选择'Complete'安装")
        logger.info("     3. 打开命令提示符(管理员)，执行以下命令：")
        logger.info("         a. cd \"C:\\Program Files\\ClamAV\"")
        logger.info("         b. freshclam.exe")
        logger.info("         c. clamd.exe")
        logger.info("     4. 如果上述步骤完成后仍无法启动，请检查：")
        logger.info("         - 确保已安装Visual C++ Redistributable")
        logger.info("         - 检查clamd.conf配置文件")
        logger.info("         - 查看Windows服务是否已正确注册")
        logger.info("   - Linux:")
        logger.info("     1. sudo apt-get install clamav clamav-daemon")
        logger.info("     2. sudo systemctl start clamav-daemon")
        logger.info("     3. sudo freshclam")
    
    if any(dep.startswith('Python包:') for dep in missing_deps):
        logger.info("3. Python依赖:")
        logger.info("   pip install -r requirements.txt")

def find_clamav_files(start_path):
    """递归搜索ClamAV文件"""
    required_files = {
        'clamd.exe': None,
        'freshclam.exe': None,
        'clamd.conf': None
    }
    
    for root, dirs, files in os.walk(start_path):
        for file in files:
            if file in required_files and required_files[file] is None:
                required_files[file] = os.path.join(root, file)
                logger.info(f"找到{file}: {required_files[file]}")
    
    return required_files

def setup_clamav():
    """设置ClamAV环境"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        clamav_dir = os.path.join(current_dir, 'ClamAV')
        
        # 如果目标目录不存在，创建它
        if not os.path.exists(clamav_dir):
            os.makedirs(clamav_dir)
            logger.info(f"创建ClamAV目录: {clamav_dir}")
        
        # 创建必要的子目录
        subdirs = ['database', 'logs', 'temp']
        for subdir in subdirs:
            dir_path = os.path.join(clamav_dir, subdir)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                logger.info(f"创建目录: {dir_path}")
        
        # 递归搜索源文件
        source_paths = [
            os.path.join(current_dir, 'clamav'),
            os.path.join(current_dir, 'Clamav'),
            os.path.join(current_dir, 'ClamAV')
        ]
        
        found_files = {}
        for path in source_paths:
            if os.path.exists(path):
                found_files = find_clamav_files(path)
                if all(found_files.values()):  # 如果所有文件都找到了
                    break
        
        if not all(found_files.values()):
            missing = [f for f, p in found_files.items() if p is None]
            logger.error(f"未找到以下ClamAV文件: {', '.join(missing)}")
            return False
        
        # 复制文件到目标目录
        for file_name, file_path in found_files.items():
            dst = os.path.join(clamav_dir, file_name)
            if not os.path.exists(dst):
                shutil.copy2(file_path, dst)
                logger.info(f"复制文件: {file_name}")
        
        # 复制其他必要文件（dll等）
        for file_path in found_files.values():
            source_dir = os.path.dirname(file_path)
            for file in os.listdir(source_dir):
                if file.endswith('.dll'):
                    src = os.path.join(source_dir, file)
                    dst = os.path.join(clamav_dir, file)
                    if not os.path.exists(dst):
                        shutil.copy2(src, dst)
                        logger.info(f"复制依赖文件: {file}")
        
        # 创建freshclam配置文件
        freshclam_conf = os.path.join(clamav_dir, 'freshclam.conf')
        if not os.path.exists(freshclam_conf):
            with open(freshclam_conf, 'w') as f:
                f.write(f"""DatabaseDirectory {os.path.join(clamav_dir, 'database')}
LogFileMaxSize 2M
LogTime yes
PidFile {os.path.join(clamav_dir, 'temp', 'freshclam.pid')}
DatabaseOwner {os.getenv('USERNAME')}
UpdateLogFile {os.path.join(clamav_dir, 'logs', 'freshclam.log')}
DatabaseMirror database.clamav.net
ConnectTimeout 30
ReceiveTimeout 30
TestDatabases yes
ScriptedUpdates yes
NotifyClamd {os.path.join(clamav_dir, 'clamd.conf')}
SafeBrowsing yes
Bytecode yes""")
            logger.info("创建freshclam配置文件")
        
        # 修改clamd配置文件
        clamd_conf = os.path.join(clamav_dir, 'clamd.conf')
        with open(clamd_conf, 'w') as f:
            f.write(f"""LogFile {os.path.join(clamav_dir, 'logs', 'clamd.log')}
LogFileMaxSize 2M
LogTime yes
PidFile {os.path.join(clamav_dir, 'temp', 'clamd.pid')}
TemporaryDirectory {os.path.join(clamav_dir, 'temp')}
DatabaseDirectory {os.path.join(clamav_dir, 'database')}
LocalSocket {os.path.join(clamav_dir, 'temp', 'clamd.socket')}
TCPSocket 3310
TCPAddr localhost
MaxDirectoryRecursion 20
FollowDirectorySymlinks yes
FollowFileSymlinks yes
ReadTimeout 180
MaxThreads 12
MaxConnectionQueueLength 15
LogSyslog no
LogRotate yes
StreamMaxLength 25M
SelfCheck 3600
DetectPUA yes
ScanPE yes
DisableCertCheck yes
ScanELF yes
AlertBrokenExecutables yes
ScanOLE2 yes
ScanPDF yes
ScanHTML yes
ScanMail yes
ScanArchive yes""")
            logger.info("更新clamd配置文件")
        
        return True
    except Exception as e:
        logger.error(f"设置ClamAV环境失败: {str(e)}")
        return False

def check_dependencies():
    """检查必要的依赖是否已安装"""
    missing_deps = []

    # 检查ADB和AAPT
    need_platform_tools = False
    for tool in ['adb', 'aapt']:
        if not platform_tools.is_tool_available(tool):
            need_platform_tools = True
            break

    if need_platform_tools:
        logger.info("未找到 Android SDK Platform Tools，正在自动下载...")
        if not platform_tools.download_and_install():
            missing_deps.append('Android SDK Platform Tools')
    
    # 检查并安装Python依赖
    required_packages = [
        'aiohttp',
        'fastapi',
        'uvicorn',
        'python-dotenv',
        'psutil',
        'pyclamd'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logger.info(f"正在安装缺失的Python包: {', '.join(missing_packages)}")
        if not install_python_dependencies():
            missing_deps.extend([f"Python包: {pkg}" for pkg in missing_packages])

    # 设置ClamAV环境
    if not setup_clamav():
        missing_deps.append('ClamAV未正确配置')
    elif not check_clamav_service():
        missing_deps.append('ClamAV服务未运行')

    if missing_deps:
        logger.error("缺少以下依赖:")
        for dep in missing_deps:
            logger.error(f"- {dep}")
        return False
    
    # 将工具目录添加到PATH
    platform_tools.check_and_add_to_path()
    return True

def init_directories():
    """初始化必要的目录结构"""
    logger.info("正在初始化目录结构...")
    
    dirs = [
        'data/virus_db',      # 病毒库目录
        'data/logs',          # 日志目录
        'data/temp',          # 临时文件目录
        'tools/platform-tools' # Android工具目录
    ]
    
    for dir_path in dirs:
        path = Path(dir_path)
        if not path.exists():
            path.mkdir(parents=True)
            logger.info(f"创建目录: {dir_path}")

def init_environment():
    """初始化环境变量"""
    logger.info("正在初始化环境变量...")
    
    if not os.path.exists('.env'):
        logger.info("创建默认.env文件...")
        default_env = """
# API设置
API_HOST=localhost
API_PORT=8000
DEBUG_MODE=False

# 病毒库设置
AUTO_UPDATE=True
UPDATE_INTERVAL=86400  # 24小时

# 日志设置
LOG_LEVEL=INFO
MAX_LOG_SIZE=10485760  # 10MB
MAX_LOG_FILES=5

# ClamAV设置
CLAMD_HOST=localhost
CLAMD_PORT=3310
"""
        with open('.env', 'w') as f:
            f.write(default_env.strip())

def main():
    try:
        # 检查系统要求
        if not check_system_requirements():
            sys.exit(1)
        
        # 初始化目录
        init_directories()
        
        # 初始化环境
        init_environment()
        
        # 加载环境变量
        load_dotenv()
        
        # 检查依赖
        logger.info("正在检查依赖...")
        if not check_dependencies():
            logger.error("请安装缺少的依赖后重试")
            sys.exit(1)
        
        # 启动后端服务
        logger.info("正在启动后端服务...")
        from backend.main import run_as_api
        run_as_api()
        
    except Exception as e:
        logger.error(f"启动失败: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 