import os
import hashlib
import subprocess
import asyncio
import json
from datetime import datetime, timedelta
import aiohttp
import clamd
from typing import Dict, List
import tempfile
import time
from ..utils.config_loader import ConfigLoader
from ..utils.logger import logger
from .virus_db_updater import VirusDBUpdater
from ..utils.platform_tools import PlatformTools
from .log_manager import LogManager
from .memory_cleaner import MemoryCleaner
from .virus_cleaner import VirusCleaner

class VirusScanner:
    def __init__(self):
        self.virus_total_api_key = ConfigLoader.get_virus_total_api_key()
        self.scan_status = {}
        self.vt_requests = []
        self.max_requests_per_minute = 4
        self.max_requests_per_day = 500
        self.clam = None
        self.db_updater = VirusDBUpdater()
        self.platform_tools = PlatformTools()
        self.is_windows = os.name == 'nt'
        self.log_manager = LogManager()
        self.memory_cleaner = MemoryCleaner()
        self.virus_cleaner = VirusCleaner()
        self._init_clamav()
        self.clamav_last_check = datetime.now()
        self.clamav_check_interval = timedelta(minutes=5)
        self.scan_stats = {
            'total_files': 0,
            'scanned_files': 0,
            'suspicious_files': 0,
            'high_risk_files': 0
        }
        self.scan_history = {}  # 存储扫描历史
        self.paused_scans = set()  # 存储已暂停的扫描

    def _ensure_log_directory(self):
        pass

    async def get_logs(self, start_time: str = None, end_time: str = None, 
                      level: str = None, limit: int = 1000) -> List[Dict]:
        return await self.log_manager.get_logs(start_time=start_time, 
                                             end_time=end_time,
                                             level=level,
                                             limit=limit)

    async def clear_logs(self) -> bool:
        return await self.log_manager.clear_logs()

    async def get_log_stats(self) -> Dict:
        return await self.log_manager.get_log_stats()

    def _init_clamav(self):
        """初始化ClamAV连接"""
        try:
            if self.is_windows:
                # Windows下尝试TCP连接
                clamav_paths = [
                    'clamav',  # 相对路径
                    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'clamav'),  # 项目根目录下
                    os.path.abspath('clamav'),  # 绝对路径
                    r'C:\Program Files\ClamAV',
                    r'C:\ClamAV'
                ]
                
                # 记录找到的ClamAV路径
                found_path = None
                for path in clamav_paths:
                    if os.path.exists(path):
                        found_path = path
                        self.log_manager.log('INFO', f"找到ClamAV安装路径: {path}")
                        break
                
                if not found_path:
                    self.log_manager.log('ERROR', "未找到ClamAV安装路径")
                    self.clam = None
                    return
                
                # 设置ClamAV环境
                clamd_conf = os.path.join(found_path, 'clamd.conf')
                if not os.path.exists(clamd_conf):
                    # 创建基本的配置文件
                    with open(clamd_conf, 'w') as f:
                        f.write("TCPSocket 3310\nTCPAddr localhost\n")
                
                os.environ['CLAMD_CONF'] = clamd_conf
                
                try:
                    # 尝试启动clamd服务
                    clamd_path = os.path.join(found_path, 'clamd.exe')
                    if os.path.exists(clamd_path):
                        try:
                            # 检查服务是否已经运行
                            subprocess.run(['tasklist', '/FI', 'IMAGENAME eq clamd.exe'], 
                                        capture_output=True, text=True)
                            
                            # 如果服务未运行，则启动它
                            subprocess.Popen([clamd_path], 
                                          creationflags=subprocess.CREATE_NO_WINDOW,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
                            
                            # 等待服务启动
                            time.sleep(2)
                            self.log_manager.log('INFO', "已启动ClamAV服务")
                        except Exception as start_error:
                            self.log_manager.log('WARNING', f"启动ClamAV服务失败: {start_error}")
                    
                    # 尝试TCP连接
                    self.clam = clamd.ClamdNetworkSocket(host='localhost', port=3310)
                    self.clam.ping()
                    self.log_manager.log('INFO', "成功通过TCP连接到ClamAV")
                    return
                    
                except Exception as tcp_error:
                    self.log_manager.log('WARNING', f"TCP连接ClamAV失败: {tcp_error}")
                    self.clam = None
            else:
                # Unix系统尝试Unix socket
                socket_paths = [
                    '/var/run/clamav/clamd.ctl',
                    '/var/run/clamd.scan/clamd.sock',
                    '/run/clamav/clamd.ctl',
                    '/tmp/clamd.socket'
                ]
                
                for socket_path in socket_paths:
                    try:
                        if os.path.exists(socket_path):
                            self.clam = clamd.ClamdUnixSocket(socket_path)
                            self.clam.ping()
                            self.log_manager.log('INFO', f"成功通过Unix socket连接到ClamAV: {socket_path}")
                            return
                    except Exception as unix_error:
                        self.log_manager.log('WARNING', f"Unix socket连接失败 {socket_path}: {unix_error}")
                
                # 如果Unix socket都失败，尝试TCP连接
                try:
                    self.clam = clamd.ClamdNetworkSocket()
                    self.clam.ping()
                    self.log_manager.log('INFO', "成功通过TCP连接到ClamAV")
                    return
                except Exception as tcp_error:
                    self.log_manager.log('WARNING', f"TCP连接失败: {tcp_error}")
            
            self.log_manager.log('ERROR', "所有ClamAV连接方式都失败")
            self.clam = None
            
        except Exception as e:
            self.log_manager.log('ERROR', f"初始化ClamAV时出错: {e}")
            self.clam = None

    async def start_scan(self, device_id: str, scan_params: Dict = None):
        """开始扫描设备"""
        try:
            # 首先检查设备是否连接
            if not await self._check_device_connected(device_id):
                return {
                    'status': 'error',
                    'error': f'设备 {device_id} 未连接',
                    'scanned_files': 0,
                    'total_files': 0,
                    'scanned_apps': 0,
                    'total_apps': 0,
                    'found_threats': []
                }

            self.scan_status[device_id] = {
                'status': 'scanning',
                'progress': 0,
                'found_threats': [],
                'scanned_files': 0,
                'total_files': 0,
                'scanned_apps': 0,
                'total_apps': 0,
                'start_time': datetime.now().isoformat(),
                'current_path': None
            }
            
            self.log_manager.log('INFO', "开始扫描设备...")
            
            # 检查是否提供了文件列表
            provided_files = []
            if scan_params and 'file_list' in scan_params:
                provided_files = scan_params['file_list']
                self.log_manager.log('INFO', f"收到 {len(provided_files)} 个文件待扫描")
            
            # 检查设备是否已root
            has_root = await self._check_root_access(device_id)
            self.log_manager.log('INFO', f"设备root状态: {'已root' if has_root else '未root'}")
            
            # 扫描已安装的应用
            if not scan_params or scan_params.get('scan_apps', True):
                await self._scan_installed_apps(device_id)
            
            # 如果没有提供文件列表，则扫描文件系统
            if not provided_files:
                all_files = await self._scan_filesystem(device_id)
            else:
                all_files = provided_files
            
            # 更新总文件数
            self.scan_status[device_id]['total_files'] = len(all_files)
            self.log_manager.log('INFO', f"总共有 {len(all_files)} 个文件待扫描")
            
            # 扫描所有文件
            for file_path in all_files:
                try:
                    await self._scan_file(device_id, file_path)
                    self.scan_status[device_id]['scanned_files'] += 1
                    self.scan_status[device_id]['progress'] = (
                        (self.scan_status[device_id]['scanned_files'] + self.scan_status[device_id]['scanned_apps']) / 
                        (self.scan_status[device_id]['total_files'] + self.scan_status[device_id]['total_apps']) * 100
                    )
                    self.log_manager.log('DEBUG', f"完成扫描文件: {file_path}")
                except Exception as e:
                    self.log_manager.log('ERROR', f"扫描文件 {file_path} 时出错: {str(e)}")
            
            self.scan_status[device_id]['status'] = 'completed'
            self.scan_status[device_id]['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            self.scan_status[device_id]['status'] = 'error'
            self.scan_status[device_id]['error'] = str(e)
            self.log_manager.log('ERROR', f"扫描设备 {device_id} 时出错: {e}")
        
        return self.scan_status[device_id]

    async def _check_device_connected(self, device_id: str) -> bool:
        """检查设备是否已连接"""
        try:
            result = subprocess.run(
                [self.platform_tools.adb_path, "devices"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=5
            )
            
            if result.returncode != 0:
                self.log_manager.log('ERROR', f"检查设备连接状态失败: {result.stderr}")
                return False
            
            # 解析设备列表
            devices = []
            for line in result.stdout.splitlines()[1:]:  # 跳过第一行的"List of devices attached"
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        devices.append(parts[0])
            
            is_connected = device_id in devices
            if not is_connected:
                self.log_manager.log('ERROR', f"设备 {device_id} 未连接")
            else:
                self.log_manager.log('INFO', f"设备 {device_id} 已连接")
            
            return is_connected
            
        except Exception as e:
            self.log_manager.log('ERROR', f"检查设备连接状态时出错: {e}")
            return False

    async def _scan_filesystem(self, device_id: str) -> List[str]:
        """扫描文件系统"""
        if not await self._check_device_connected(device_id):
            self.log_manager.log('ERROR', f"设备 {device_id} 未连接，无法扫描文件系统")
            return []

        self.log_manager.log('INFO', "开始扫描文件系统...")
        
        storage_paths = [
            "/storage/emulated/0/Download",  # 优先扫描下载目录
            "/storage/emulated/0/Documents",
            "/storage/emulated/0",
            "/storage/emulated/0/DCIM",
            "/storage/emulated/0/Pictures",
            "/sdcard",
            "/storage/self/primary"
        ]

        has_root = await self._check_root_access(device_id)
        if has_root:
            storage_paths.extend([
                "/data/app",
                "/data/local/tmp",
                "/system/app",
                "/system/priv-app"
            ])

        all_files = []
        filtered_files = []
        suspicious_files = []
        
        for path in storage_paths:
            try:
                if not await self._check_device_connected(device_id):
                    self.log_manager.log('ERROR', f"设备连接已断开，停止扫描")
                    break

                self.scan_status[device_id]['current_path'] = path
                self.log_manager.log('INFO', f"扫描目录: {path}")
                
                # 检查目录是否存在
                check_dir = subprocess.run(
                    [self.platform_tools.adb_path, "-s", device_id, "shell", f"ls {path}"],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore',
                    timeout=5
                )
                
                if check_dir.returncode != 0:
                    self.log_manager.log('WARNING', f"目录不存在或无法访问: {path}")
                    continue

                # 使用find命令获取所有文件
                cmd = f"find {path} -type f"
                
                if has_root:
                    cmd = f"su -c '{cmd}'"
                
                result = subprocess.run(
                    [self.platform_tools.adb_path, "-s", device_id, "shell", cmd],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore',
                    timeout=30
                )
                
                if result.returncode == 0 and result.stdout:
                    files = [f for f in result.stdout.splitlines() if f and not f.startswith("find:")]
                    all_files.extend(files)
                    
                    # 分类文件
                    for file in files:
                        if self._is_suspicious_file(file):
                            suspicious_files.append(file)
                            filtered_files.append(file)
                        elif self._should_scan_file(file):
                            filtered_files.append(file)
                    
            except subprocess.TimeoutExpired:
                self.log_manager.log('WARNING', f"扫描目录超时: {path}")
            except Exception as e:
                self.log_manager.log('ERROR', f"扫描目录 {path} 时出错: {str(e)}")
        
        # 更新扫描统计
        self.scan_stats['total_files'] = len(all_files)
        self.scan_stats['suspicious_files'] = len(suspicious_files)
        
        self.log_manager.log('INFO', f"总共找到 {len(all_files)} 个文件")
        self.log_manager.log('INFO', f"需要扫描的文件: {len(filtered_files)}")
        self.log_manager.log('WARNING', f"可疑文件: {len(suspicious_files)}")
        
        return filtered_files

    async def _scan_file(self, device_id: str, file_path: str):
        """扫描单个文件"""
        try:
            self.log_manager.log('INFO', f"正在扫描文件: {file_path}")
            
            # 快速过滤：跳过明显的缓存文件和临时文件
            if any(keyword in file_path.lower() for keyword in ['/cache/', '/temp/', '/tmp/']):
                self.log_manager.log('INFO', f"跳过缓存文件: {file_path}")
                return
            
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                local_path = os.path.join(temp_dir, os.path.basename(file_path))
                
                # 提取文件
                try:
                    pull_result = subprocess.run(
                        [self.platform_tools.adb_path, "-s", device_id, "pull", file_path, local_path],
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=10
                    )
                    
                    if not os.path.exists(local_path):
                        self.log_manager.log('WARNING', f"无法提取文件: {file_path}")
                        return
                    
                    # 检查文件大小
                    file_size = os.path.getsize(local_path)
                    if file_size == 0:
                        self.log_manager.log('INFO', f"跳过空文件: {file_path}")
                        return
                    if file_size > 50 * 1024 * 1024:  # 50MB
                        self.log_manager.log('INFO', f"跳过大文件: {file_path} ({file_size/1024/1024:.2f}MB)")
                        return
                    
                    # 计算MD5
                    md5_hash = self._calculate_md5(local_path)
                    
                    # 基本威胁检测
                    threat_found = False
                    threat_info = {
                        'file_path': file_path,
                        'md5': md5_hash,
                        'file_size': file_size,
                        'detection_time': datetime.now().isoformat(),
                        'threat_details': []
                    }
                    
                    # 1. 检查MD5黑名单
                    blacklist = self.db_updater.get_md5_blacklist()
                    if md5_hash in blacklist:
                        threat_info['threat_details'].append({
                            'type': 'md5_blacklist',
                            'details': blacklist[md5_hash]
                        })
                        threat_found = True
                    
                    # 2. 使用ClamAV扫描
                    try:
                        # 确保ClamAV服务运行
                        await self._ensure_clamav_running()
                        
                        if self.clam:
                            self.log_manager.log('INFO', f"使用ClamAV扫描文件: {file_path}")
                            clam_result = await self._scan_with_clamav(local_path)
                            if clam_result['status'] == 'threat_found':
                                threat_info['threat_details'].append({
                                    'type': 'clamav',
                                    'details': clam_result['threat_type']
                                })
                                threat_found = True
                                self.log_manager.log('WARNING', f"ClamAV发现威胁: {clam_result['threat_type']}")
                        else:
                            self.log_manager.log('WARNING', "ClamAV服务不可用，跳过ClamAV扫描")
                    except Exception as e:
                        self.log_manager.log('ERROR', f"ClamAV扫描失败: {e}")
                    
                    # 3. 检查文件特征
                    if await self._is_high_risk_file(local_path):
                        # 使用VirusTotal进行深度扫描
                        vt_result = await self._scan_with_virustotal(local_path)
                        if vt_result['status'] == 'threat_found':
                            threat_info['threat_details'].append({
                                'type': 'virustotal',
                                'details': {
                                    'threat_type': vt_result['threat_type'],
                                    'detection_ratio': vt_result['detection_ratio']
                                }
                            })
                            threat_found = True
                            # 添加到黑名单
                            self.db_updater.add_to_md5_blacklist(md5_hash, vt_result)
                    
                    # 4. 检查文件内容的可疑特征
                    suspicious_features = await self._check_file_content(local_path)
                    if suspicious_features:
                        threat_info['threat_details'].append({
                            'type': 'suspicious_content',
                            'details': suspicious_features
                        })
                        threat_found = True
                    
                    # 如果发现威胁，添加到结果中
                    if threat_found:
                        self._add_threat(device_id, file_path, 'multiple_scanners', threat_info)
                        self.log_manager.log('WARNING', f"发现威胁: {file_path}")
                    
                except subprocess.TimeoutExpired:
                    self.log_manager.log('WARNING', f"提取文件超时: {file_path}")
                except Exception as e:
                    self.log_manager.log('ERROR', f"处理文件失败: {file_path} - {e}")
                
        except Exception as e:
            self.log_manager.log('ERROR', f"扫描文件 {file_path} 时出错: {e}")

    async def _scan_installed_apps(self, device_id: str):
        """扫描已安装的应用"""
        self.log_manager.log('INFO', "扫描已安装应用...")
        
        # 使用不同的命令获取应用列表
        cmd_list = [
            f"{self.platform_tools.adb_path} -s {device_id} shell cmd package list packages -f -3",
            f"{self.platform_tools.adb_path} -s {device_id} shell pm list packages -f -3",
            f"{self.platform_tools.adb_path} -s {device_id} shell pm list packages -f"
        ]
        
        apps = []
        for cmd in cmd_list:
            try:
                result = subprocess.run(
                    cmd.split(),
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore'
                )
                
                if result.returncode == 0 and result.stdout:
                    self.log_manager.log('INFO', f"成功使用命令获取应用列表: {cmd}")
                    for line in result.stdout.split('\n'):
                        if '=' in line:
                            try:
                                path = line.split('=')[0].replace('package:', '').strip()
                                package = line.split('=')[1].strip()
                                if path and package:
                                    apps.append({
                                        'path': path,
                                        'package': package
                                    })
                            except Exception as e:
                                self.log_manager.log('ERROR', f"解析应用信息时出错: {line} - {str(e)}")
                    break
            except Exception as e:
                self.log_manager.log('ERROR', f"执行命令出错: {cmd} - {str(e)}")
                continue
        
        self.scan_status[device_id]['total_apps'] = len(apps)
        self.log_manager.log('INFO', f"找到 {len(apps)} 个已安装应用")
        
        # 扫描所有应用
        for app in apps:
            try:
                await self._scan_app(device_id, app['package'], app['path'])
                self.scan_status[device_id]['scanned_apps'] += 1
                self.log_manager.log('INFO', f"完成扫描应用: {app['package']}")
            except Exception as e:
                self.log_manager.log('ERROR', f"扫描应用时出错: {app['package']} - {str(e)}")

    async def _check_file_content(self, file_path: str) -> List[str]:
        """检查文件内容中的可疑特征"""
        suspicious_features = []
        try:
            # 读取文件内容
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # 检查可执行文件特征
            if content.startswith(b'MZ') or content.startswith(b'ELF'):
                suspicious_features.append('executable_header')
            
            # 检查脚本特征
            script_patterns = [
                (b'#!/bin/sh', 'shell_script'),
                (b'#!/bin/bash', 'bash_script'),
                (b'import os;', 'python_script'),
                (b'<?php', 'php_script'),
                (b'<script>', 'javascript')
            ]
            
            for pattern, feature in script_patterns:
                if pattern in content:
                    suspicious_features.append(feature)
            
            # 检查危险函数调用
            dangerous_patterns = [
                (b'system(', 'system_call'),
                (b'exec(', 'exec_call'),
                (b'eval(', 'eval_usage'),
                (b'shell_exec', 'shell_exec_usage'),
                (b'chmod +x', 'chmod_execution'),
                (b'rm -rf', 'dangerous_deletion'),
                (b'sudo ', 'sudo_usage')
            ]
            
            for pattern, feature in dangerous_patterns:
                if pattern in content:
                    suspicious_features.append(feature)
            
            return suspicious_features
        except Exception as e:
            self.log_manager.log('ERROR', f"检查文件内容时出错: {e}")
            return []

    def _add_threat(self, device_id: str, file_path: str, source: str, info: Dict):
        """添加威胁记录"""
        threat = {
            'file_path': file_path,
            'source': source,
            'info': info,
            'time': datetime.now().isoformat(),
            'threat_score': self._calculate_threat_score(info.get('threat_details', []))
        }
        
        if device_id not in self.scan_status:
            self.scan_status[device_id] = {
                'found_threats': []
            }
        if 'found_threats' not in self.scan_status[device_id]:
            self.scan_status[device_id]['found_threats'] = []
        
        self.scan_status[device_id]['found_threats'].append(threat)
        self.log_manager.log('WARNING', f"添加威胁记录: {file_path} - {source} (威胁评分: {threat['threat_score']})")

    def _calculate_md5(self, file_path: str) -> str:
        """计算文件MD5值"""
        md5_hash = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()

    async def _scan_with_clamav(self, file_path: str) -> Dict:
        """使用ClamAV扫描文件"""
        await self._ensure_clamav_running()

        try:
            # 确保文件存在且可读
            if not os.path.exists(file_path):
                self.log_manager.log('ERROR', f"文件不存在: {file_path}")
                return {
                    'status': 'error',
                    'error': 'File not found'
                }
                
            # 检查文件大小
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                self.log_manager.log('INFO', f"跳过空文件: {file_path}")
                return {
                    'status': 'error',
                    'error': 'Empty file'
                }
            
            if file_size > 100 * 1024 * 1024:  # 100MB
                self.log_manager.log('INFO', f"跳过大文件: {file_path}")
                return {
                    'status': 'error',
                    'error': 'File too large'
                }

            # 执行扫描，添加超时控制
            try:
                # 创建异步任务
                loop = asyncio.get_event_loop()
                scan_future = loop.run_in_executor(None, self.clam.scan_file, file_path)
                result = await asyncio.wait_for(scan_future, timeout=30)
                
                self.log_manager.log('INFO', f"ClamAV扫描结果: {result}")
                
                if result:
                    if isinstance(result, dict):
                        if file_path in result:
                            status, signature = result[file_path]
                        else:
                            status, signature = next(iter(result.values()))
                    else:
                        status, signature = result
                        
                    if status == 'OK':
                        return {'status': 'clean'}
                    elif status == 'FOUND':
                        return {
                            'status': 'threat_found',
                            'threat_type': signature
                        }
                    
                return {
                    'status': 'error',
                    'error': 'Invalid scan result'
                }
                
            except asyncio.TimeoutError:
                self.log_manager.log('WARNING', f"ClamAV扫描超时: {file_path}")
                return {
                    'status': 'error',
                    'error': 'Scan timeout'
                }
            except Exception as scan_error:
                self.log_manager.log('ERROR', f"ClamAV扫描出错: {scan_error}")
                return {
                    'status': 'error',
                    'error': f'Scan failed: {str(scan_error)}'
                }
                
        except Exception as e:
            self.log_manager.log('ERROR', f"ClamAV扫描过程出错: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    async def _scan_with_virustotal(self, file_path: str) -> Dict:
        """使用VirusTotal扫描文件"""
        if not self._can_make_vt_request():
            return {'status': 'rate_limited'}
        
        try:
            # 上传文件
            async with aiohttp.ClientSession() as session:
                files = {'file': open(file_path, 'rb')}
                headers = {'apikey': self.virus_total_api_key}
                async with session.post('https://www.virustotal.com/vtapi/v2/file/scan',
                                    data=files, headers=headers) as response:
                    scan_result = await response.json()
                
                # 记录请求
                self._record_vt_request()
                
                # 等待分析完成
                resource = scan_result['scan_id']
                await asyncio.sleep(15)  # 等待分析
                
                # 获取报告
                params = {'apikey': self.virus_total_api_key, 'resource': resource}
                async with session.get('https://www.virustotal.com/vtapi/v2/file/report',
                                    params=params) as response:
                    report = await response.json()
                
                self._record_vt_request()
                
                if report['positives'] > 0:
                    return {
                        'status': 'threat_found',
                        'threat_type': 'malware',
                        'detection_ratio': f"{report['positives']}/{report['total']}"
                    }
                return {'status': 'clean'}
                
        except Exception as e:
            self.log_manager.log('ERROR', f"VirusTotal扫描出错: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def _can_make_vt_request(self) -> bool:
        """检查是否可以发送VirusTotal请求"""
        now = datetime.now()
        
        # 清理旧请求记录
        self.vt_requests = [t for t in self.vt_requests 
                          if t > now - timedelta(minutes=1)]
        
        # 检查频率限制
        if len(self.vt_requests) >= self.max_requests_per_minute:
            return False
        
        # 检查每日限制
        daily_requests = len([t for t in self.vt_requests 
                            if t > now - timedelta(days=1)])
        if daily_requests >= self.max_requests_per_day:
            return False
        
        return True

    def _record_vt_request(self):
        """记录VirusTotal请求"""
        self.vt_requests.append(datetime.now())

    async def _is_high_risk_file(self, file_path: str) -> bool:
        """判断文件是否高风险"""
        try:
            # 检查文件扩展名
            ext = os.path.splitext(file_path)[1].lower()
            high_risk_exts = {'.exe', '.dll', '.sys', '.apk', '.dex', '.so'}
            if ext in high_risk_exts:
                return True
            
            # 读取文件头部来判断文件类型
            with open(file_path, 'rb') as f:
                header = f.read(4096)
                
            # 检查是否是可执行文件
            if header.startswith(b'MZ') or header.startswith(b'ELF'):
                return True
                
            # 检查是否包含可疑特征
            suspicious_patterns = [
                b'powershell',
                b'cmd.exe',
                b'shell_exec',
                b'eval(',
                b'system(',
                b'exec(',
                b'chmod +x'
            ]
            
            return any(pattern in header.lower() for pattern in suspicious_patterns)
            
        except Exception as e:
            self.log_manager.log('ERROR', f"检查文件风险等级时出错: {e}")
            return False

    async def _scan_app(self, device_id: str, package_name: str, app_path: str):
        """扫描单个应用"""
        try:
            self.log_manager.log('INFO', f"正在扫描应用: {package_name}")
            
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                apk_path = os.path.join(temp_dir, f"{package_name}.apk")
                
                # 提取APK文件
                pull_result = subprocess.run(
                    [self.platform_tools.adb_path, "-s", device_id, "pull", app_path, apk_path],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore'
                )
                self.log_manager.log('INFO', f"提取APK结果: {pull_result.stdout}")
                
                if not os.path.exists(apk_path):
                    self.log_manager.log('WARNING', f"无法提取应用: {package_name}, 路径: {app_path}")
                    return
                
                # 计算MD5
                md5_hash = self._calculate_md5(apk_path)
                self.log_manager.log('INFO', f"应用 {package_name} 的MD5: {md5_hash}")
                
                # 检查MD5是否在黑名单中
                blacklist = self.db_updater.get_md5_blacklist()
                if md5_hash in blacklist:
                    self._add_threat(device_id, package_name, 'md5_blacklist', blacklist[md5_hash])
                    return
                
                # 检查APK是否可疑
                if await self._is_suspicious_apk(apk_path):
                    vt_result = await self._scan_with_virustotal(apk_path)
                    if vt_result['status'] == 'threat_found':
                        threat_info = {
                            'package_name': package_name,
                            'md5': md5_hash,
                            'threat_type': vt_result['threat_type'],
                            'detection_ratio': vt_result['detection_ratio']
                        }
                        self._add_threat(device_id, package_name, 'virustotal', threat_info)
                        self.db_updater.add_to_md5_blacklist(md5_hash, threat_info)
                
        except Exception as e:
            self.log_manager.log('ERROR', f"扫描应用 {package_name} 时出错: {e}")

    async def _is_suspicious_apk(self, apk_path: str) -> bool:
        """分析APK文件是否可疑"""
        try:
            # 检查文件是否存在
            if not os.path.exists(apk_path):
                self.log_manager.log('ERROR', f"APK文件不存在: {apk_path}")
                return False

            # 检查文件大小
            file_size = os.path.getsize(apk_path)
            if file_size == 0:
                self.log_manager.log('WARNING', f"APK文件为空: {apk_path}")
                return False

            # 尝试使用aapt分析APK
            aapt_path = os.path.join(os.path.dirname(self.platform_tools.adb_path), 'aapt.exe')
            if not os.path.exists(aapt_path):
                self.log_manager.log('WARNING', f"aapt工具不存在: {aapt_path}")
                return False

            result = subprocess.run([aapt_path, 'd', 'permissions', apk_path],
                                capture_output=True,
                                text=True,
                                encoding='utf-8',
                                errors='ignore')
            
            if result.returncode != 0:
                self.log_manager.log('ERROR', f"aapt分析失败: {result.stderr}")
                return False

            permissions = result.stdout.split('\n')
            
            # 定义可疑权限列表
            suspicious_permissions = [
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS',
                'android.permission.RECEIVE_SMS',
                'android.permission.READ_CONTACTS',
                'android.permission.RECORD_AUDIO',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.READ_PHONE_STATE',
                'android.permission.CAMERA',
                'android.permission.CALL_PHONE',
                'android.permission.GET_ACCOUNTS'
            ]
            
            # 检查是否使用了可疑权限
            suspicious_count = sum(1 for p in permissions 
                                if any(sp in p for sp in suspicious_permissions))
            
            if suspicious_count >= 3:
                self.log_manager.log('WARNING', f"发现可疑APK，使用了 {suspicious_count} 个敏感权限")
                return True
                
            return False
            
        except Exception as e:
            self.log_manager.log('ERROR', f"分析APK时出错: {e}")
            return False

    def get_status(self) -> Dict:
        """获取扫描状态"""
        return self.scan_status 

    def get_scan_result(self, device_id: str) -> Dict:
        """获取扫描结果"""
        if device_id not in self.scan_status:
            return {
                "status": "not_found",
                "error": "No scan results found for this device"
            }
        
        result = self.scan_status[device_id].copy()
        
        # 添加扫描统计信息
        result['scan_summary'] = {
            'total_files_scanned': result.get('scanned_files', 0),
            'total_apps_scanned': result.get('scanned_apps', 0),
            'total_threats_found': len(result.get('found_threats', [])),
            'scan_duration': None
        }
        
        # 计算扫描持续时间
        if 'start_time' in result and 'end_time' in result:
            start = datetime.fromisoformat(result['start_time'])
            end = datetime.fromisoformat(result['end_time'])
            result['scan_summary']['scan_duration'] = str(end - start)
        
        # 整理威胁信息
        result['threats'] = []
        for threat in result.get('found_threats', []):
            threat_info = {
                'file_path': threat['file_path'],
                'detection_source': threat['source'],
                'detection_time': threat['time'],
                'threat_details': threat['info'].get('threat_details', []),
                'md5': threat['info'].get('md5', ''),
                'file_size': threat['info'].get('file_size', 0)
            }
            result['threats'].append(threat_info)
        
        return result

    def _scan_directory(self, directory):
        """递归扫描目录"""
        try:
            for root, dirs, files in os.walk(directory):
                # 跳过系统目录
                if any(skip in root.lower() for skip in ['windows\\system32', 'windows\\syswow64', '$recycle.bin', 'system volume information']):
                    continue

                # 扫描文件
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        # 只扫描特定类型的文件
                        if file.lower().endswith(('.exe', '.dll', '.sys', '.apk', '.zip', '.rar', '.7z', '.pdf', '.doc', '.docx')):
                            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                                self.scan_status['scanned_files'] += 1
                                # 使用ClamAV扫描文件
                                try:
                                    if self.clam.scan_file(file_path):
                                        self.scan_status['threats_found'] += 1
                                except Exception as e:
                                    self.log_manager.log('ERROR', f"扫描文件失败 {file_path}: {str(e)}")
                    except Exception as file_error:
                        self.log_manager.log('ERROR', f"处理文件失败 {file}: {str(file_error)}")
                        continue

        except Exception as dir_error:
            self.log_manager.log('ERROR', f"扫描目录失败 {directory}: {str(dir_error)}")

    async def _check_root_access(self, device_id: str) -> bool:
        """检查设备是否有root权限"""
        try:
            result = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "su -c 'whoami'"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=5
            )
            return result.returncode == 0 and 'root' in result.stdout
        except:
            return False

    def _parse_memory_value(self, value: str) -> int:
        """解析带单位的内存值
        
        Args:
            value: 带单位的内存值字符串 (例如: '7827800K', '1.5G')
            
        Returns:
            int: 转换后的字节数
        """
        try:
            # 移除所有空白字符
            value = value.strip()
            
            # 如果是纯数字，直接返回
            if value.isdigit():
                return int(value)
            
            # 提取数字部分和单位部分
            number = ''
            unit = ''
            for char in value:
                if char.isdigit() or char == '.':
                    number += char
                else:
                    unit += char.upper()
            
            # 转换为浮点数
            number = float(number)
            
            # 根据单位进行转换
            unit_multipliers = {
                'K': 1024,
                'KB': 1024,
                'M': 1024 * 1024,
                'MB': 1024 * 1024,
                'G': 1024 * 1024 * 1024,
                'GB': 1024 * 1024 * 1024,
                'T': 1024 * 1024 * 1024 * 1024,
                'TB': 1024 * 1024 * 1024 * 1024
            }
            
            if unit in unit_multipliers:
                return int(number * unit_multipliers[unit])
            
            # 如果没有单位，返回原始值
            return int(number)
            
        except Exception as e:
            self.log_manager.log('ERROR', f"解析内存值失败 '{value}': {str(e)}")
            return 0

    async def _get_device_memory_info(self, device_id: str) -> Dict:
        """获取设备内存信息"""
        try:
            # 获取内存信息
            mem_info = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "cat", "/proc/meminfo"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if mem_info.returncode != 0:
                return {}
            
            memory_stats = {}
            for line in mem_info.stdout.splitlines():
                if ':' in line:
                    key, value = line.split(':')
                    key = key.strip()
                    value = value.strip()
                    if value:  # 只处理有值的行
                        try:
                            # 使用新的解析函数
                            memory_stats[key] = self._parse_memory_value(value)
                        except Exception as e:
                            self.log_manager.log('ERROR', f"解析内存信息时出错: {str(e)}")
                            continue
            
            return memory_stats
            
        except Exception as e:
            self.log_manager.log('ERROR', f"获取设备内存信息时出错: {str(e)}")
            return {} 

    async def _ensure_clamav_running(self):
        """确保ClamAV服务正在运行"""
        now = datetime.now()
        # 每5分钟检查一次服务状态
        if now - self.clamav_last_check > self.clamav_check_interval:
            try:
                if not self.clam:
                    self._init_clamav()
                else:
                    # 测试连接
                    self.clam.ping()
            except Exception as e:
                self.log_manager.log('WARNING', f"ClamAV服务检查失败: {e}")
                # 重新初始化
                self._init_clamav()
            finally:
                self.clamav_last_check = now

        if not self.clam:
            self.log_manager.log('ERROR', "ClamAV服务不可用")
            raise Exception("ClamAV service is not available")

    async def clean_memory(self, device_id: str) -> Dict:
        """清理设备内存"""
        return await self.memory_cleaner.clean_memory(device_id)

    def _calculate_threat_score(self, threat_details: List[Dict]) -> int:
        """计算威胁评分"""
        score = 0
        for detail in threat_details:
            if detail['type'] == 'suspicious_content':
                for feature in detail['details']:
                    if feature in ['eval_usage', 'exec_call']:
                        score += 2
                    elif feature in ['javascript']:
                        score += 1
                    elif feature in ['shell_script', 'python_script']:
                        score += 3
                    elif feature in ['system_call', 'shell_exec_usage']:
                        score += 4
        return score

    def _is_suspicious_file(self, file_path: str) -> bool:
        """判断文件是否可疑"""
        suspicious_patterns = [
            '.js', '.exe', '.dll', '.so', '.apk', '.dex',
            '.sh', '.py', '.php', '.jar', '.bat', '.cmd'
        ]
        return any(file_path.lower().endswith(ext) for ext in suspicious_patterns)

    def _should_scan_file(self, file_path: str) -> bool:
        """判断是否需要扫描该文件"""
        # 始终扫描下载目录中的文件
        if '/Download/' in file_path:
            return True
            
        # 跳过明显的系统文件和缓存
        if any(keyword in file_path.lower() for keyword in ['/cache/', '/temp/', '/tmp/']):
            return False
            
        # 检查文件扩展名
        scan_extensions = {
            '.apk', '.dex', '.so', '.exe', '.dll', '.sys',
            '.sh', '.jar', '.zip', '.rar', '.7z', '.js',
            '.py', '.php', '.html', '.htm', '.pdf',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
        }
        return os.path.splitext(file_path)[1].lower() in scan_extensions 

    async def get_memory_info(self, device_id: str) -> Dict:
        """获取设备内存信息"""
        try:
            # 获取内存信息
            mem_info = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "cat", "/proc/meminfo"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=5
            )
            
            if mem_info.returncode != 0:
                self.log_manager.log('ERROR', f"获取内存信息失败: {mem_info.stderr}")
                return {
                    'error': '获取内存信息失败',
                    'details': mem_info.stderr
                }
            
            memory_stats = {}
            for line in mem_info.stdout.splitlines():
                if ':' in line:
                    key, value = line.split(':')
                    key = key.strip()
                    value = value.strip()
                    if value:  # 只处理有值的行
                        try:
                            # 解析内存值（例如：1234 kB）
                            value_parts = value.split()
                            if len(value_parts) == 2:
                                number = float(value_parts[0])
                                unit = value_parts[1].lower()
                                
                                # 转换为字节
                                if unit == 'kb':
                                    memory_stats[key] = int(number * 1024)
                                elif unit == 'mb':
                                    memory_stats[key] = int(number * 1024 * 1024)
                                elif unit == 'gb':
                                    memory_stats[key] = int(number * 1024 * 1024 * 1024)
                                else:
                                    memory_stats[key] = int(number)
                            else:
                                memory_stats[key] = int(value_parts[0])
                        except Exception as e:
                            self.log_manager.log('ERROR', f"解析内存值时出错 '{value}': {str(e)}")
                            continue
            
            # 添加一些计算值
            if 'MemTotal' in memory_stats and 'MemFree' in memory_stats:
                memory_stats['MemUsed'] = memory_stats['MemTotal'] - memory_stats['MemFree']
                memory_stats['MemUsagePercent'] = round(
                    (memory_stats['MemUsed'] / memory_stats['MemTotal']) * 100, 2
                )
            
            self.log_manager.log('INFO', f"成功获取内存信息: {memory_stats}")
            return memory_stats
            
        except subprocess.TimeoutExpired:
            self.log_manager.log('ERROR', "获取内存信息超时")
            return {'error': '获取内存信息超时'}
        except Exception as e:
            self.log_manager.log('ERROR', f"获取内存信息时出错: {str(e)}")
            return {'error': str(e)} 

    async def clean_threats(self, device_id: str, threats: List[Dict]) -> Dict:
        """清理检测到的威胁"""
        try:
            if not await self._check_device_connected(device_id):
                return {
                    'status': 'error',
                    'error': f'设备 {device_id} 未连接'
                }
            
            # 直接删除文件
            success_count = 0
            failed_count = 0
            results = []
            
            for threat in threats:
                try:
                    file_path = threat['file_path']
                    result = subprocess.run(
                        [self.platform_tools.adb_path, "-s", device_id, "shell", f"rm -f '{file_path}'"],
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore'
                    )
                    
                    if result.returncode == 0:
                        success_count += 1
                        results.append({
                            'file_path': file_path,
                            'status': 'success'
                        })
                    else:
                        failed_count += 1
                        results.append({
                            'file_path': file_path,
                            'status': 'failed',
                            'error': result.stderr
                        })
                except Exception as e:
                    failed_count += 1
                    results.append({
                        'file_path': file_path,
                        'status': 'failed',
                        'error': str(e)
                    })
            
            return {
                'status': 'success',
                'summary': {
                    'total': len(threats),
                    'success': success_count,
                    'failed': failed_count
                },
                'results': results
            }
            
        except Exception as e:
            self.log_manager.log('ERROR', f"清理威胁时出错: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    async def cancel_scan(self, device_id: str) -> Dict:
        """取消扫描任务"""
        try:
            if device_id not in self.scan_status:
                return {
                    'status': 'error',
                    'error': '没有正在进行的扫描任务'
                }
            
            current_progress = self.scan_status[device_id].get('progress', 0)
            self.scan_status[device_id]['status'] = 'cancelled'
            self.scan_status[device_id]['end_time'] = datetime.now().isoformat()
            
            # 记录到历史
            self._add_to_history(device_id, 'cancelled')
            
            self.log_manager.log('INFO', f"扫描任务已取消: {device_id}")
            return {
                'status': 'success',
                'progress': current_progress
            }
        except Exception as e:
            self.log_manager.log('ERROR', f"取消扫描任务时出错: {str(e)}")
            return {'status': 'error', 'error': str(e)}

    async def pause_scan(self, device_id: str) -> Dict:
        """暂停扫描任务"""
        try:
            if device_id not in self.scan_status:
                return {
                    'status': 'error',
                    'error': '没有正在进行的扫描任务'
                }
            
            if self.scan_status[device_id]['status'] != 'scanning':
                return {
                    'status': 'error',
                    'error': '扫描任务不在进行中'
                }
            
            self.paused_scans.add(device_id)
            self.scan_status[device_id]['status'] = 'paused'
            current_progress = self.scan_status[device_id].get('progress', 0)
            
            self.log_manager.log('INFO', f"扫描任务已暂停: {device_id}")
            return {
                'status': 'success',
                'progress': current_progress
            }
        except Exception as e:
            self.log_manager.log('ERROR', f"暂停扫描任务时出错: {str(e)}")
            return {'status': 'error', 'error': str(e)}

    async def resume_scan(self, device_id: str) -> Dict:
        """恢复扫描任务"""
        try:
            if device_id not in self.scan_status:
                return {
                    'status': 'error',
                    'error': '没有可恢复的扫描任务'
                }
            
            if device_id not in self.paused_scans:
                return {
                    'status': 'error',
                    'error': '扫描任务未暂停'
                }
            
            self.paused_scans.remove(device_id)
            self.scan_status[device_id]['status'] = 'scanning'
            
            self.log_manager.log('INFO', f"扫描任务已恢复: {device_id}")
            return {'status': 'success'}
        except Exception as e:
            self.log_manager.log('ERROR', f"恢复扫描任务时出错: {str(e)}")
            return {'status': 'error', 'error': str(e)}

    def _add_to_history(self, device_id: str, status: str):
        """添加扫描记录到历史"""
        if device_id not in self.scan_history:
            self.scan_history[device_id] = []
        
        scan_info = self.scan_status[device_id].copy()
        scan_info['status'] = status
        scan_info['threats_found'] = len(scan_info.get('found_threats', []))
        scan_info['total_scanned'] = (
            scan_info.get('scanned_files', 0) + 
            scan_info.get('scanned_apps', 0)
        )
        
        self.scan_history[device_id].append(scan_info)

    async def get_scan_history(
        self,
        device_id: str,
        start_time: str = None,
        end_time: str = None,
        page: int = 1,
        page_size: int = 20
    ) -> Dict:
        """获取扫描历史记录"""
        try:
            if device_id not in self.scan_history:
                return {'total': 0, 'records': []}
            
            history = self.scan_history[device_id]
            
            # 时间过滤
            if start_time:
                start = datetime.fromisoformat(start_time)
                history = [h for h in history if datetime.fromisoformat(h['start_time']) >= start]
            
            if end_time:
                end = datetime.fromisoformat(end_time)
                history = [h for h in history if datetime.fromisoformat(h['start_time']) <= end]
            
            # 分页
            total = len(history)
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            
            records = history[start_idx:end_idx]
            
            return {
                'total': total,
                'records': records
            }
            
        except Exception as e:
            self.log_manager.log('ERROR', f"获取扫描历史时出错: {str(e)}")
            return {'total': 0, 'records': []} 