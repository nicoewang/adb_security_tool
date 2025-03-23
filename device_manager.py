import asyncio
import subprocess
import json
import psutil
import time
import threading
import re
from typing import Dict, List, Optional
from ..utils.logger import logger
from ..utils.platform_tools import PlatformTools
from datetime import datetime

class DeviceManager:
    def __init__(self):
        self.platform_tools = PlatformTools()
        self.connected_devices = {}  # 存储已连接设备的信息
        self.is_monitoring = False
        self._monitor_task = None
        self.ws_manager = None  # WebSocket连接管理器的引用
        self.scanning = False
        self.current_device: Optional[str] = None
        self.adb_path = "adb"  # 假设adb在环境变量中
        self._start_device_scanner()

    def set_ws_manager(self, manager):
        """设置WebSocket管理器"""
        self.ws_manager = manager

    def _start_device_scanner(self):
        """启动设备扫描线程"""
        def scanner():
            while True:
                try:
                    self._scan_devices()
                    time.sleep(5)  # 每5秒扫描一次
                except Exception as e:
                    logger.error(f"设备扫描错误: {e}")
                    time.sleep(5)

        thread = threading.Thread(target=scanner, daemon=True)
        thread.start()

    def _scan_devices(self):
        """扫描连接的设备"""
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')[1:]  # 跳过第一行
            current_devices = {}
            
            for line in lines:
                if line.strip():
                    serial, status = line.split()
                    if status == 'device':
                        if serial not in self.connected_devices:
                            info = self._get_device_info_internal(serial)
                            current_devices[serial] = info
                        else:
                            current_devices[serial] = self.connected_devices[serial]
            
            self.connected_devices = current_devices
        except Exception as e:
            logger.error(f"扫描设备时出错: {e}")

    def _get_device_info_internal(self, serial):
        """获取设备详细信息"""
        try:
            # 获取设备品牌
            brand = subprocess.run(['adb', '-s', serial, 'shell', 'getprop', 'ro.product.brand'],
                                capture_output=True, text=True).stdout.strip()
            # 获取设备型号
            model = subprocess.run(['adb', '-s', serial, 'shell', 'getprop', 'ro.product.model'],
                                capture_output=True, text=True).stdout.strip()
            # 获取CPU架构
            cpu_abi = subprocess.run(['adb', '-s', serial, 'shell', 'getprop', 'ro.product.cpu.abi'],
                                capture_output=True, text=True).stdout.strip()
            # 获取屏幕分辨率
            display = subprocess.run(['adb', '-s', serial, 'shell', 'wm', 'size'],
                                capture_output=True, text=True).stdout.strip()
            # 获取存储信息
            storage = subprocess.run(['adb', '-s', serial, 'shell', 'df', '/storage/emulated/0'],
                                capture_output=True, text=True).stdout.strip()

            info = {
                'serial': serial,
                'brand': brand,
                'model': model,
                'cpu_abi': cpu_abi,
                'display': display.replace('Physical size: ', ''),
                'storage': storage.split('\n')[-1].split() if '\n' in storage else [],
                'status': 'connected'
            }
            return info
        except Exception as e:
            logger.error(f"获取设备信息时出错: {e}")
            return {
                'serial': serial,
                'status': 'error',
                'error': str(e)
            }

    async def _check_devices(self) -> List[str]:
        """检查已连接的设备"""
        try:
            result = subprocess.run(
                [self.platform_tools.adb_path, "devices"],
                capture_output=True,
                text=True
            )
            devices = []
            for line in result.stdout.split('\n')[1:]:  # 跳过第一行（标题行）
                if '\t' in line:
                    device_id, status = line.strip().split('\t')
                    if status == 'device':  # 只添加已授权的设备
                        devices.append(device_id)
            return devices
        except Exception as e:
            logger.error(f"检查设备时出错: {str(e)}")
            return []

    async def _device_monitor(self):
        """设备监控心跳"""
        self.is_monitoring = True
        logger.info("启动设备监控...")
        
        while self.is_monitoring:
            try:
                current_devices = await self._check_devices()
                
                # 检查新连接的设备
                for device_id in current_devices:
                    if device_id not in self.connected_devices:
                        device_info = await self.get_device_info(device_id)
                        self.connected_devices[device_id] = device_info
                        logger.info(f"新设备连接: {device_id}")
                        if self.ws_manager:
                            await self.ws_manager.broadcast({
                                "type": "device_connected",
                                "device_id": device_id,
                                "device_info": device_info
                            })

                # 检查断开连接的设备
                disconnected_devices = []
                for device_id in list(self.connected_devices.keys()):
                    if device_id not in current_devices:
                        disconnected_devices.append(device_id)
                        logger.info(f"设备断开连接: {device_id}")
                        if self.ws_manager:
                            await self.ws_manager.broadcast({
                                "type": "device_disconnected",
                                "device_id": device_id
                            })

                # 移除断开连接的设备
                for device_id in disconnected_devices:
                    self.connected_devices.pop(device_id, None)

                await asyncio.sleep(5)  # 每5秒检查一次
            except Exception as e:
                logger.error(f"设备监控出错: {str(e)}")
                await asyncio.sleep(5)  # 发生错误时等待5秒后继续

    def start_monitoring(self):
        """启动设备监控"""
        if not self.is_monitoring:
            self.is_monitoring = True
            # 在后台运行设备监控
            asyncio.create_task(self._device_monitor())
            logger.info("设备监控任务已启动")

    def stop_monitoring(self):
        """停止设备监控"""
        if self.is_monitoring:
            self.is_monitoring = False
            logger.info("设备监控任务已停止")

    async def get_device_info(self, device_id: str) -> Dict:
        """获取设备详细信息"""
        try:
            # 获取设备型号
            model = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "getprop", "ro.product.model"],
                capture_output=True,
                text=True
            ).stdout.strip()

            # 获取Android版本
            android_version = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "getprop", "ro.build.version.release"],
                capture_output=True,
                text=True
            ).stdout.strip()

            # 获取设备序列号
            serial = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "getprop", "ro.serialno"],
                capture_output=True,
                text=True
            ).stdout.strip()

            return {
                "device_id": device_id,
                "model": model,
                "android_version": android_version,
                "serial": serial,
                "status": "connected"
            }
        except Exception as e:
            logger.error(f"获取设备信息时出错: {str(e)}")
            return {
                "device_id": device_id,
                "status": "error",
                "error": str(e)
            }

    def get_devices(self) -> List[Dict]:
        """获取所有已连接设备的信息"""
        return list(self.connected_devices.values())

    async def clean_memory(self, device_id: str) -> Dict:
        """清理设备内存"""
        try:
            # 获取清理前的内存信息
            before_info = self.get_memory_info(device_id)
            
            # 获取运行中的应用列表
            running_apps = self._get_running_apps(device_id)
            cleaned_apps = []
            
            # 清理后台应用
            for app in running_apps:
                if not self._is_system_app(app):
                    try:
                        subprocess.run(
                            [self.adb_path, "-s", device_id, "shell", "am", "force-stop", app],
                            check=True
                        )
                        cleaned_apps.append(app)
                    except subprocess.CalledProcessError:
                        continue
            
            # 清理缓存
            subprocess.run(
                [self.adb_path, "-s", device_id, "shell", "sync; echo 3 > /proc/sys/vm/drop_caches"],
                check=True
            )
            
            # 获取清理后的内存信息
            after_info = self.get_memory_info(device_id)
            
            freed_memory = (after_info["free"] - before_info["free"]) / (1024 * 1024)  # 转换为MB
            
            return {
                "status": "success",
                "freed": round(freed_memory, 2),
                "cleaned_apps": cleaned_apps,
                "details": {
                    "before_mem": f"{before_info['free'] / (1024*1024*1024):.2f}GB",
                    "after_mem": f"{after_info['free'] / (1024*1024*1024):.2f}GB"
                }
            }
            
        except Exception as e:
            logger.error(f"清理内存失败: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    def _get_running_apps(self, device_id: str) -> List[str]:
        """获取正在运行的应用列表"""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", device_id, "shell", "ps"],
                capture_output=True,
                text=True,
                check=True
            )
            
            apps = set()
            for line in result.stdout.splitlines():
                if "com.android" in line or "system" in line:
                    continue
                parts = line.split()
                if len(parts) >= 8:
                    package = parts[-1]
                    if "." in package and "/" not in package:
                        apps.add(package)
            
            return list(apps)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"获取运行应用列表失败: {e}")
            return []

    def _is_system_app(self, package_name: str) -> bool:
        """判断是否是系统应用"""
        return (
            package_name.startswith("com.android") or
            package_name.startswith("android") or
            package_name.startswith("com.google") or
            package_name.startswith("com.samsung") or
            package_name.startswith("com.sec")
        )

    def get_memory_info(self, device_id: str) -> Dict:
        """获取内存信息"""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", device_id, "shell", "cat", "/proc/meminfo"],
                capture_output=True,
                text=True,
                check=True
            )
            
            mem_info = {}
            for line in result.stdout.splitlines():
                if "MemTotal:" in line:
                    mem_info["total"] = int(line.split()[1]) * 1024
                elif "MemFree:" in line:
                    mem_info["free"] = int(line.split()[1]) * 1024
                elif "MemAvailable:" in line:
                    mem_info["available"] = int(line.split()[1]) * 1024
            
            mem_info["used"] = mem_info["total"] - mem_info["free"]
            return mem_info
            
        except subprocess.CalledProcessError as e:
            logger.error(f"获取内存信息失败: {e}")
            return {}

    def reboot_device(self, mode: str) -> Dict:
        """重启设备"""
        device_id = self.get_current_device()
        try:
            if mode == "normal":
                cmd = [self.adb_path, "-s", device_id, "reboot"]
            elif mode == "recovery":
                cmd = [self.adb_path, "-s", device_id, "reboot", "recovery"]
            elif mode == "fastboot":
                cmd = [self.adb_path, "-s", device_id, "reboot", "bootloader"]
            elif mode == "poweroff":
                cmd = [self.adb_path, "-s", device_id, "shell", "reboot", "-p"]
            else:
                return {
                    "status": "error",
                    "message": "Invalid reboot mode"
                }
            
            subprocess.run(cmd, check=True)
            return {
                "status": "success",
                "message": f"设备正在{mode}重启"
            }
            
        except subprocess.CalledProcessError as e:
            logger.error(f"重启设备失败: {e}")
            return {
                "status": "error",
                "message": str(e)
            }

    def get_current_device(self) -> str:
        """获取当前设备ID"""
        if not self.current_device:
            devices = self._get_connected_devices()
            if devices:
                self.current_device = devices[0]
            else:
                raise Exception("No device connected")
        return self.current_device

    def _get_connected_devices(self) -> List[str]:
        """获取已连接的设备列表"""
        try:
            result = subprocess.run(
                [self.adb_path, "devices"],
                capture_output=True,
                text=True,
                check=True
            )
            devices = []
            for line in result.stdout.splitlines()[1:]:
                if line.strip() and "device" in line:
                    devices.append(line.split()[0])
            return devices
        except subprocess.CalledProcessError as e:
            logger.error(f"获取设备列表失败: {e}")
            return []

    def _get_device_props(self, device_id: str) -> Dict:
        """获取设备属性"""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", device_id, "shell", "getprop"],
                capture_output=True,
                text=True,
                check=True
            )
            props = {}
            for line in result.stdout.splitlines():
                match = re.match(r'\[([^]]+)\]:\s*\[([^]]*)\]', line)
                if match:
                    props[match.group(1)] = match.group(2)
            return props
        except subprocess.CalledProcessError as e:
            logger.error(f"获取设备属性失败: {e}")
            return {}

    def _get_battery_info(self, device_id: str) -> Dict:
        """获取电池信息"""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", device_id, "shell", "dumpsys", "battery"],
                capture_output=True,
                text=True,
                check=True
            )
            info = {}
            for line in result.stdout.splitlines():
                if "level:" in line:
                    info["level"] = int(line.split(":")[1].strip())
                elif "voltage:" in line:
                    info["voltage"] = float(line.split(":")[1].strip()) / 1000
                elif "temperature:" in line:
                    info["temperature"] = float(line.split(":")[1].strip()) / 10
            return info
        except subprocess.CalledProcessError as e:
            logger.error(f"获取电池信息失败: {e}")
            return {}

    def _get_screen_resolution(self, device_id: str) -> str:
        """获取屏幕分辨率"""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", device_id, "shell", "wm", "size"],
                capture_output=True,
                text=True,
                check=True
            )
            match = re.search(r'Physical size: (\d+x\d+)', result.stdout)
            if match:
                return match.group(1)
            return "Unknown"
        except subprocess.CalledProcessError as e:
            logger.error(f"获取屏幕分辨率失败: {e}")
            return "Unknown"

    async def disconnect_device(self, device_id: str) -> bool:
        """主动断开设备连接"""
        try:
            if device_id not in self.connected_devices:
                logger.error(f"设备未连接: {device_id}")
                return False

            # 使用adb断开设备
            result = subprocess.run(
                [self.platform_tools.adb_path, "disconnect", device_id],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode == 0:
                # 从连接设备列表中移除
                if device_id in self.connected_devices:
                    del self.connected_devices[device_id]

                # 发送WebSocket通知
                if self.ws_manager:
                    await self.ws_manager.broadcast({
                        "type": "device_disconnected",
                        "device_id": device_id,
                        "timestamp": datetime.now().isoformat()
                    })

                logger.info(f"设备已断开连接: {device_id}")
                return True
            else:
                logger.error(f"断开设备连接失败: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"断开设备连接时出错: {str(e)}")
            return False

    async def reconnect_device(self, device_id: str) -> bool:
        """尝试重新连接设备"""
        try:
            # 先检查设备是否已连接
            if device_id in self.connected_devices:
                logger.warning(f"设备已经连接: {device_id}")
                return True

            # 尝试连接设备
            result = subprocess.run(
                [self.platform_tools.adb_path, "connect", device_id],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode == 0 and "connected" in result.stdout.lower():
                # 添加到连接设备列表
                self.connected_devices[device_id] = {
                    "status": "connected",
                    "connection_time": datetime.now().isoformat()
                }

                # 发送WebSocket通知
                if self.ws_manager:
                    await self.ws_manager.broadcast({
                        "type": "device_connected",
                        "device_id": device_id,
                        "timestamp": datetime.now().isoformat()
                    })

                logger.info(f"设备已重新连接: {device_id}")
                return True
            else:
                logger.error(f"重新连接设备失败: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"重新连接设备时出错: {str(e)}")
            return False

    async def _monitor_devices(self):
        """监控设备连接状态"""
        while self.is_monitoring:
            try:
                # 获取当前连接的设备
                result = subprocess.run(
                    [self.platform_tools.adb_path, "devices"],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore'
                )

                if result.returncode == 0:
                    current_devices = set()
                    for line in result.stdout.splitlines()[1:]:
                        if line.strip() and "device" in line:
                            device_id = line.split()[0]
                            current_devices.add(device_id)
                            
                            # 处理新连接的设备
                            if device_id not in self.connected_devices:
                                self.connected_devices[device_id] = {
                                    "status": "connected",
                                    "connection_time": datetime.now().isoformat()
                                }
                                if self.ws_manager:
                                    await self.ws_manager.broadcast({
                                        "type": "device_connected",
                                        "device_id": device_id,
                                        "timestamp": datetime.now().isoformat()
                                    })

                    # 处理断开的设备
                    for device_id in list(self.connected_devices.keys()):
                        if device_id not in current_devices:
                            del self.connected_devices[device_id]
                            if self.ws_manager:
                                await self.ws_manager.broadcast({
                                    "type": "device_disconnected",
                                    "device_id": device_id,
                                    "timestamp": datetime.now().isoformat()
                                })

            except Exception as e:
                logger.error(f"监控设备时出错: {str(e)}")

            await asyncio.sleep(2)  # 每2秒检查一次

    def get_devices(self) -> Dict:
        """获取已连接的设备列表"""
        return {"devices": [
            {
                "id": device_id,
                **device_info
            }
            for device_id, device_info in self.connected_devices.items()
        ]}

    async def get_device_info(self, device_id: str) -> Dict:
        """获取设备详细信息"""
        try:
            if device_id not in self.connected_devices:
                raise Exception("设备未连接")

            # 获取设备信息
            props = {}
            result = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "getprop"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if ']' in line and '[' in line:
                        key = line.split('[')[1].split(']')[0]
                        value = line.split('[')[2].split(']')[0]
                        props[key] = value

            # 获取存储信息
            storage = await self._get_storage_info(device_id)

            return {
                "device_id": device_id,
                "model": props.get("ro.product.model", "Unknown"),
                "android_version": props.get("ro.build.version.release", "Unknown"),
                "manufacturer": props.get("ro.product.manufacturer", "Unknown"),
                "storage": storage
            }

        except Exception as e:
            logger.error(f"获取设备信息时出错: {str(e)}")
            raise

    async def _get_storage_info(self, device_id: str) -> Dict:
        """获取设备存储信息"""
        try:
            result = subprocess.run(
                [self.platform_tools.adb_path, "-s", device_id, "shell", "df", "/storage/emulated/0"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode == 0:
                lines = result.stdout.splitlines()
                if len(lines) >= 2:
                    parts = lines[1].split()
                    if len(parts) >= 4:
                        return {
                            "total": parts[1],
                            "available": parts[3]
                        }

            return {
                "total": "Unknown",
                "available": "Unknown"
            }

        except Exception as e:
            logger.error(f"获取存储信息时出错: {str(e)}")
            return {
                "total": "Error",
                "available": "Error"
            }
