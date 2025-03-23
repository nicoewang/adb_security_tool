from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Body
from fastapi.responses import HTMLResponse
from typing import List, Dict
import json
from ..core.device_manager import DeviceManager
from ..core.scanner import VirusScanner
from ..core.app_manager import AppManager
from ..utils.logger import logger

router = APIRouter()
device_manager = DeviceManager()
virus_scanner = VirusScanner()
app_manager = AppManager()

@router.get("/", response_class=HTMLResponse)
async def root():
    """根路径处理"""
    return """
    <html>
        <head>
            <title>USB设备病毒扫描工具 API</title>
        </head>
        <body>
            <h1>USB设备病毒扫描工具 API</h1>
            <p>可用的API端点：</p>
            <ul>
                <li>GET /devices - 获取设备列表</li>
                <li>GET /device/{device_id}/info - 获取设备信息</li>
                <li>GET /device/{device_id}/apps - 获取已安装的应用</li>
                <li>POST /device/{device_id}/scan - 开始病毒扫描</li>
                <li>GET /scan/status - 获取扫描状态</li>
                <li>POST /device/{device_id}/uninstall/{package_name} - 卸载应用</li>
                <li>POST /device/{device_id}/clean-memory - 清理内存</li>
                <li>WebSocket /ws - 实时通信接口</li>
            </ul>
        </body>
    </html>
    """

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict):
        """广播消息到所有连接的客户端"""
        if self.active_connections:
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"发送WebSocket消息时出错: {str(e)}")

manager = ConnectionManager()
device_manager.set_ws_manager(manager)  # 设置WebSocket管理器

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    # 启动设备监控
    device_manager.start_monitoring()
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast({"type": "message", "content": data})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        # 当最后一个WebSocket连接断开时，停止设备监控
        if not manager.active_connections:
            device_manager.stop_monitoring()

@router.get("/devices")
async def get_devices():
    """获取已连接的设备列表"""
    return device_manager.get_devices()

@router.get("/device/{device_id}/info")
async def get_device_info(device_id: str):
    """获取设备信息"""
    return await device_manager.get_device_info(device_id)

@router.get("/device/{device_id}/apps")
async def get_installed_apps(device_id: str):
    """获取已安装的应用列表"""
    return app_manager.get_installed_apps(device_id)

@router.post("/device/{device_id}/scan")
async def start_scan(device_id: str):
    """开始病毒扫描"""
    return await virus_scanner.start_scan(device_id)

@router.post("/device/{device_id}/uninstall/{package_name}")
async def uninstall_app(device_id: str, package_name: str):
    """卸载应用"""
    return app_manager.uninstall_app(device_id, package_name)

@router.post("/device/{device_id}/clean-memory")
async def clean_memory(device_id: str):
    """清理内存"""
    return await device_manager.clean_memory(device_id)

@router.get("/scan/status")
async def get_scan_status():
    """获取扫描状态"""
    return virus_scanner.get_status()

@router.get("/device/{device_id}/scan/result")
async def get_scan_result(device_id: str):
    """获取设备扫描结果"""
    try:
        result = virus_scanner.get_scan_result(device_id)
        if result.get("status") == "not_found":
            raise HTTPException(
                status_code=404,
                detail=f"No scan results found for device {device_id}"
            )
        return result
    except Exception as e:
        logger.error(f"获取扫描结果时出错: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get scan results: {str(e)}"
        )

@router.get("/device/{device_id}/memory-info")
async def get_device_memory_info(device_id: str):
    """获取设备内存信息"""
    try:
        memory_info = await virus_scanner.get_memory_info(device_id)
        if 'error' in memory_info:
            raise HTTPException(
                status_code=500,
                detail=memory_info['error']
            )
        return memory_info
    except Exception as e:
        logger.error(f"获取设备内存信息时出错: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"获取内存信息失败: {str(e)}"
        )

@router.post("/device/{device_id}/clean-threats")
async def clean_threats(device_id: str, threats: List[Dict] = Body(...)):
    """清理检测到的威胁"""
    try:
        result = await virus_scanner.clean_threats(device_id, threats)
        if 'error' in result:
            raise HTTPException(status_code=500, detail=result['error'])
        return result
    except Exception as e:
        logger.error(f"清理威胁时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/quarantine/list")
async def get_quarantine_list():
    """获取隔离区文件列表"""
    try:
        files = virus_scanner.get_quarantine_list()
        return {"files": files}
    except Exception as e:
        logger.error(f"获取隔离区列表时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/device/{device_id}/restore-file")
async def restore_quarantined_file(
    device_id: str, 
    quarantine_file: str = Body(..., embed=True)
):
    """从隔离区恢复文件"""
    try:
        result = await virus_scanner.restore_from_quarantine(device_id, quarantine_file)
        if result['status'] == 'failed':
            raise HTTPException(status_code=500, detail=result['message'])
        return result
    except Exception as e:
        logger.error(f"恢复文件时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 日志管理相关路由
@router.get("/logs")
async def get_logs(
    start_time: str = None,
    end_time: str = None,
    level: str = None,
    limit: int = 1000
):
    """获取系统日志"""
    try:
        logs = await virus_scanner.get_logs(
            start_time=start_time,
            end_time=end_time,
            level=level,
            limit=limit
        )
        return {"logs": logs, "total": len(logs)}
    except Exception as e:
        logger.error(f"获取日志时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/logs/clear")
async def clear_logs():
    """清理系统日志"""
    try:
        success = await virus_scanner.clear_logs()
        return {
            "status": "success" if success else "failed",
            "message": "日志已清理" if success else "清理失败"
        }
    except Exception as e:
        logger.error(f"清理日志时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/logs/stats")
async def get_log_stats():
    """获取日志统计信息"""
    try:
        return await virus_scanner.get_log_stats()
    except Exception as e:
        logger.error(f"获取日志统计时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 病毒库管理相关路由
@router.post("/virus-db/update")
async def update_virus_db():
    """更新病毒特征库"""
    try:
        result = await virus_scanner.db_updater.update_database()
        return result
    except Exception as e:
        logger.error(f"更新病毒库时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/virus-db/info")
async def get_virus_db_info():
    """获取病毒特征库信息"""
    try:
        return virus_scanner.db_updater.get_database_info()
    except Exception as e:
        logger.error(f"获取病毒库信息时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 设备管理相关路由
@router.post("/device/{device_id}/disconnect")
async def disconnect_device(device_id: str):
    """主动断开设备连接"""
    try:
        result = await device_manager.disconnect_device(device_id)
        if not result:
            raise HTTPException(status_code=400, detail="断开设备连接失败")
        return {"status": "success", "message": "设备已断开连接"}
    except Exception as e:
        logger.error(f"断开设备连接时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/device/{device_id}/reconnect")
async def reconnect_device(device_id: str):
    """尝试重新连接设备"""
    try:
        result = await device_manager.reconnect_device(device_id)
        return {
            "status": "success" if result else "failed",
            "message": "设备已重新连接" if result else "重新连接失败"
        }
    except Exception as e:
        logger.error(f"重新连接设备时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 扫描任务管理相关路由
@router.post("/device/{device_id}/scan/cancel")
async def cancel_scan(device_id: str):
    """取消扫描任务"""
    try:
        result = await virus_scanner.cancel_scan(device_id)
        return {
            "status": "success",
            "message": "扫描已取消",
            "scan_progress": result.get("progress", 0)
        }
    except Exception as e:
        logger.error(f"取消扫描时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/device/{device_id}/scan/pause")
async def pause_scan(device_id: str):
    """暂停扫描任务"""
    try:
        result = await virus_scanner.pause_scan(device_id)
        return {
            "status": "success",
            "message": "扫描已暂停",
            "scan_progress": result.get("progress", 0)
        }
    except Exception as e:
        logger.error(f"暂停扫描时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/device/{device_id}/scan/resume")
async def resume_scan(device_id: str):
    """恢复扫描任务"""
    try:
        result = await virus_scanner.resume_scan(device_id)
        return {
            "status": "success",
            "message": "扫描已恢复"
        }
    except Exception as e:
        logger.error(f"恢复扫描时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/device/{device_id}/scan/history")
async def get_scan_history(
    device_id: str,
    start_time: str = None,
    end_time: str = None,
    page: int = 1,
    page_size: int = 20
):
    """获取扫描历史记录"""
    try:
        history = await virus_scanner.get_scan_history(
            device_id,
            start_time=start_time,
            end_time=end_time,
            page=page,
            page_size=page_size
        )
        return history
    except Exception as e:
        logger.error(f"获取扫描历史时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 