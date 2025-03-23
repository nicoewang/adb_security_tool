# 注意！！！该代码只有后端部分，没有UI，并且代码不全，只用于个人记录！！！不可直接使用！！！
# USB设备病毒扫描工具

## 功能特点

- 实时设备监控
- 病毒扫描
- 内存清理
- 应用管理
- 威胁隔离
- 日志管理

## 系统要求

- Python 3.8+
- Windows 10/11
- Android SDK Platform Tools
- ClamAV 病毒引擎

## 安装步骤

1. 安装Python依赖：
```bash
pip install -r requirements.txt
```

2. 安装ClamAV：
   - 下载ClamAV并解压到项目目录的`ClamAV`文件夹
   - 确保`clamd.exe`和`freshclam.exe`存在
   - 运行`freshclam.exe`更新病毒库

3. 安装Android SDK Platform Tools：
   - 下载Android SDK Platform Tools
   - 将`adb.exe`放入系统PATH或项目目录

## 配置说明

1. ClamAV配置：
   - 配置文件位于`ClamAV/clamd.conf`
   - 默认端口：3310
   - 默认主机：localhost

2. 环境变量：
   - `CLAMD_HOST`: ClamAV服务器地址（默认：localhost）
   - `CLAMD_PORT`: ClamAV服务器端口（默认：3310）

## 启动应用

1. 启动ClamAV服务：
```bash
cd ClamAV
freshclam.exe  # 更新病毒库
clamd.exe      # 启动服务
```

2. 启动应用：
```bash
python run.py
```

## 使用说明

1. 设备连接：
   - 启用Android设备的USB调试
   - 通过USB连接设备
   - 在设备上确认调试授权

2. 病毒扫描：
   - 点击"开始扫描"
   - 选择扫描范围
   - 等待扫描完成
   - 查看扫描结果

3. 内存清理：
   - 点击"内存清理"
   - 查看清理前后的内存状态
   - 确认清理效果

4. 应用管理：
   - 查看已安装应用
   - 卸载可疑应用
   - 检查应用权限

5. 威胁处理：
   - 查看检测到的威胁
   - 选择处理方式（删除/隔离）
   - 确认处理结果

6. 日志查看：
   - 查看操作日志
   - 筛选日志级别
   - 导出日志记录

## 故障排除

1. ClamAV服务无法启动：
   - 检查配置文件
   - 确认端口未被占用
   - 查看错误日志

2. 设备连接问题：
   - 确认USB调试已启用
   - 检查USB连接
   - 运行`adb devices`确认设备状态

3. 扫描失败：
   - 检查设备连接
   - 确认存储权限
   - 查看详细错误日志

## 注意事项

1. 权限要求：
   - 需要设备USB调试权限
   - 需要存储访问权限
   - 部分功能可能需要root权限

2. 资源消耗：
   - 扫描过程可能占用较多系统资源
   - 建议在设备电量充足时进行

3. 数据安全：
   - 定期备份重要数据
   - 谨慎处理检测到的威胁

## 技术支持

如遇到问题，请：
1. 查看详细日志
2. 检查配置文件
3. 确认环境依赖
4. 联系技术支持

## 更新记录

### v1.0.0
- 初始版本发布
- 基础功能实现
- 界面优化 
