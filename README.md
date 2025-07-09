# DHCP MAC嗅探器

该项目包含一个**精简版DHCP数据包嗅探器**，可被动监听网络中的DHCP流量，提取客户端MAC地址，并通过网页界面展示，每个MAC地址均可一键复制。

> ⚠️  该脚本不会响应DHCP请求，仅进行观察记录。

## 运行要求

1. **Python 3.8及以上版本**
2. **管理员/root权限**（数据包捕获必需）
3. Windows系统需安装**Npcap** (https://npcap.com/)，安装时务必勾选 _"Install Npcap in WinPcap API-compatible Mode"_ 选项

安装Python依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

```bash
# 在所有网络接口上运行，并通过http://localhost:8080提供网页界面
python dhcp_mac_sniffer.py

# 指定特定网接口和自定义端口
python dhcp_mac_sniffer.py --iface Ethernet --port 8080
```

在浏览器中访问指定地址，新监测到的MAC地址将自动显示。点击任意地址旁的**复制**按钮即可将其拷贝至剪贴板。

## 工作原理

* 脚本使用**Scapy**进行数据包嗅探，BPF过滤器设置为：`udp and (port 67 or port 68)`
* 当检测到包含DHCP层的数据包时，从以太网头部提取源MAC地址并存储
* 轻量级**Flask**服务器托管一个HTML页面，该页面通过AJAX定期获取当前MAC地址列表

由于程序仅监听而不发送数据，因此不会与客户端设备建立任何通信连接。
