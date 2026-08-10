# 土耳其 (TR) 节点手动导入目录

如需使用土耳其 (TR) 出口节点，请将土耳其的 `.ovpn` 配置文件及凭据放入本目录：

## 文件结构

```text
providers/turkey/
├── provider.json       # (可选) 统一凭据和配置
├── tr-01.ovpn          # 土耳其 OpenVPN 配置文件
└── tr-02.ovpn
```

## provider.json 示例

```json
{
  "source": "turkey_custom",
  "country": "TR",
  "username": "你的OpenVPN账号",
  "password": "你的OpenVPN密码"
}
```

将 `.ovpn` 文件放入后，重启容器或等待下一次刷新，系统会自动读取土耳其节点并路由至 TR 出口槽位。
