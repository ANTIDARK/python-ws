# Python-ws

这是一个基于 Python 的轻量级 VLESS WebSocket 代理服务，适合部署在 Serverless / 容器环境中。

## 现在的功能
- 仅保留 VLESS 协议支持
- 通过 WebSocket 隧道转发 TCP 流量
- 支持订阅地址生成单条 VLESS 配置
- 支持通过环境变量配置 UUID、域名、端口和路径

## 环境变量
| 变量名 | 是否必须 | 默认值 | 备注 |
| --- | --- | --- | --- |
| UUID | 否 | 7bd180e8-1142-4387-93f5-03e8d750a896 | VLESS 节点 UUID |
| DOMAIN | 否 | 空 | 你的域名，不要带 https:// |
| PORT | 否 | 3000 | 节点监听端口 |
| SUB_PATH | 否 | sub | 订阅地址路径 |
| WSPATH | 否 | UUID 前 8 位 | WebSocket 路径 |
| DEBUG | 否 | false | 是否开启调试日志 |

## 运行方式
```bash
pip install -r requirements.txt
python app.py
```

## 使用说明
- 访问 `/` 会返回一个简单页面
- 访问 `/<SUB_PATH>` 会返回一个 Base64 编码的 VLESS 订阅内容
- WebSocket 代理路径为 `/<WSPATH>`

## 说明
这个版本已经精简为只保留 VLESS 协议，便于部署和维护。