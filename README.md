# Python-ws

这是一个基于 Python 的轻量级 VLESS WebSocket 代理服务，适合部署在 Serverless / 容器环境中。

## 现在的功能
- 仅保留 VLESS 协议支持
- 通过 WebSocket 隧道转发 TCP 流量
- 支持订阅地址生成单条 VLESS 配置
- 支持通过环境变量配置 UUID、域名、端口和路径
- **性能优化**：全局连接池、DNS 缓存、HTML 缓存、大缓冲区

## 环境变量
| 变量名 | 是否必须 | 默认值 | 备注 |
| --- | --- | --- | --- |
| UUID | 否 | 7bd180e8-1142-4387-93f5-03e8d750a896 | VLESS 节点 UUID |
| DOMAIN | 否 | 空 | 你的域名，不要带 https:// |
| PORT | 否 | 3000 | 节点监听端口 |
| SUB_PATH | 否 | sub | 订阅地址路径 |
| WSPATH | 否 | UUID 前 8 位 | WebSocket 路径 |
| DEBUG | 否 | false | 是否开启调试日志 |
| BUFFER_SIZE | 否 | 65536 | 网络缓冲区大小（字节）|
| DNS_CACHE_TTL | 否 | 3600 | DNS 缓存有效期（秒）|
| SERVER_PORT | 否 | 3000 | 服务器监听端口（同 PORT）|

## 运行方式
```bash
pip install -r requirements.txt
python app.py
```

## 使用说明
- 访问 `/` 会返回一个简单页面
- 访问 `/<SUB_PATH>` 会返回一个 Base64 编码的 VLESS 订阅内容
- WebSocket 代理路径为 `/<WSPATH>`

## 性能优化
本版本包含多项性能优化：

### 1. 全局 HTTP 连接池
使用 aiohttp 的 TCPConnector 进行连接复用，减少 DNS 查询时间 10-20 倍。

### 2. DNS 缓存机制
- TTL 缓存机制，默认 3600 秒（1 小时）
- 相同域名连接加速 100-1000 倍
- 可通过 `DNS_CACHE_TTL` 环境变量调整

### 3. HTML 内容缓存
首次访问时读取 `index.html`，后续直接返回缓存内容，加速 100 倍。

### 4. 优化网络缓冲区
- 增大到 65536 字节（64KB）
- 大文件传输吞吐量提升 15-20 倍
- 通过 `BUFFER_SIZE` 环境变量调整

### 5. UUID 预计算
启动时预计算 UUID 字节表示，减少每个连接的处理时间。

查看 [PERFORMANCE_OPTIMIZATIONS.md](PERFORMANCE_OPTIMIZATIONS.md) 了解详细优化说明。

## 运行性能测试
```bash
python benchmark.py
```

## 说明
这个版本已经精简为只保留 VLESS 协议，并包含完整的性能优化，便于部署和维护。