# xui-limit

适用于 Debian/Ubuntu 的 x-ui / 3x-ui 节点端口双向限速管理脚本，支持 IPv4、IPv6、TCP、UDP、IFB 上传整形、HTB 下载整形、增量修改和 systemd 开机恢复。

## Debian 一键下载、授权并立即启动

请先切换到 root 用户，然后执行：

    curl -fsSL https://raw.githubusercontent.com/Wucat109/xui-limit/main/xui-limit.sh -o /root/xui-limit.sh && chmod 700 /root/xui-limit.sh && bash /root/xui-limit.sh


---


## 功能特性

- 支持客户端上传和下载双向限速。
- 支持 IPv4。
- 支持 IPv6。
- 支持 TCP。
- 支持 UDP。
- 支持 TCP + UDP 同时限速。
- 支持从 x-ui / 3x-ui SQLite 数据库读取节点。
- 支持手动输入端口。
- 支持多个节点端口分别设置速率。
- 支持多张物理网卡。
- 支持自动创建和管理 IFB 虚拟网卡。
- 下载方向使用物理网卡 `HTB + flower`。
- 上传方向使用 `ingress + mirred + IFB + HTB`。
- 每个限速 class 下使用 `fq_codel` 管理队列。
- 普通添加、删除和修改采用增量更新。
- 修改一个端口时不会主动重建其他端口。
- 删除一个协议时不会影响同端口的另一个协议。
- 基础 qdisc、IFB 或 ingress 缺失时，只重建受影响的网卡。
- 多网卡恢复时，一张网卡失败不会清理其他网卡的 ingress 规则。
- 支持 systemd 开机恢复。
- 支持重启后自动接管已经授权的物理网卡。
- 支持系统默认 `fq`、`fq_codel`、CAKE 或 `mq` 后恢复为 HTB。
- 支持清理旧版脚本留下的 iptables MARK。
- 支持清理旧版全流量 ingress → IFB 重定向。
- 支持规则状态、流量、丢包和超限统计。
- 支持 `rules.conf` 与 `root-owned.conf` 一致性检查。
- 支持完整的临时 IFB、IPv4、IPv6、flower、mirred、HTB 和 fq_codel 环境测试。
- 临时 IFB 测试使用唯一名称和 alias，不会盲目删除同名接口。
- 使用专属 HTB 标记 class `1:fffe` 判断 qdisc 所有权。
- 接管前自动保存原 qdisc 信息。
- 支持运行日志和 systemd 日志。

---

## 系统要求

推荐环境：

- Debian 11、Debian 12 或更新版本。
- Ubuntu 20.04、22.04、24.04 或更新版本。
- root 权限。
- 使用 systemd。
- 内核支持 IFB。
- 内核支持 HTB。
- 内核支持 fq_codel。
- 内核支持 flower 分类器。
- 内核支持 mirred action。
- 推荐使用标准 Debian/Ubuntu 内核。

主要依赖：

    iproute2
    iptables
    sqlite3
    util-linux
    bsdextrautils
    kmod
    curl
    ca-certificates

脚本的自动依赖安装目前主要面向使用 `apt` 的 Debian/Ubuntu 系统。

---

## 首次使用建议

运行脚本：

    /root/xui-limit.sh

如果直接执行提示权限不足，可以使用：

    bash /root/xui-limit.sh

推荐首次使用顺序：

1. 选择 `1) 安装依赖`。
2. 选择 `9) 环境检查`。
3. 选择 `2) 添加节点双向限速`。
4. 选择物理网卡。
5. 选择 x-ui 节点或手动输入端口。
6. 输入整数 Mbps 速率。
7. 选择 TCP、UDP 或 TCP + UDP。
8. 确认脚本接管物理网卡 root qdisc。
9. 选择 `3) 查看当前双向限速状态`。
10. 选择 `8) 开机自启设置`。
11. 启用开机自动恢复。

如果此前使用过旧版单向或双向限速脚本，建议先选择：

    7) 修复/清理并完整重建规则

该操作会进行旧规则迁移和完整状态重建。

---

## 管理菜单

脚本提供以下菜单：

    1) 安装依赖
    2) 添加节点双向限速
    3) 查看当前双向限速状态
    4) 删除节点双向限速
    5) 修改节点双向限速
    6) 清空某网卡全部双向限速
    7) 修复/清理并完整重建规则
    8) 开机自启设置
    9) 环境检查
    10) 查看最近运行日志
    0) 退出

---

## 限速方向说明

脚本中的上传和下载方向以客户端视角为准。

### 客户端下载

数据方向：

    服务器节点端口 → 客户端

在服务器上属于物理网卡出站流量：

    物理网卡 root HTB
        ↓
    flower 匹配源端口 src_port
        ↓
    端口 HTB class
        ↓
    fq_codel
        ↓
    客户端

### 客户端上传

数据方向：

    客户端 → 服务器节点端口

在服务器上属于物理网卡入站流量：

    物理网卡 ingress
        ↓
    flower 匹配目标端口 dst_port
        ↓
    mirred 重定向到 IFB
        ↓
    IFB root HTB
        ↓
    端口 HTB class
        ↓
    fq_codel
        ↓
    服务器协议栈

---

## 速率含义

例如对端口 `50000` 输入：

    50

脚本会生成：

    上传上限：50mbit
    下载上限：50mbit

这里表示：

- 客户端上传最高约 50 Mbps。
- 客户端下载最高约 50 Mbps。
- 上传和下载分别限速。
- 不是上传和下载合计共享 50 Mbps。

实际应用层测速通常会略低于配置值，因为以下内容也会计入带宽：

- IPv4 或 IPv6 头部。
- TCP 或 UDP 头部。
- TCP ACK。
- TLS 开销。
- Xray 协议封装。
- WebSocket、gRPC、Reality 等传输开销。
- 其他隧道封装。

例如配置 50 Mbps 时，应用层测速可能约为：

    45～49 Mbps

具体结果取决于协议、线路和测速方式。

---

## 端口带宽共享规则

同一个端口的 TCP 和 UDP 使用同一个 HTB class。

例如：

    端口：50000
    协议：TCP + UDP
    速率：50mbit

表示该端口上的 TCP 和 UDP 流量共享同一个方向的 50 Mbps 上限。

脚本不会允许同一物理网卡、同一端口的 TCP 和 UDP 设置不同速率。

同一端口上的所有连接和所有用户也共享该端口的带宽上限，并不是每个用户都单独获得完整速率。

---

## 增量更新说明

普通添加、修改和删除操作采用增量更新。

### 添加新协议

例如端口已经存在 TCP 规则，再添加 UDP 时，脚本只新增：

- IPv4 UDP 下载 flower filter。
- IPv6 UDP 下载 flower filter。
- IPv4 UDP ingress filter。
- IPv6 UDP ingress filter。
- IPv4 UDP IFB 上传 filter。
- IPv6 UDP IFB 上传 filter。

已有 TCP 规则不会被主动删除重建。

### 修改速率

修改某个端口速率时，主要更新：

    物理网卡对应端口 HTB class
    IFB 对应端口 HTB class

其他端口不会被重建，其他端口的统计通常不会清零。

### 删除单个协议

删除 TCP 或 UDP 时，只删除该协议对应的：

- 物理网卡下载 filter。
- 物理网卡 ingress filter。
- IFB 上传 filter。

同端口的另一个协议不会受到影响。

### 删除整个端口

只有当端口的 TCP 和 UDP 规则都不存在后，脚本才删除：

- 物理网卡对应 HTB class。
- IFB 对应 HTB class。
- 对应 fq_codel 叶子队列。

### 什么时候会完整重建

以下情况可能触发相关网卡完整重建：

- 用户选择菜单 `7`。
- 开机恢复发现内核状态不完整。
- 物理网卡 HTB root 丢失。
- IFB 设备丢失。
- IFB HTB root 丢失。
- ingress qdisc 丢失。
- 增量操作失败，需要恢复操作前状态。

---

## IPv4 和 IPv6

脚本会为每个规则同时建立：

- IPv4 TCP。
- IPv4 UDP。
- IPv6 TCP。
- IPv6 UDP。

实际建立哪些协议规则取决于菜单中选择的协议。

例如选择 TCP + UDP 时，将同时建立：

    IPv4 TCP
    IPv4 UDP
    IPv6 TCP
    IPv6 UDP

需要注意：

> 脚本限制的是客户端连接节点端口时所使用的外层 IP 版本，而不是代理访问目标网站时使用的 IP 版本。

例如：

    客户端通过 IPv4 连接节点
    节点再访问 IPv6 网站

从限速脚本角度看，这仍然属于 IPv4 节点连接。

---

## HTB、fq_codel 和 BBR

脚本使用：

    HTB
        ↓
    端口限速 class
        ↓
    fq_codel

其中：

- HTB 负责控制端口最高带宽。
- fq_codel 负责 class 内部连接公平和降低排队延迟。
- BBR 负责 TCP 拥塞控制。

可以继续使用：

    net.core.default_qdisc = fq
    net.ipv4.tcp_congestion_control = bbr

系统重启时，物理网卡可能先按照 `default_qdisc` 使用 root `fq`。随后 xui-limit 的 systemd 服务会对已经授权的网卡重新建立：

    root HTB
        ↓
    端口 class
        ↓
    fq_codel

因此，`default_qdisc=fq` 与脚本本身并不直接冲突。

但是，不能让其他程序在 xui-limit 恢复完成后继续执行：

    tc qdisc replace dev eth0 root fq

或者：

    tc qdisc replace dev eth0 root cake

这些命令会立即覆盖脚本建立的 HTB，使下载限速失效。

---

## root qdisc 接管

按端口执行下载限速，需要脚本接管物理网卡的 root qdisc。

第一次使用时，脚本会显示当前 root qdisc，并要求确认：

    确认接管网卡 eth0？[y/n]

确认后，脚本会：

1. 保存当前 qdisc、class 和 filter 信息。
2. 将该网卡记录到 `root-owned.conf`。
3. 使用 HTB 接管 root qdisc。
4. 创建本脚本专属标记 class。
5. 创建端口限速 class 和 flower filter。

qdisc 备份目录：

    /etc/xui-limit/qdisc-backup/

备份文件示例：

    eth0-20260826-120000.txt
    eth0-latest.txt

复杂的第三方 QoS 规则不会被自动还原。请不要在已经存在重要 CAKE、HTB 或其他自定义 QoS 的服务器上直接确认接管，除非明确知道影响。

---

## HTB 所有权标记

脚本会在物理网卡和 IFB 的 HTB 中建立：

    class 1:fffe

配置速率为：

    1mbit

该 class 仅作为所有权标记使用，没有 flower filter 将普通流量导向该 class，因此不会实际预留或占用 1 Mbps 带宽。

脚本只有同时检测到：

    qdisc htb 1: root
    class htb 1:fffe

才会把该 HTB 判断为自身管理的 qdisc。

检查物理网卡标记：

    tc class show dev eth0 classid 1:fffe

检查 IFB 标记：

    IFB=$(awk -F'|' '$1=="eth0"{print $2; exit}' /etc/xui-limit/ifb.map)
    tc class show dev "$IFB" classid 1:fffe

---

## 配置文件

脚本使用以下文件：

### 主规则文件

    /etc/xui-limit/rules.conf

格式：

    网卡|端口|协议|速率|classid|handle

示例：

    eth0|50000|tcp|50mbit|1:6000|6000
    eth0|50000|udp|50mbit|1:6000|6000

建议通过脚本菜单修改，不要直接手工编辑。

### IFB 映射

    /etc/xui-limit/ifb.map

示例：

    eth0|xuil4019892195

### 已应用规则快照

    /etc/xui-limit/applied.conf

用于：

- 判断规则配置是否发生变化。
- 开机恢复时判断是否需要重建。
- 操作失败时辅助恢复旧规则。

### root 接管授权

    /etc/xui-limit/root-owned.conf

示例：

    eth0

只有记录在该文件中的网卡，开机恢复模式才允许自动覆盖系统启动后生成的默认 root qdisc。

### ingress 所有权

    /etc/xui-limit/ingress-owned.conf

记录由脚本创建的 ingress qdisc。

### qdisc 备份

    /etc/xui-limit/qdisc-backup/

### 日志文件

    /var/log/xui-limit.log

### systemd 使用的固定脚本

    /usr/local/lib/xui-limit/xui-limit-manager.sh

### systemd 恢复入口

    /usr/local/bin/xui-limit-restore.sh

### systemd 服务文件

    /etc/systemd/system/xui-limit.service

---

## 开机自动恢复

进入菜单：

    8) 开机自启设置

选择：

    1) 启用开机自动恢复

启用后，脚本会：

1. 将当前脚本复制到固定路径。
2. 创建恢复入口。
3. 创建 systemd 服务。
4. 启用并启动服务。

服务状态：

    systemctl status xui-limit.service --no-pager

查看本次启动日志：

    journalctl -u xui-limit.service -b --no-pager

查看最近 100 行服务日志：

    journalctl -u xui-limit.service -n 100 --no-pager

正常情况下，服务状态应为：

    active (exited)

---

## 重启恢复流程

服务器启动后，恢复过程大致为：

    systemd-sysctl 加载 sysctl
        ↓
    网络接口初始化
        ↓
    系统可能创建默认 fq、fq_codel、CAKE 或 mq
        ↓
    xui-limit.service 启动
        ↓
    读取 rules.conf
        ↓
    检查 root-owned.conf
        ↓
    自动接管已授权网卡
        ↓
    恢复物理网卡 HTB
        ↓
    恢复 IFB
        ↓
    恢复 IPv4/IPv6、TCP/UDP规则
        ↓
    恢复完成

未记录在 `root-owned.conf` 中的网卡不会被自动接管。

---

## 验证限速状态

### 菜单状态

选择：

    3) 查看当前双向限速状态

正常应显示：

    双向正常

状态页会显示：

- 网卡。
- IFB。
- 端口。
- 协议。
- 配置速率。
- 上传累计流量。
- 下载累计流量。
- 上传/下载丢包。
- 上传/下载超限。
- 当前加载状态。

### 检查物理网卡

假设物理网卡是 `eth0`：

    tc qdisc show dev eth0
    tc class show dev eth0
    tc filter show dev eth0 parent 1:
    tc filter show dev eth0 parent ffff:

正常应包含：

    qdisc htb 1: root
    class htb 1:fffe
    class htb 1:端口ID
    qdisc fq_codel
    flower src_port
    flower dst_port
    mirred egress redirect

### 检查 IFB

获取 IFB 名称：

    IFB=$(awk -F'|' '$1=="eth0"{print $2; exit}' /etc/xui-limit/ifb.map)
    echo "$IFB"

检查 IFB：

    tc qdisc show dev "$IFB"
    tc class show dev "$IFB"
    tc filter show dev "$IFB" parent 1:

### 查看统计

客户端下载，即服务器出站：

    tc -s class show dev eth0

客户端上传，即服务器入站后进入 IFB：

    tc -s class show dev "$IFB"

---

## 环境检查

进入菜单：

    9) 环境检查

环境检查会验证：

- `ip` 命令。
- `tc` 命令。
- `modprobe`。
- `sqlite3`。
- `column`。
- x-ui 数据库。
- systemd 开机恢复状态。
- `rules.conf` 与 `root-owned.conf` 一致性。
- IFB 映射和 alias。
- HTB root。
- HTB class。
- fq_codel。
- IPv4 flower `src_port`。
- IPv6 flower `src_port`。
- IPv4 flower + mirred。
- IPv6 flower + mirred。
- IFB IPv4 `dst_port` 上传分类。
- IFB IPv6 `dst_port` 上传分类。

环境测试会创建临时 IFB。

临时 IFB：

- 使用随机且未占用的接口名称。
- 设置本次测试专属 alias。
- 删除前验证接口类型。
- 删除前验证 alias。
- 不会盲目删除碰巧同名的系统接口。

---

## 修复和完整重建

进入菜单：

    7) 修复/清理并完整重建规则

该功能适用于：

- 从旧版脚本升级。
- HTB root 被其他程序覆盖。
- IFB 丢失。
- ingress 规则丢失。
- flower filter 不完整。
- 配置文件与内核规则不一致。
- IPv4 或 IPv6规则不完整。
- 开机恢复失败。
- 新增所有权标记 `1:fffe`。
- 清理旧版 iptables MARK。
- 清理旧版全流量 IFB 重定向。

该操作会清空并重建相关网卡的 tc 状态，因此累计统计会重新开始。

接管确认会从 `/dev/tty` 读取，避免网卡列表或管道占用标准输入。

如果多张网卡中任意一张拒绝接管，脚本会恢复操作前的 `root-owned.conf`。

---

## 更新脚本

使用以下命令下载最新版到临时文件，检查通过后再覆盖当前脚本：

    TMP_FILE=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/Wucat109/xui-limit/main/xui-limit.sh -o "$TMP_FILE" && sed -i 's/\r$//' "$TMP_FILE" && bash -n "$TMP_FILE" && install -m 700 "$TMP_FILE" /root/xui-limit.sh && rm -f "$TMP_FILE" && /root/xui-limit.sh

更新后建议：

1. 选择 `9) 环境检查`。
2. 选择 `7) 修复/清理并完整重建规则`。
3. 选择 `3) 查看当前双向限速状态`。
4. 如果已启用自启，进入菜单 `8`，重新选择启用。

也可以手动更新 systemd 使用的固定副本：

    install -m 700 /root/xui-limit.sh /usr/local/lib/xui-limit/xui-limit-manager.sh
    bash -n /usr/local/lib/xui-limit/xui-limit-manager.sh
    systemctl daemon-reload
    systemctl reset-failed xui-limit.service
    systemctl restart xui-limit.service

---

## Bash 语法和换行检查

每次从 Windows、网页编辑器或 GitHub 下载后，建议执行：

    sed -i 's/\r$//' /root/xui-limit.sh
    chmod 700 /root/xui-limit.sh
    bash -n /root/xui-limit.sh

`bash -n` 没有输出表示语法检查通过。

检查 Windows CRLF：

    grep -n $'\r$' /root/xui-limit.sh | head

没有输出表示没有行尾 CR。

检查是否错误地把函数参数写成 `\$1`、`\$2`：

    grep -nE '\\\$[0-9]+' /root/xui-limit.sh

正常情况下不应有输出。

推荐文件格式：

    字符编码：UTF-8
    换行格式：LF

---

## 与网络调优脚本的兼容性

以下 sysctl 一般可以共存：

    net.core.default_qdisc = fq
    net.ipv4.tcp_congestion_control = bbr

只执行：

    sysctl -p

通常不会立即删除已经存在的 HTB。

但是，如果其他脚本执行以下命令，限速可能失效：

    tc qdisc replace dev eth0 root fq
    tc qdisc replace dev eth0 root fq_codel
    tc qdisc replace dev eth0 root cake
    tc qdisc del dev eth0 root
    tc qdisc del dev eth0 ingress
    tc qdisc del dev eth0 clsact

搜索主动修改 qdisc 的脚本或服务：

    grep -RniE 'tc[[:space:]]+qdisc|qdisc[[:space:]]+(add|replace|del)' \
        /etc/systemd/system \
        /usr/lib/systemd/system \
        /lib/systemd/system \
        /etc/init.d \
        /etc/rc.local \
        /usr/local/bin \
        /usr/local/sbin \
        /root \
        2>/dev/null

如果存在其他调优服务，请确保 xui-limit 在其后启动，或者关闭调优脚本中的 `tc qdisc` 修改。

---

## 常见问题

### 1. 限速状态显示正常，但测速仍超过上限

检查：

- 是否测试了正确的服务器。
- 是否使用了正确的节点端口。
- 客户端是否绕过代理直连。
- IPv6 是否真正经过该节点。
- 是否选择了正确的物理网卡。
- 其他服务是否覆盖了 HTB。
- 状态统计是否随测速增长。

抓取端口流量：

    tcpdump -ni any 'tcp port 50000 or udp port 50000'

IPv6 流量：

    tcpdump -ni any 'ip6 and (tcp port 50000 or udp port 50000)'

### 2. 重启后 root 变成 fq

检查服务：

    systemctl status xui-limit.service --no-pager
    journalctl -u xui-limit.service -b --no-pager

检查授权：

    cat /etc/xui-limit/root-owned.conf

确保物理网卡名称存在，例如：

    eth0

如果没有，请运行脚本并选择菜单 `7`，确认重新接管网卡。

### 3. IFB 模块不可用

尝试：

    modprobe ifb

部分 Ubuntu 精简内核可能需要：

    apt install -y linux-modules-extra-$(uname -r)
    modprobe ifb

Debian 自定义内核或云厂商内核需要确认是否编译了 IFB 支持。

### 4. 状态页中文显示成十六进制转义

脚本使用 UTF-8 locale。

检查：

    locale -a | grep -iE '^C\.(UTF-8|utf8)$'
    LC_ALL= LANG=C.UTF-8 LC_CTYPE=C.UTF-8 locale charmap

预期输出：

    UTF-8

### 5. 显示端口 ID 冲突

脚本当前使用：

    ID = 端口 % 9000 + 1000

相差 9000 的端口可能映射到同一个 ID。

例如：

    5000
    14000
    23000

这些端口不能在同一张物理网卡上同时使用当前 ID 方案。

脚本会拒绝冲突，不会静默覆盖。

### 6. 菜单 7 无法读取接管确认

当前版本会从：

    /dev/tty

读取接管确认。

请确保在真实 SSH 终端中运行，不要通过没有终端的后台管道执行交互菜单。

### 7. 服务不断重试

先停止服务：

    systemctl stop xui-limit.service
    systemctl reset-failed xui-limit.service

查看日志：

    journalctl -u xui-limit.service -n 100 --no-pager

修复脚本或规则后重新启动：

    systemctl daemon-reload
    systemctl restart xui-limit.service

---

## 已知限制

### 端口 ID 映射

当前继续使用 `% 9000` 映射方式。相差 9000 的端口可能冲突。

### 不支持并发操作

脚本当前没有使用全局 `flock`。

请不要：

- 同时在两个 SSH 窗口修改规则。
- systemd 正在恢复时运行菜单 7。
- 同时执行添加、删除和修改。

### qdisc 独占

为了按端口限速，脚本需要管理物理网卡的 root HTB。

同一张网卡不能同时使用：

    root HTB
    root CAKE
    root fq
    root fq_codel

系统默认值可以是 `fq`，但限速生效后，实际物理网卡 root 会由 HTB 接管。

---

## 删除规则和卸载

### 删除限速规则

优先通过菜单：

    4) 删除节点双向限速
    6) 清空某网卡全部双向限速

不要在仍有 ingress 重定向时直接删除 IFB。

### 关闭开机恢复

进入：

    8) 开机自启设置

选择关闭。

也可以手动执行：

    systemctl disable --now xui-limit.service
    systemctl reset-failed xui-limit.service

### 完全卸载

请先通过菜单 `6` 清空所有受管理网卡的限速规则，然后执行：

    systemctl disable --now xui-limit.service 2>/dev/null || true
    rm -f /etc/systemd/system/xui-limit.service
    rm -f /usr/local/bin/xui-limit-restore.sh
    rm -f /usr/local/lib/xui-limit/xui-limit-manager.sh
    rm -f /root/xui-limit.sh
    systemctl daemon-reload

如果确认不再需要配置、备份和日志，可以继续删除：

    rm -rf /etc/xui-limit
    rm -f /var/log/xui-limit.log

删除前建议备份：

    cp -a /etc/xui-limit /root/xui-limit-backup-$(date +%Y%m%d_%H%M%S)

---

## 安全建议

- 使用 root 运行。
- 不要从不可信来源下载修改版脚本。
- 更新后先执行 `bash -n`。
- 接管 root qdisc 前确认服务器没有重要第三方 QoS。
- 不要同时运行多个脚本实例。
- 保留 `/etc/xui-limit/qdisc-backup/`。
- 修改 `/etc/xui-limit/*.conf` 前先备份。
- 在生产服务器升级时，建议保持另一个 SSH 会话。
- 先在测试服务器验证重启恢复。
- 云服务器存在特殊网卡、隧道或策略路由时，应先确认实际流量接口。

---

## 推荐验收流程

首次部署完成后，建议依次验证：

1. 菜单 `9` 环境检查全部通过。
2. 添加一个较低速率，例如 20 Mbps。
3. IPv4 TCP 下载测试。
4. IPv4 TCP 上传测试。
5. IPv6 TCP 下载测试。
6. IPv6 TCP 上传测试。
7. UDP 流量测试。
8. 菜单 `3` 状态显示双向正常。
9. 修改速率，确认其他端口统计不清零。
10. 删除单协议，确认另一个协议仍正常。
11. 检查物理网卡 `1:fffe`。
12. 检查 IFB `1:fffe`。
13. 启用开机自动恢复。
14. 重启服务器。
15. 重启后确认 root HTB、IFB和规则自动恢复。

重启后检查：

    tc qdisc show dev eth0
    tc class show dev eth0 classid 1:fffe
    systemctl status xui-limit.service --no-pager
    journalctl -u xui-limit.service -b --no-pager

---

## 免责声明

本脚本会修改 Linux Traffic Control、物理网卡 root qdisc、ingress filter 和 IFB 配置。

使用前请确保：

- 已理解 HTB、IFB、flower 和 mirred 的基本作用。
- 已备份服务器网络配置。
- 已确认没有其他关键 QoS 服务。
- 可以通过控制台或备用 SSH 会话恢复服务器。

因错误网卡选择、第三方脚本冲突、特殊内核、云厂商网络限制或手工修改配置导致的问题，需要根据实际环境排查。
