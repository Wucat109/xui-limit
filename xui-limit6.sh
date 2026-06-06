#!/bin/bash

CONFIG_DIR="/etc/xui-limit"
RULES_FILE="$CONFIG_DIR/rules.conf"
RESTORE_SCRIPT="/usr/local/bin/xui-limit-restore.sh"
SERVICE_FILE="/etc/systemd/system/xui-limit.service"

mkdir -p "$CONFIG_DIR"
touch "$RULES_FILE"

color_green="\033[32m"
color_red="\033[31m"
color_yellow="\033[33m"
color_blue="\033[36m"
color_reset="\033[0m"

msg()  { echo -e "${color_green}$1${color_reset}"; }
warn() { echo -e "${color_yellow}$1${color_reset}"; }
err()  { echo -e "${color_red}$1${color_reset}"; }
info() { echo -e "${color_blue}$1${color_reset}"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        err "请使用 root 运行此脚本"
        exit 1
    fi
}

trim() { echo "$1" | xargs; }

pause_enter() {
    echo
    read -rp "按回车继续..." _
}

show_table() {
    if command -v column >/dev/null 2>&1; then
        column -t -s '|'
    else
        cat
    fi
}

install_deps() {
    msg "正在安装依赖..."
    if command -v apt >/dev/null 2>&1; then
        apt update
        apt install -y iproute2 iptables sqlite3 util-linux bsdextrautils
    else
        warn "暂不支持当前包管理器，请手动安装：iproute2 iptables sqlite3"
    fi

    command -v column >/dev/null 2>&1 && msg "依赖安装完成" || info "column 未安装成功，仅影响表格对齐显示"
    command -v ip6tables >/dev/null 2>&1 || warn "未检测到 ip6tables：IPv6 限速无法生效"
}

get_default_interface() {
    ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1
}

list_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1
}

choose_interface() {
    local DEFAULT_DEV idx i default_index dev
    DEFAULT_DEV=$(get_default_interface)
    mapfile -t IFACES < <(list_interfaces)

    if [ "${#IFACES[@]}" -eq 0 ]; then
        err "未检测到任何网卡"
        return 1
    fi

    echo
    info "================ 选择网卡 ================"
    {
        echo "编号|网卡|说明"
        echo "----|----|----"
        i=1
        default_index=1
        for dev in "${IFACES[@]}"; do
            if [ "$dev" = "$DEFAULT_DEV" ]; then
                echo "${i}|${dev}|默认/推荐"
                default_index=$i
            else
                echo "${i}|${dev}|-"
            fi
            i=$((i+1))
        done
    } | show_table

    echo
    read -rp "请选择网卡编号 [默认: ${default_index}]: " idx
    idx=$(trim "$idx")
    idx=${idx:-$default_index}

    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
        err "请输入正确的网卡编号"
        return 1
    fi
    if [ "$idx" -lt 1 ] || [ "$idx" -gt "${#IFACES[@]}" ]; then
        err "网卡编号超出范围"
        return 1
    fi

    SELECTED_DEV="${IFACES[$((idx-1))]}"
    return 0
}

# 把端口映射到 1000~9999 范围内，避免 classid 过大无效
# 注意：相差 9000 的端口会映射到同一个 ID，同一网卡上不要同时限速这类端口
calc_id() {
    local PORT="$1"
    echo $((PORT % 9000 + 1000))
}

rule_exists() {
    local DEV="$1" PORT="$2" PROTO="$3"
    grep -q "^${DEV}|${PORT}|${PROTO}|" "$RULES_FILE" 2>/dev/null
}

has_any_rule_for_port() {
    local DEV="$1" PORT="$2"
    grep -q "^${DEV}|${PORT}|" "$RULES_FILE" 2>/dev/null
}

ensure_qdisc() {
    local DEV="$1"
    tc qdisc add dev "$DEV" root handle 1: htb default 999 2>/dev/null || true
    tc class replace dev "$DEV" parent 1: classid 1:999 htb rate 1000mbit ceil 1000mbit >/dev/null 2>&1
}

tc_class_exists() {
    local DEV="$1" CLASS_ID="$2"
    tc class show dev "$DEV" 2>/dev/null | grep -q "class htb ${CLASS_ID} "
}

tc_filter_exists() {
    local DEV="$1" FAMILY="$2" HANDLE="$3" CLASS_ID="$4" HANDLE_HEX
    HANDLE_HEX=$(printf '%x' "$HANDLE")
    tc filter show dev "$DEV" parent 1: protocol "$FAMILY" 2>/dev/null | grep -q "handle 0x${HANDLE_HEX}.*classid ${CLASS_ID}"
}

# 按 handle 删除 tc filter。
# 注意：部分系统的 fw filter 必须带 pref 才能删掉；只用 handle 删除可能无效。
# 这里先从 tc 输出中提取所有匹配 handle 的 pref，再逐个删除，避免残留和死循环。
tc_filter_del_safe() {
    local DEV="$1" FAMILY="$2" HANDLE="$3" HANDLE_HEX
    HANDLE_HEX=$(printf '%x' "$HANDLE")

    local prefs pref
    mapfile -t prefs < <(
        tc filter show dev "$DEV" parent 1: protocol "$FAMILY" 2>/dev/null | \
        awk -v h="handle 0x${HANDLE_HEX}" '
            $0 ~ h {
                for (i=1; i<=NF; i++) {
                    if ($i == "pref") { print $(i+1); break }
                }
            }
        '
    )

    if [ "${#prefs[@]}" -eq 0 ]; then
        tc filter del dev "$DEV" parent 1: protocol "$FAMILY" handle "$HANDLE" fw >/dev/null 2>&1 || true
        return 0
    fi

    for pref in "${prefs[@]}"; do
        [ -z "$pref" ] && continue
        tc filter del dev "$DEV" parent 1: protocol "$FAMILY" pref "$pref" handle "0x${HANDLE_HEX}" fw >/dev/null 2>&1 || \
        tc filter del dev "$DEV" parent 1: protocol "$FAMILY" pref "$pref" handle "$HANDLE" fw >/dev/null 2>&1 || true
    done
}

tc_filter_add_one() {
    local DEV="$1" FAMILY="$2" HANDLE="$3" CLASS_ID="$4"
    tc filter add dev "$DEV" parent 1: protocol "$FAMILY" handle "$HANDLE" fw flowid "$CLASS_ID" >/dev/null 2>&1
}

iptables4_rule_exists() {
    local PROTO="$1" PORT="$2" HANDLE="$3"
    iptables -t mangle -C OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null
}

iptables6_rule_exists() {
    local PROTO="$1" PORT="$2" HANDLE="$3"
    command -v ip6tables >/dev/null 2>&1 || return 1
    ip6tables -t mangle -C OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null
}

# 兼容原脚本中的旧函数名：默认检查 IPv4
iptables_rule_exists() { iptables4_rule_exists "$@"; }

add_iptables_rule() {
    local PROTO="$1" PORT="$2" HANDLE="$3" ok=1

    if ! iptables4_rule_exists "$PROTO" "$PORT" "$HANDLE"; then
        iptables -t mangle -A OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" || ok=0
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        if ! iptables6_rule_exists "$PROTO" "$PORT" "$HANDLE"; then
            ip6tables -t mangle -A OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" || ok=0
        fi
    else
        warn "未检测到 ip6tables：IPv6 的 ${PROTO}/${PORT} 限速标记未添加"
    fi

    return "$ok"
}

delete_iptables_rule() {
    local PROTO="$1" PORT="$2" HANDLE="$3"

    while iptables4_rule_exists "$PROTO" "$PORT" "$HANDLE"; do
        iptables -t mangle -D OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null || break
    done

    if command -v ip6tables >/dev/null 2>&1; then
        while iptables6_rule_exists "$PROTO" "$PORT" "$HANDLE"; do
            ip6tables -t mangle -D OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null || break
        done
    fi
}

ensure_tc_mapping_for_port() {
    local DEV="$1" PORT="$2" RATE="$3" ID CLASS_ID
    ID=$(calc_id "$PORT")
    CLASS_ID="1:${ID}"

    ensure_qdisc "$DEV"

    if ! tc class replace dev "$DEV" parent 1: classid "$CLASS_ID" htb rate "$RATE" ceil "$RATE" >/dev/null 2>&1; then
        err "创建 tc class 失败：网卡=$DEV 端口=$PORT classid=$CLASS_ID"
        return 1
    fi

    tc_filter_del_safe "$DEV" ip "$ID"
    tc_filter_del_safe "$DEV" ipv6 "$ID"

    if ! tc_filter_add_one "$DEV" ip "$ID" "$CLASS_ID"; then
        err "创建 IPv4 tc filter 失败：网卡=$DEV 端口=$PORT handle=$ID flowid=$CLASS_ID"
        return 1
    fi

    if ! tc_filter_add_one "$DEV" ipv6 "$ID" "$CLASS_ID"; then
        err "创建 IPv6 tc filter 失败：网卡=$DEV 端口=$PORT handle=$ID flowid=$CLASS_ID"
        return 1
    fi

    tc_class_exists "$DEV" "$CLASS_ID" || { err "tc class 校验失败：$CLASS_ID"; return 1; }
    tc_filter_exists "$DEV" ip "$ID" "$CLASS_ID" || { err "IPv4 tc filter 校验失败：handle=$ID classid=$CLASS_ID"; return 1; }
    tc_filter_exists "$DEV" ipv6 "$ID" "$CLASS_ID" || { err "IPv6 tc filter 校验失败：handle=$ID classid=$CLASS_ID"; return 1; }

    return 0
}

remove_tc_mapping_for_port_if_unused() {
    local DEV="$1" PORT="$2" ID CLASS_ID

    has_any_rule_for_port "$DEV" "$PORT" && return

    ID=$(calc_id "$PORT")
    CLASS_ID="1:${ID}"

    # 删除该端口对应的 IPv4/IPv6 tc filter。不要用无限 while，避免 tc 删除失败时 CPU 满载。
    tc_filter_del_safe "$DEV" ip "$ID"
    tc_filter_del_safe "$DEV" ipv6 "$ID"

    if tc_filter_exists "$DEV" ip "$ID" "$CLASS_ID"; then
        warn "IPv4 tc filter 仍有残留：网卡=$DEV 端口=$PORT handle=$ID classid=$CLASS_ID"
    fi

    if tc_filter_exists "$DEV" ipv6 "$ID" "$CLASS_ID"; then
        warn "IPv6 tc filter 仍有残留：网卡=$DEV 端口=$PORT handle=$ID classid=$CLASS_ID"
    fi

    tc class del dev "$DEV" classid "$CLASS_ID" >/dev/null 2>&1 || true

    if ! grep -q "^${DEV}|" "$RULES_FILE" 2>/dev/null; then
        tc qdisc del dev "$DEV" root >/dev/null 2>&1 || true
    fi
}

save_rule() {
    local DEV="$1" PORT="$2" PROTO="$3" RATE="$4" CLASS_ID="$5" HANDLE="$6"
    rule_exists "$DEV" "$PORT" "$PROTO" || echo "${DEV}|${PORT}|${PROTO}|${RATE}|${CLASS_ID}|${HANDLE}" >> "$RULES_FILE"
}

add_proto_rule() {
    local DEV="$1" PORT="$2" RATE="$3" PROTO="$4" ID CLASS_ID HANDLE
    ID=$(calc_id "$PORT")
    CLASS_ID="1:${ID}"
    HANDLE="$ID"

    if rule_exists "$DEV" "$PORT" "$PROTO"; then
        warn "规则已存在：网卡=$DEV 端口=$PORT 协议=$PROTO"
        return 0
    fi

    if ! ensure_tc_mapping_for_port "$DEV" "$PORT" "$RATE"; then
        err "tc 映射创建失败，已取消保存该规则"
        return 1
    fi

    if ! add_iptables_rule "$PROTO" "$PORT" "$HANDLE"; then
        err "iptables/ip6tables 规则添加失败，已取消保存该规则"
        return 1
    fi

    if ! iptables4_rule_exists "$PROTO" "$PORT" "$HANDLE"; then
        err "IPv4 iptables 规则校验失败，已取消保存该规则"
        return 1
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        if ! iptables6_rule_exists "$PROTO" "$PORT" "$HANDLE"; then
            err "IPv6 ip6tables 规则校验失败，已取消保存该规则"
            return 1
        fi
    else
        warn "ip6tables 不可用：规则已保存并对 IPv4 生效，但 IPv6 限速不会生效"
    fi

    save_rule "$DEV" "$PORT" "$PROTO" "$RATE" "$CLASS_ID" "$HANDLE"
    msg "已添加限速：网卡=$DEV 端口=$PORT 协议=$PROTO 速率=$RATE（IPv4+IPv6）"
    return 0
}

delete_proto_rule() {
    local DEV="$1" PORT="$2" PROTO="$3" LINE HANDLE
    LINE=$(grep "^${DEV}|${PORT}|${PROTO}|" "$RULES_FILE" 2>/dev/null || true)

    if [ -z "$LINE" ]; then
        warn "未找到规则：网卡=$DEV 端口=$PORT 协议=$PROTO"
        return 0
    fi

    HANDLE=$(echo "$LINE" | cut -d'|' -f6)
    delete_iptables_rule "$PROTO" "$PORT" "$HANDLE"

    grep -v "^${DEV}|${PORT}|${PROTO}|" "$RULES_FILE" > "${RULES_FILE}.tmp" || true
    mv "${RULES_FILE}.tmp" "$RULES_FILE" 2>/dev/null || true

    remove_tc_mapping_for_port_if_unused "$DEV" "$PORT"
    msg "已删除限速：网卡=$DEV 端口=$PORT 协议=$PROTO（IPv4+IPv6）"
}

update_rate_for_port() {
    local DEV="$1" PORT="$2" NEW_RATE="$3" ID CLASS_ID
    ID=$(calc_id "$PORT")
    CLASS_ID="1:${ID}"

    if ! has_any_rule_for_port "$DEV" "$PORT"; then
        err "未找到该端口对应的限速规则"
        return 1
    fi

    if ! tc class replace dev "$DEV" parent 1: classid "$CLASS_ID" htb rate "$NEW_RATE" ceil "$NEW_RATE" >/dev/null 2>&1; then
        err "修改 tc class 失败：$CLASS_ID"
        return 1
    fi

    awk -F'|' -v dev="$DEV" -v port="$PORT" -v rate="$NEW_RATE" '
    BEGIN{OFS="|"}
    {
        if ($1==dev && $2==port) $4=rate;
        print
    }' "$RULES_FILE" > "${RULES_FILE}.tmp" && mv "${RULES_FILE}.tmp" "$RULES_FILE"

    msg "已修改限速：网卡=$DEV 端口=$PORT 新速率=$NEW_RATE"
}

detect_xui_db() {
    local candidates=(
        "/etc/x-ui/x-ui.db"
        "/usr/local/x-ui/x-ui.db"
        "/etc/3x-ui/x-ui.db"
        "/usr/local/3x-ui/x-ui.db"
        "/opt/x-ui/x-ui.db"
        "/opt/3x-ui/x-ui.db"
        "/root/x-ui.db"
    )
    local db found

    for db in "${candidates[@]}"; do
        if [ -f "$db" ]; then
            XUI_DB_PATH="$db"
            return 0
        fi
    done

    found=$(find / -name "x-ui.db" 2>/dev/null | head -n1)
    if [ -n "$found" ] && [ -f "$found" ]; then
        XUI_DB_PATH="$found"
        return 0
    fi

    return 1
}

query_xui_nodes_enabled() {
    local DB="$1"
    sqlite3 -separator '|' "$DB" "
        SELECT
            COALESCE(id,''),
            COALESCE(remark,''),
            COALESCE(port,''),
            COALESCE(protocol,''),
            COALESCE(enable,'')
        FROM inbounds
        WHERE enable IN (1,'1',true,'true')
        ORDER BY id ASC;
    " 2>/dev/null
}

query_xui_nodes_all() {
    local DB="$1"
    sqlite3 -separator '|' "$DB" "
        SELECT
            COALESCE(id,''),
            COALESCE(remark,''),
            COALESCE(port,''),
            COALESCE(protocol,''),
            COALESCE(enable,'')
        FROM inbounds
        ORDER BY
            CASE WHEN enable IN (1,'1',true,'true') THEN 0 ELSE 1 END,
            id ASC;
    " 2>/dev/null
}

port_is_limited_anywhere() {
    local PORT="$1"
    grep -q "|${PORT}|" "$RULES_FILE" 2>/dev/null
}

choose_xui_node_or_manual_port() {
    if ! command -v sqlite3 >/dev/null 2>&1; then
        warn "未检测到 sqlite3，将回退为手动输入端口"
        SELECTED_PORT=""; SELECTED_REMARK="-"; SELECTED_NODE_PROTO="-"
        return 1
    fi

    if ! detect_xui_db; then
        warn "未找到 x-ui.db，将回退为手动输入端口"
        SELECTED_PORT=""; SELECTED_REMARK="-"; SELECTED_NODE_PROTO="-"
        return 1
    fi

    local DB rows row nid remark port proto enable state limited i choice selected
    DB="$XUI_DB_PATH"
    rows=$(query_xui_nodes_enabled "$DB")

    if [ -z "$rows" ]; then
        warn "未读取到启用中的节点，尝试读取全部节点..."
        rows=$(query_xui_nodes_all "$DB")
    fi

    if [ -z "$rows" ]; then
        warn "已找到数据库：$DB，但未能读取到节点，将回退为手动输入端口"
        SELECTED_PORT=""; SELECTED_REMARK="-"; SELECTED_NODE_PROTO="-"
        return 1
    fi

    mapfile -t NODE_ROWS <<< "$rows"

    echo
    info "================ 选择 x-ui 节点 ================"
    echo "数据库：$DB"
    {
        echo "编号|状态|端口|协议|备注|限速状态"
        echo "----|----|----|----|----|--------"
        i=1
        for row in "${NODE_ROWS[@]}"; do
            IFS='|' read -r nid remark port proto enable <<< "$row"
            [ -z "$remark" ] && remark="-"
            [ -z "$proto" ] && proto="-"
            state="停用"
            [[ "$enable" == "1" || "$enable" == "true" || "$enable" == "TRUE" ]] && state="启用"
            limited="未限速"
            [[ "$port" =~ ^[0-9]+$ ]] && port_is_limited_anywhere "$port" && limited="已限速"
            echo "${i}|${state}|${port}|${proto}|${remark}|${limited}"
            i=$((i+1))
        done
    } | show_table

    echo
    read -rp "请选择节点编号（输入 m 可手动输入端口）: " choice
    choice=$(trim "$choice")

    if [[ "$choice" == "m" || "$choice" == "M" ]]; then
        SELECTED_PORT=""; SELECTED_REMARK="-"; SELECTED_NODE_PROTO="-"
        return 1
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        err "请输入正确的节点编号"
        return 2
    fi
    if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#NODE_ROWS[@]}" ]; then
        err "节点编号超出范围"
        return 2
    fi

    selected="${NODE_ROWS[$((choice-1))]}"
    IFS='|' read -r nid remark port proto enable <<< "$selected"

    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        warn "所选节点端口无效，将回退为手动输入端口"
        SELECTED_PORT=""; SELECTED_REMARK="-"; SELECTED_NODE_PROTO="-"
        return 1
    fi

    [ -z "$remark" ] && remark="-"
    [ -z "$proto" ] && proto="-"
    SELECTED_PORT="$port"
    SELECTED_REMARK="$remark"
    SELECTED_NODE_PROTO="$proto"

    echo
    info "已选择节点：端口=$port  协议=$proto  备注=$remark"
    return 0
}

input_manual_port() {
    local PORT
    read -rp "请输入要操作的节点端口: " PORT
    PORT=$(trim "$PORT")
    if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
        err "端口必须是数字"
        return 1
    fi
    SELECTED_PORT="$PORT"
    SELECTED_REMARK="-"
    SELECTED_NODE_PROTO="-"
    return 0
}

choose_protocol_with_recommend() {
    local NODE_PROTO="$1" pchoice

    echo
    info "================ 选择协议类型 ================"
    if [[ "$NODE_PROTO" == "vless" || "$NODE_PROTO" == "vmess" || "$NODE_PROTO" == "trojan" ]]; then
        echo "推荐：此类常见 TCP 节点通常优先选择『仅 TCP』"
    elif [[ "$NODE_PROTO" == "tunnel" ]]; then
        echo "提示：此类节点可能涉及 TCP/UDP，如不确定可选择『TCP + UDP』"
    else
        echo "提示：如不确定，可选择『TCP + UDP』"
    fi
    echo
    {
        echo "编号|含义"
        echo "----|----"
        echo "1|仅 TCP"
        echo "2|仅 UDP"
        echo "3|TCP + UDP"
    } | show_table

    echo
    read -rp "请输入协议编号 [1-3]: " pchoice
    pchoice=$(trim "$pchoice")
    case "$pchoice" in
        1) SELECTED_PROTO="tcp" ;;
        2) SELECTED_PROTO="udp" ;;
        3) SELECTED_PROTO="both" ;;
        *) SELECTED_PROTO="invalid" ;;
    esac
}

create_merged_rules_cache() {
    MERGED_RULES=()
    [ -s "$RULES_FILE" ] || return 0

    local keys=() dev port proto rate classid handle key tcp_exists udp_exists proto_show
    while IFS='|' read -r dev port proto rate classid handle; do
        [ -z "$dev" ] && continue
        key="${dev}|${port}"
        if [[ ! " ${keys[*]} " =~ " ${key} " ]]; then
            keys+=("$key")
        fi
    done < "$RULES_FILE"

    for key in "${keys[@]}"; do
        dev=$(echo "$key" | cut -d'|' -f1)
        port=$(echo "$key" | cut -d'|' -f2)
        rate=$(grep "^${dev}|${port}|" "$RULES_FILE" | head -n1 | cut -d'|' -f4)
        tcp_exists=0; udp_exists=0
        grep -q "^${dev}|${port}|tcp|" "$RULES_FILE" 2>/dev/null && tcp_exists=1
        grep -q "^${dev}|${port}|udp|" "$RULES_FILE" 2>/dev/null && udp_exists=1
        proto_show="-"
        [ "$tcp_exists" -eq 1 ] && proto_show="tcp"
        [ "$udp_exists" -eq 1 ] && proto_show="udp"
        [ "$tcp_exists" -eq 1 ] && [ "$udp_exists" -eq 1 ] && proto_show="tcp+udp"
        MERGED_RULES+=("${dev}|${port}|${proto_show}|${rate}")
    done
}

choose_existing_limited_rule() {
    local idx i row dev port proto rate selected
    create_merged_rules_cache

    if [ "${#MERGED_RULES[@]}" -eq 0 ]; then
        warn "当前没有任何已配置的限速规则"
        return 1
    fi

    echo
    info "================ 选择已限速规则 ================"
    {
        echo "编号|网卡|端口|协议|速率"
        echo "----|----|----|----|----"
        i=1
        for row in "${MERGED_RULES[@]}"; do
            IFS='|' read -r dev port proto rate <<< "$row"
            echo "${i}|${dev}|${port}|${proto}|${rate}"
            i=$((i+1))
        done
    } | show_table

    echo
    read -rp "请选择规则编号: " idx
    idx=$(trim "$idx")
    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
        err "请输入正确的规则编号"
        return 1
    fi
    if [ "$idx" -lt 1 ] || [ "$idx" -gt "${#MERGED_RULES[@]}" ]; then
        err "规则编号超出范围"
        return 1
    fi

    selected="${MERGED_RULES[$((idx-1))]}"
    IFS='|' read -r SELECTED_DEV SELECTED_PORT SELECTED_PROTO_SHOW SELECTED_RATE <<< "$selected"
    return 0
}

confirm_action() {
    local ACTION="$1" DEV="$2" PORT="$3" REMARK="$4" PROTO="$5" RATE="$6" CONFIRM
    echo
    info "================ 操作确认 ================"
    {
        echo "项目|内容"
        echo "----|----"
        echo "动作|$ACTION"
        echo "网卡|$DEV"
        echo "端口|$PORT"
        echo "备注|$REMARK"
        echo "协议|$PROTO"
        [ -n "$RATE" ] && echo "速率|$RATE"
        echo "IP版本|IPv4 + IPv6"
    } | show_table
    echo
    read -rp "确认继续？[y/n]: " CONFIRM
    case "$CONFIRM" in
        y|Y) return 0 ;;
        *) warn "已取消操作"; return 1 ;;
    esac
}

iptables_hits_one_family() {
    local TOOL="$1" PORT="$2" PROTO_SHOW="$3" total=0 v
    command -v "$TOOL" >/dev/null 2>&1 || { echo 0; return; }

    if [ "$PROTO_SHOW" = "tcp" ] || [ "$PROTO_SHOW" = "tcp+udp" ]; then
        v=$($TOOL -t mangle -L OUTPUT -n -v -x 2>/dev/null | awk -v p="spt:${PORT}" '$0 ~ /tcp/ && $0 ~ p {sum+=$1} END{print sum+0}')
        total=$((total + v))
    fi
    if [ "$PROTO_SHOW" = "udp" ] || [ "$PROTO_SHOW" = "tcp+udp" ]; then
        v=$($TOOL -t mangle -L OUTPUT -n -v -x 2>/dev/null | awk -v p="spt:${PORT}" '$0 ~ /udp/ && $0 ~ p {sum+=$1} END{print sum+0}')
        total=$((total + v))
    fi
    echo "$total"
}

iptables_hits_for_rule() {
    local PORT="$1" PROTO_SHOW="$2" v4 v6
    v4=$(iptables_hits_one_family iptables "$PORT" "$PROTO_SHOW")
    v6=$(iptables_hits_one_family ip6tables "$PORT" "$PROTO_SHOW")
    echo $((v4 + v6))
}

iptables_proto_show_ok_v4() {
    local PORT="$1" PROTO_SHOW="$2" HANDLE="$3"
    case "$PROTO_SHOW" in
        tcp) iptables4_rule_exists tcp "$PORT" "$HANDLE" ;;
        udp) iptables4_rule_exists udp "$PORT" "$HANDLE" ;;
        *) iptables4_rule_exists tcp "$PORT" "$HANDLE" && iptables4_rule_exists udp "$PORT" "$HANDLE" ;;
    esac
}

iptables_proto_show_ok_v6() {
    local PORT="$1" PROTO_SHOW="$2" HANDLE="$3"
    command -v ip6tables >/dev/null 2>&1 || return 2
    case "$PROTO_SHOW" in
        tcp) iptables6_rule_exists tcp "$PORT" "$HANDLE" ;;
        udp) iptables6_rule_exists udp "$PORT" "$HANDLE" ;;
        *) iptables6_rule_exists tcp "$PORT" "$HANDLE" && iptables6_rule_exists udp "$PORT" "$HANDLE" ;;
    esac
}

rule_loaded_status() {
    local DEV="$1" PORT="$2" PROTO_SHOW="$3" ID CLASS_ID class_ok=1 v4_ok=1 v6_ok=1 v6_available=1
    ID=$(calc_id "$PORT")
    CLASS_ID="1:${ID}"

    tc_class_exists "$DEV" "$CLASS_ID" || class_ok=0
    tc_filter_exists "$DEV" ip "$ID" "$CLASS_ID" || v4_ok=0
    iptables_proto_show_ok_v4 "$PORT" "$PROTO_SHOW" "$ID" || v4_ok=0

    if command -v ip6tables >/dev/null 2>&1; then
        tc_filter_exists "$DEV" ipv6 "$ID" "$CLASS_ID" || v6_ok=0
        iptables_proto_show_ok_v6 "$PORT" "$PROTO_SHOW" "$ID" || v6_ok=0
    else
        v6_available=0
        v6_ok=0
    fi

    if [ "$class_ok" -eq 1 ] && [ "$v4_ok" -eq 1 ] && [ "$v6_ok" -eq 1 ]; then
        echo "已加载(v4+v6)"
    elif [ "$class_ok" -eq 1 ] && [ "$v4_ok" -eq 1 ] && [ "$v6_available" -eq 0 ]; then
        echo "IPv4已加载/IPv6不可用"
    elif [ "$class_ok" -eq 1 ] && [ "$v4_ok" -eq 1 ]; then
        echo "IPv6异常"
    elif [ "$class_ok" -eq 1 ] && [ "$v6_ok" -eq 1 ]; then
        echo "IPv4异常"
    else
        echo "异常"
    fi
}

show_status_simple() {
    local i row dev port proto rate loaded hits hit_text
    create_merged_rules_cache
    echo
    info "================ 当前限速状态（简洁视图） ================"
    if [ "${#MERGED_RULES[@]}" -eq 0 ]; then
        warn "当前没有任何限速规则"
        return
    fi
    {
        echo "编号|网卡|端口|协议|速率|加载状态|流量命中"
        echo "----|----|----|----|----|--------|--------"
        i=1
        for row in "${MERGED_RULES[@]}"; do
            IFS='|' read -r dev port proto rate <<< "$row"
            loaded=$(rule_loaded_status "$dev" "$port" "$proto")
            hits=$(iptables_hits_for_rule "$port" "$proto")
            [ "$hits" -gt 0 ] && hit_text="有" || hit_text="暂无"
            echo "${i}|${dev}|${port}|${proto}|${rate}|${loaded}|${hit_text}"
            i=$((i+1))
        done
    } | show_table
}

show_status_with_debug_hint() {
    show_status_simple
    echo
    echo "如需查看底层调试信息，可手动执行："
    echo "iptables -t mangle -L OUTPUT -n -v"
    echo "ip6tables -t mangle -L OUTPUT -n -v"
    echo "tc class show dev <网卡名>"
    echo "tc filter show dev <网卡名> parent 1: protocol ip"
    echo "tc filter show dev <网卡名> parent 1: protocol ipv6"
    echo "tc -s class show dev <网卡名>"
}

delete_all_rules_for_dev() {
    local DEV="$1" RDEV PORT PROTO RATE CLASS_ID HANDLE
    if [ -f "$RULES_FILE" ]; then
        while IFS='|' read -r RDEV PORT PROTO RATE CLASS_ID HANDLE; do
            [ -z "$RDEV" ] && continue
            [ "$RDEV" = "$DEV" ] && delete_iptables_rule "$PROTO" "$PORT" "$HANDLE"
        done < "$RULES_FILE"

        grep -v "^${DEV}|" "$RULES_FILE" > "${RULES_FILE}.tmp" || true
        mv "${RULES_FILE}.tmp" "$RULES_FILE" 2>/dev/null || true
    fi
    tc qdisc del dev "$DEV" root >/dev/null 2>&1 || true
    msg "已删除网卡 $DEV 的全部限速规则（IPv4+IPv6）"
}

create_restore_script() {
    cat > "$RESTORE_SCRIPT" <<'RESTORE_EOF'
#!/bin/bash

RULES_FILE="/etc/xui-limit/rules.conf"
[ -f "$RULES_FILE" ] || exit 0

ensure_qdisc() {
    local DEV="$1"
    tc qdisc add dev "$DEV" root handle 1: htb default 999 2>/dev/null || true
    tc class replace dev "$DEV" parent 1: classid 1:999 htb rate 1000mbit ceil 1000mbit >/dev/null 2>&1
}

iptables4_rule_exists() {
    local PROTO="$1" PORT="$2" HANDLE="$3"
    iptables -t mangle -C OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null
}

iptables6_rule_exists() {
    local PROTO="$1" PORT="$2" HANDLE="$3"
    command -v ip6tables >/dev/null 2>&1 || return 1
    ip6tables -t mangle -C OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null
}

add_mark_rules() {
    local PROTO="$1" PORT="$2" HANDLE="$3"
    if ! iptables4_rule_exists "$PROTO" "$PORT" "$HANDLE"; then
        iptables -t mangle -A OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null || true
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        if ! iptables6_rule_exists "$PROTO" "$PORT" "$HANDLE"; then
            ip6tables -t mangle -A OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null || true
        fi
    fi
}

# 恢复时也按 pref 清理旧 tc filter，避免重复堆积。
tc_filter_del_by_handle() {
    local DEV="$1" FAMILY="$2" HANDLE="$3" HANDLE_HEX
    HANDLE_HEX=$(printf '%x' "$HANDLE")

    local prefs pref
    mapfile -t prefs < <(
        tc filter show dev "$DEV" parent 1: protocol "$FAMILY" 2>/dev/null | \
        awk -v h="handle 0x${HANDLE_HEX}" '
            $0 ~ h {
                for (i=1; i<=NF; i++) {
                    if ($i == "pref") { print $(i+1); break }
                }
            }
        '
    )

    if [ "${#prefs[@]}" -eq 0 ]; then
        tc filter del dev "$DEV" parent 1: protocol "$FAMILY" handle "$HANDLE" fw >/dev/null 2>&1 || true
        return 0
    fi

    for pref in "${prefs[@]}"; do
        [ -z "$pref" ] && continue
        tc filter del dev "$DEV" parent 1: protocol "$FAMILY" pref "$pref" handle "0x${HANDLE_HEX}" fw >/dev/null 2>&1 || \
        tc filter del dev "$DEV" parent 1: protocol "$FAMILY" pref "$pref" handle "$HANDLE" fw >/dev/null 2>&1 || true
    done
}

sort -u "$RULES_FILE" | while IFS='|' read -r DEV PORT PROTO RATE CLASS_ID HANDLE; do
    [ -z "$DEV" ] && continue
    ensure_qdisc "$DEV"
    add_mark_rules "$PROTO" "$PORT" "$HANDLE"

    if ! tc class replace dev "$DEV" parent 1: classid "$CLASS_ID" htb rate "$RATE" ceil "$RATE" >/dev/null 2>&1; then
        continue
    fi

    tc_filter_del_by_handle "$DEV" ip "$HANDLE"
    tc_filter_del_by_handle "$DEV" ipv6 "$HANDLE"
    tc filter add dev "$DEV" parent 1: protocol ip handle "$HANDLE" fw flowid "$CLASS_ID" >/dev/null 2>&1 || true
    tc filter add dev "$DEV" parent 1: protocol ipv6 handle "$HANDLE" fw flowid "$CLASS_ID" >/dev/null 2>&1 || true
done
RESTORE_EOF
    chmod +x "$RESTORE_SCRIPT"
}

create_service() {
    cat > "$SERVICE_FILE" <<SERVICE_EOF
[Unit]
Description=Restore xui-limit rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$RESTORE_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE_EOF
}

enable_autostart() {
    create_restore_script
    create_service
    systemctl daemon-reload
    systemctl enable xui-limit.service >/dev/null 2>&1 || true
    systemctl restart xui-limit.service
    msg "已启用开机自动恢复当前限速规则（IPv4+IPv6）"
}

disable_autostart() {
    systemctl disable xui-limit.service >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    msg "已关闭开机自动恢复当前限速规则"
}

environment_check() {
    echo
    info "================ 环境检查 ================"
    [ "$EUID" -eq 0 ] && msg "[OK] root 权限" || err "[FAIL] 需要 root 权限"
    command -v iptables >/dev/null 2>&1 && msg "[OK] iptables 可用（IPv4）" || err "[FAIL] iptables 不可用（IPv4 限速不可用）"
    command -v ip6tables >/dev/null 2>&1 && msg "[OK] ip6tables 可用（IPv6）" || warn "[WARN] ip6tables 不可用（IPv6 限速不可用）"
    command -v tc >/dev/null 2>&1 && msg "[OK] tc 可用" || err "[FAIL] tc 不可用"
    command -v sqlite3 >/dev/null 2>&1 && msg "[OK] sqlite3 可用" || warn "[WARN] sqlite3 不可用（无法读取 x-ui 节点信息）"
    command -v column >/dev/null 2>&1 && msg "[OK] column 可用" || info "[INFO] column 不可用（仅影响表格对齐显示）"
    detect_xui_db && msg "[OK] 已检测到 x-ui.db：$XUI_DB_PATH" || warn "[WARN] 未检测到 x-ui.db"
    systemctl is-enabled xui-limit.service >/dev/null 2>&1 && msg "[OK] 开机自动恢复当前限速规则：已启用" || warn "[WARN] 开机自动恢复当前限速规则：未启用"
}

repair_and_cleanup() {
    local c dev port proto rate classid handle devs=()
    echo
    info "================ 修复 / 清理残留规则 ================"
    echo "此操作会："
    echo "1) 删除 rules.conf 中的重复记录"
    echo "2) 删除脚本规则对应的 IPv4 iptables 标记"
    echo "3) 删除脚本规则对应的 IPv6 ip6tables 标记"
    echo "4) 清空相关网卡上的 tc root qdisc"
    echo "5) 按当前 rules.conf 重新加载 IPv4 + IPv6 限速规则"
    echo
    read -rp "确认继续？[y/n]: " c
    case "$c" in y|Y) ;; *) warn "已取消"; return ;; esac

    if [ -s "$RULES_FILE" ]; then
        sort -u "$RULES_FILE" > "${RULES_FILE}.tmp" && mv "${RULES_FILE}.tmp" "$RULES_FILE"
        while IFS='|' read -r dev port proto rate classid handle; do
            [ -z "$dev" ] && continue
            delete_iptables_rule "$proto" "$port" "$handle"
            [[ ! " ${devs[*]} " =~ " ${dev} " ]] && devs+=("$dev")
        done < "$RULES_FILE"
        for dev in "${devs[@]}"; do
            tc qdisc del dev "$dev" root >/dev/null 2>&1 || true
        done
    fi

    create_restore_script
    bash "$RESTORE_SCRIPT"
    msg "修复完成，已按当前规则重新加载 IPv4 + IPv6 限速"
}

add_limit_interactive() {
    local DEV node_result PORT REMARK NODE_PROTO MBPS RATE PROTO PROTO_SHOW AUTO ok=1
    echo
    info "================ 添加节点限速 ================"
    choose_interface || return
    DEV="$SELECTED_DEV"

    choose_xui_node_or_manual_port
    node_result=$?
    if [ "$node_result" -eq 1 ]; then
        info "已切换到手动输入端口模式"
        input_manual_port || return
    elif [ "$node_result" -eq 2 ]; then
        return
    fi

    PORT="$SELECTED_PORT"
    REMARK="$SELECTED_REMARK"
    NODE_PROTO="$SELECTED_NODE_PROTO"

    echo
    read -rp "请输入限速值（单位 Mbps，例如 20）: " MBPS
    MBPS=$(trim "$MBPS")
    if ! [[ "$MBPS" =~ ^[0-9]+$ ]]; then
        err "速率必须是数字"
        return
    fi
    RATE="${MBPS}mbit"

    choose_protocol_with_recommend "$NODE_PROTO"
    PROTO="$SELECTED_PROTO"
    if [ "$PROTO" = "invalid" ]; then
        err "协议选择无效"
        return
    fi

    PROTO_SHOW="$PROTO"
    [ "$PROTO_SHOW" = "both" ] && PROTO_SHOW="tcp+udp"
    confirm_action "添加限速" "$DEV" "$PORT" "$REMARK" "$PROTO_SHOW" "$RATE" || return

    case "$PROTO" in
        tcp) add_proto_rule "$DEV" "$PORT" "$RATE" tcp || ok=0 ;;
        udp) add_proto_rule "$DEV" "$PORT" "$RATE" udp || ok=0 ;;
        both)
            add_proto_rule "$DEV" "$PORT" "$RATE" tcp || ok=0
            add_proto_rule "$DEV" "$PORT" "$RATE" udp || ok=0
            ;;
    esac

    if [ "$ok" -ne 1 ]; then
        err "添加限速未完全成功，请检查上方错误信息"
        return
    fi

    echo
    echo "说明：启用后，服务器重启时会自动重新加载当前已保存的 IPv4 + IPv6 限速规则。"
    read -rp "是否启用开机自动恢复当前限速规则？[y/n]: " AUTO
    case "$AUTO" in y|Y) enable_autostart ;; *) warn "未启用开机自动恢复当前限速规则" ;; esac
}

delete_limit_interactive() {
    local DEV PORT PROTO_SHOW RATE mode DELETE_MODE show_proto
    echo
    info "================ 删除节点限速 ================"
    choose_existing_limited_rule || return
    DEV="$SELECTED_DEV"
    PORT="$SELECTED_PORT"
    PROTO_SHOW="$SELECTED_PROTO_SHOW"
    RATE="$SELECTED_RATE"

    echo
    echo "请选择删除方式："
    {
        echo "编号|含义"
        echo "----|----"
        echo "1|删除该节点的全部限速"
        echo "2|仅删除指定协议的限速"
    } | show_table
    echo
    read -rp "请输入选项 [1-2]: " mode
    mode=$(trim "$mode")

    if [ "$mode" = "1" ]; then
        DELETE_MODE="all"
    elif [ "$mode" = "2" ]; then
        choose_protocol_with_recommend "-"
        case "$SELECTED_PROTO" in
            tcp) DELETE_MODE="tcp" ;;
            udp) DELETE_MODE="udp" ;;
            both) DELETE_MODE="both" ;;
            *) err "协议选择无效"; return ;;
        esac
    else
        err "删除方式无效"
        return
    fi

    show_proto="$PROTO_SHOW"
    [ "$DELETE_MODE" = "tcp" ] && show_proto="tcp"
    [ "$DELETE_MODE" = "udp" ] && show_proto="udp"
    [ "$DELETE_MODE" = "both" ] && show_proto="tcp+udp"
    confirm_action "删除限速" "$DEV" "$PORT" "-" "$show_proto" "$RATE" || return

    case "$DELETE_MODE" in
        all)
            grep -q "^${DEV}|${PORT}|tcp|" "$RULES_FILE" 2>/dev/null && delete_proto_rule "$DEV" "$PORT" tcp
            grep -q "^${DEV}|${PORT}|udp|" "$RULES_FILE" 2>/dev/null && delete_proto_rule "$DEV" "$PORT" udp
            ;;
        tcp) delete_proto_rule "$DEV" "$PORT" tcp ;;
        udp) delete_proto_rule "$DEV" "$PORT" udp ;;
        both)
            delete_proto_rule "$DEV" "$PORT" tcp
            delete_proto_rule "$DEV" "$PORT" udp
            ;;
    esac
}

modify_limit_interactive() {
    local DEV PORT PROTO_SHOW MBPS NEW_RATE
    echo
    info "================ 修改节点限速 ================"
    choose_existing_limited_rule || return
    DEV="$SELECTED_DEV"
    PORT="$SELECTED_PORT"
    PROTO_SHOW="$SELECTED_PROTO_SHOW"

    echo
    read -rp "请输入新的限速值（单位 Mbps，例如 20）: " MBPS
    MBPS=$(trim "$MBPS")
    if ! [[ "$MBPS" =~ ^[0-9]+$ ]]; then
        err "速率必须是数字"
        return
    fi
    NEW_RATE="${MBPS}mbit"
    confirm_action "修改限速" "$DEV" "$PORT" "-" "$PROTO_SHOW" "$NEW_RATE" || return
    update_rate_for_port "$DEV" "$PORT" "$NEW_RATE"
}

delete_all_interactive() {
    local DEV
    echo
    info "================ 清空某网卡全部限速 ================"
    choose_interface || return
    DEV="$SELECTED_DEV"
    confirm_action "清空某网卡全部限速" "$DEV" "-" "-" "-" "-" || return
    delete_all_rules_for_dev "$DEV"
}

autostart_menu() {
    local c
    echo
    info "================ 开机自启设置 ================"
    {
        echo "编号|含义"
        echo "----|----"
        echo "1|启用开机自动恢复当前限速规则"
        echo "2|关闭开机自动恢复当前限速规则"
    } | show_table
    echo
    read -rp "请选择 [1-2]: " c
    case "$c" in
        1) enable_autostart ;;
        2) disable_autostart ;;
        *) err "无效选择" ;;
    esac
}

main_menu() {
    while true; do
        echo
        info "================ x-ui 节点限速管理 ================"
        echo "1) 安装依赖"
        echo "2) 添加节点限速"
        echo "3) 查看当前状态"
        echo "4) 删除节点限速"
        echo "5) 修改节点限速"
        echo "6) 清空某网卡全部限速"
        echo "7) 修复/清理残留规则"
        echo "8) 开机自启设置"
        echo "9) 环境检查"
        echo "0) 退出"
        echo "=================================================="
        read -rp "请输入选项: " CHOICE

        case "$CHOICE" in
            1) install_deps; pause_enter ;;
            2) add_limit_interactive; pause_enter ;;
            3) show_status_with_debug_hint; pause_enter ;;
            4) delete_limit_interactive; pause_enter ;;
            5) modify_limit_interactive; pause_enter ;;
            6) delete_all_interactive; pause_enter ;;
            7) repair_and_cleanup; pause_enter ;;
            8) autostart_menu; pause_enter ;;
            9) environment_check; pause_enter ;;
            0) exit 0 ;;
            *) err "无效选项，请重新输入" ;;
        esac
    done
}

check_root
main_menu
