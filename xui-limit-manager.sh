#!/bin/bash

CONFIG_DIR="/etc/xui-node-limit"
RULES_FILE="$CONFIG_DIR/rules.conf"
RESTORE_SCRIPT="/usr/local/bin/xui-node-limit-restore.sh"
SERVICE_FILE="/etc/systemd/system/xui-node-limit.service"

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

trim() {
    echo "$1" | xargs
}

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
    apt update
    apt install -y iproute2 iptables sqlite3 bsdextrautils
    msg "依赖安装完成"
}

get_default_interface() {
    ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1
}

list_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1
}

choose_interface() {
    local DEFAULT_DEV
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
        local i=1
        local default_index=1
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

# 修复点：把 ID 限制在 1000~9999 范围内，避免 classid 过大无效
calc_id() {
    local PORT="$1"
    echo $((PORT % 9000 + 1000))
}

rule_exists() {
    local DEV="$1"
    local PORT="$2"
    local PROTO="$3"
    grep -q "^${DEV}|${PORT}|${PROTO}|" "$RULES_FILE" 2>/dev/null
}

has_any_rule_for_port() {
    local DEV="$1"
    local PORT="$2"
    grep -q "^${DEV}|${PORT}|" "$RULES_FILE" 2>/dev/null
}

ensure_qdisc() {
    local DEV="$1"
    tc qdisc add dev "$DEV" root handle 1: htb default 999 2>/dev/null || true
    tc class replace dev "$DEV" parent 1: classid 1:999 htb rate 1000mbit ceil 1000mbit >/dev/null 2>&1
}

iptables_rule_exists() {
    local PROTO="$1"
    local PORT="$2"
    local HANDLE="$3"
    iptables -t mangle -C OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null
}

add_iptables_rule() {
    local PROTO="$1"
    local PORT="$2"
    local HANDLE="$3"

    if ! iptables_rule_exists "$PROTO" "$PORT" "$HANDLE"; then
        iptables -t mangle -A OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE"
    fi
}

delete_iptables_rule() {
    local PROTO="$1"
    local PORT="$2"
    local HANDLE="$3"

    while iptables_rule_exists "$PROTO" "$PORT" "$HANDLE"; do
        iptables -t mangle -D OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null || true
    done
}

# 关键修复：必须确保 tc class/filter 都成功，才返回成功
ensure_tc_mapping_for_port() {
    local DEV="$1"
    local PORT="$2"
    local RATE="$3"

    local ID CLASS_ID HANDLE_HEX
    ID=$(calc_id "$PORT")
    CLASS_ID="1:${ID}"
    HANDLE_HEX=$(printf '%x' "$ID")

    ensure_qdisc "$DEV"

    if ! tc class replace dev "$DEV" parent 1: classid "$CLASS_ID" htb rate "$RATE" ceil "$RATE" >/dev/null 2>&1; then
        err "创建 tc class 失败：网卡=$DEV 端口=$PORT classid=$CLASS_ID"
        return 1
    fi

    tc filter del dev "$DEV" parent 1: protocol ip handle "$ID" fw >/dev/null 2>&1 || true

    if ! tc filter add dev "$DEV" parent 1: protocol ip handle "$ID" fw flowid "$CLASS_ID" >/dev/null 2>&1; then
        err "创建 tc filter 失败：网卡=$DEV 端口=$PORT handle=$ID flowid=$CLASS_ID"
        return 1
    fi

    tc class show dev "$DEV" 2>/dev/null | grep -q "class htb ${CLASS_ID} " || {
        err "tc class 校验失败：$CLASS_ID"
        return 1
    }

    tc filter show dev "$DEV" parent 1: 2>/dev/null | grep -q "handle 0x${HANDLE_HEX} classid ${CLASS_ID}" || {
        err "tc filter 校验失败：handle=0x${HANDLE_HEX} classid=${CLASS_ID}"
        return 1
    }

    return 0
}

remove_tc_mapping_for_port_if_unused() {
    local DEV="$1"
    local PORT="$2"

    if has_any_rule_for_port "$DEV" "$PORT"; then
        return
    fi

    local ID CLASS_ID
    ID=$(calc_id "$PORT")
    CLASS_ID="1:${ID}"

    while tc filter show dev "$DEV" parent 1: 2>/dev/null | grep -q "handle 0x$(printf '%x' "$ID")"; do
        tc filter del dev "$DEV" parent 1: protocol ip handle "$ID" fw >/dev/null 2>&1 || break
    done

    tc class del dev "$DEV" classid "$CLASS_ID" >/dev/null 2>&1 || true

    if ! grep -q "^${DEV}|" "$RULES_FILE" 2>/dev/null; then
        tc qdisc del dev "$DEV" root >/dev/null 2>&1 || true
    fi
}

save_rule() {
    local DEV="$1"
    local PORT="$2"
    local PROTO="$3"
    local RATE="$4"
    local CLASS_ID="$5"
    local HANDLE="$6"

    if ! rule_exists "$DEV" "$PORT" "$PROTO"; then
        echo "${DEV}|${PORT}|${PROTO}|${RATE}|${CLASS_ID}|${HANDLE}" >> "$RULES_FILE"
    fi
}

add_proto_rule() {
    local DEV="$1"
    local PORT="$2"
    local RATE="$3"
    local PROTO="$4"

    local ID CLASS_ID HANDLE
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
        err "iptables 规则添加失败，已取消保存该规则"
        return 1
    fi

    if ! iptables_rule_exists "$PROTO" "$PORT" "$HANDLE"; then
        err "iptables 规则校验失败，已取消保存该规则"
        return 1
    fi

    save_rule "$DEV" "$PORT" "$PROTO" "$RATE" "$CLASS_ID" "$HANDLE"
    msg "已添加限速：网卡=$DEV 端口=$PORT 协议=$PROTO 速率=$RATE"
    return 0
}

delete_proto_rule() {
    local DEV="$1"
    local PORT="$2"
    local PROTO="$3"

    local LINE
    LINE=$(grep "^${DEV}|${PORT}|${PROTO}|" "$RULES_FILE" 2>/dev/null || true)

    if [ -z "$LINE" ]; then
        warn "未找到规则：网卡=$DEV 端口=$PORT 协议=$PROTO"
        return 0
    fi

    local HANDLE
    HANDLE=$(echo "$LINE" | cut -d'|' -f6)

    delete_iptables_rule "$PROTO" "$PORT" "$HANDLE"

    grep -v "^${DEV}|${PORT}|${PROTO}|" "$RULES_FILE" > "${RULES_FILE}.tmp" || true
    mv "${RULES_FILE}.tmp" "$RULES_FILE" 2>/dev/null || true

    remove_tc_mapping_for_port_if_unused "$DEV" "$PORT"

    msg "已删除限速：网卡=$DEV 端口=$PORT 协议=$PROTO"
}

update_rate_for_port() {
    local DEV="$1"
    local PORT="$2"
    local NEW_RATE="$3"

    local ID CLASS_ID
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

    for db in "${candidates[@]}"; do
        if [ -f "$db" ]; then
            XUI_DB_PATH="$db"
            return 0
        fi
    done

    local found
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
        SELECTED_PORT=""
        SELECTED_REMARK="-"
        SELECTED_NODE_PROTO="-"
        return 1
    fi

    if ! detect_xui_db; then
        warn "未找到 x-ui.db，将回退为手动输入端口"
        SELECTED_PORT=""
        SELECTED_REMARK="-"
        SELECTED_NODE_PROTO="-"
        return 1
    fi

    local DB="$XUI_DB_PATH"
    local rows
    rows=$(query_xui_nodes_enabled "$DB")

    if [ -z "$rows" ]; then
        warn "未读取到启用中的节点，尝试读取全部节点..."
        rows=$(query_xui_nodes_all "$DB")
    fi

    if [ -z "$rows" ]; then
        warn "已找到数据库：$DB，但未能读取到节点，将回退为手动输入端口"
        SELECTED_PORT=""
        SELECTED_REMARK="-"
        SELECTED_NODE_PROTO="-"
        return 1
    fi

    mapfile -t NODE_ROWS <<< "$rows"

    echo
    info "================ 选择 x-ui 节点 ================"
    echo "数据库：$DB"

    {
        echo "编号|状态|端口|协议|备注|限速状态"
        echo "----|----|----|----|----|--------"
        local i=1
        for row in "${NODE_ROWS[@]}"; do
            IFS='|' read -r nid remark port proto enable <<< "$row"
            [ -z "$remark" ] && remark="-"
            [ -z "$proto" ] && proto="-"

            local state="停用"
            if [[ "$enable" == "1" || "$enable" == "true" || "$enable" == "TRUE" ]]; then
                state="启用"
            fi

            local limited="未限速"
            if [[ "$port" =~ ^[0-9]+$ ]] && port_is_limited_anywhere "$port"; then
                limited="已限速"
            fi

            echo "${i}|${state}|${port}|${proto}|${remark}|${limited}"
            i=$((i+1))
        done
    } | show_table

    echo
    read -rp "请选择节点编号（输入 m 可手动输入端口）: " choice
    choice=$(trim "$choice")

    if [[ "$choice" == "m" || "$choice" == "M" ]]; then
        SELECTED_PORT=""
        SELECTED_REMARK="-"
        SELECTED_NODE_PROTO="-"
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

    local selected="${NODE_ROWS[$((choice-1))]}"
    IFS='|' read -r nid remark port proto enable <<< "$selected"

    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        warn "所选节点端口无效，将回退为手动输入端口"
        SELECTED_PORT=""
        SELECTED_REMARK="-"
        SELECTED_NODE_PROTO="-"
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
    local NODE_PROTO="$1"

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

    local keys=()
    while IFS='|' read -r dev port proto rate classid handle; do
        [ -z "$dev" ] && continue
        local key="${dev}|${port}"
        if [[ ! " ${keys[*]} " =~ " ${key} " ]]; then
            keys+=("$key")
        fi
    done < "$RULES_FILE"

    for key in "${keys[@]}"; do
        local dev port
        dev=$(echo "$key" | cut -d'|' -f1)
        port=$(echo "$key" | cut -d'|' -f2)

        local tcp_exists udp_exists rate
        tcp_exists=0
        udp_exists=0
        rate=$(grep "^${dev}|${port}|" "$RULES_FILE" | head -n1 | cut -d'|' -f4)

        grep -q "^${dev}|${port}|tcp|" "$RULES_FILE" 2>/dev/null && tcp_exists=1
        grep -q "^${dev}|${port}|udp|" "$RULES_FILE" 2>/dev/null && udp_exists=1

        local proto_show="-"
        if [ "$tcp_exists" -eq 1 ] && [ "$udp_exists" -eq 1 ]; then
            proto_show="tcp+udp"
        elif [ "$tcp_exists" -eq 1 ]; then
            proto_show="tcp"
        elif [ "$udp_exists" -eq 1 ]; then
            proto_show="udp"
        fi

        MERGED_RULES+=("${dev}|${port}|${proto_show}|${rate}")
    done
}

choose_existing_limited_rule() {
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
        local i=1
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

    local selected="${MERGED_RULES[$((idx-1))]}"
    IFS='|' read -r SELECTED_DEV SELECTED_PORT SELECTED_PROTO_SHOW SELECTED_RATE <<< "$selected"
    return 0
}

confirm_action() {
    local ACTION="$1"
    local DEV="$2"
    local PORT="$3"
    local REMARK="$4"
    local PROTO="$5"
    local RATE="$6"

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
    } | show_table
    echo

    read -rp "确认继续？[y/n]: " CONFIRM
    case "$CONFIRM" in
        y|Y) return 0 ;;
        *) warn "已取消操作"; return 1 ;;
    esac
}

iptables_hits_for_rule() {
    local PORT="$1"
    local PROTO_SHOW="$2"

    local total=0

    if [ "$PROTO_SHOW" = "tcp" ] || [ "$PROTO_SHOW" = "tcp+udp" ]; then
        local v
        v=$(iptables -t mangle -L OUTPUT -n -v -x 2>/dev/null | awk -v p="spt:${PORT}" '$0 ~ /tcp/ && $0 ~ p {sum+=$1} END{print sum+0}')
        total=$((total + v))
    fi

    if [ "$PROTO_SHOW" = "udp" ] || [ "$PROTO_SHOW" = "tcp+udp" ]; then
        local v
        v=$(iptables -t mangle -L OUTPUT -n -v -x 2>/dev/null | awk -v p="spt:${PORT}" '$0 ~ /udp/ && $0 ~ p {sum+=$1} END{print sum+0}')
        total=$((total + v))
    fi

    echo "$total"
}

rule_loaded_status() {
    local DEV="$1"
    local PORT="$2"
    local PROTO_SHOW="$3"

    local ID CLASS_ID HANDLE_HEX
    ID=$(calc_id "$PORT")
    CLASS_ID="1:${ID}"
    HANDLE_HEX=$(printf '%x' "$ID")

    local ok=1

    tc class show dev "$DEV" 2>/dev/null | grep -q "class htb ${CLASS_ID} " || ok=0
    tc filter show dev "$DEV" parent 1: 2>/dev/null | grep -q "handle 0x${HANDLE_HEX} classid ${CLASS_ID}" || ok=0

    if [ "$PROTO_SHOW" = "tcp" ]; then
        iptables_rule_exists tcp "$PORT" "$ID" || ok=0
    elif [ "$PROTO_SHOW" = "udp" ]; then
        iptables_rule_exists udp "$PORT" "$ID" || ok=0
    else
        iptables_rule_exists tcp "$PORT" "$ID" || ok=0
        iptables_rule_exists udp "$PORT" "$ID" || ok=0
    fi

    [ "$ok" -eq 1 ] && echo "已加载" || echo "异常"
}

show_status_simple() {
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
        local i=1
        for row in "${MERGED_RULES[@]}"; do
            IFS='|' read -r dev port proto rate <<< "$row"
            local loaded hits hit_text
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
    echo "tc class show dev <网卡名>"
    echo "tc filter show dev <网卡名> parent 1:"
    echo "tc -s class show dev <网卡名>"
}

delete_all_rules_for_dev() {
    local DEV="$1"

    if [ -f "$RULES_FILE" ]; then
        while IFS='|' read -r RDEV PORT PROTO RATE CLASS_ID HANDLE; do
            [ -z "$RDEV" ] && continue
            if [ "$RDEV" = "$DEV" ]; then
                delete_iptables_rule "$PROTO" "$PORT" "$HANDLE"
            fi
        done < "$RULES_FILE"

        grep -v "^${DEV}|" "$RULES_FILE" > "${RULES_FILE}.tmp" || true
        mv "${RULES_FILE}.tmp" "$RULES_FILE" 2>/dev/null || true
    fi

    tc qdisc del dev "$DEV" root >/dev/null 2>&1 || true
    msg "已删除网卡 $DEV 的全部限速规则"
}

create_restore_script() {
    cat > "$RESTORE_SCRIPT" <<'EOF'
#!/bin/bash

RULES_FILE="/etc/xui-node-limit/rules.conf"
[ -f "$RULES_FILE" ] || exit 0

ensure_qdisc() {
    local DEV="$1"
    tc qdisc add dev "$DEV" root handle 1: htb default 999 2>/dev/null || true
    tc class replace dev "$DEV" parent 1: classid 1:999 htb rate 1000mbit ceil 1000mbit >/dev/null 2>&1
}

sort -u "$RULES_FILE" | while IFS='|' read -r DEV PORT PROTO RATE CLASS_ID HANDLE; do
    [ -z "$DEV" ] && continue

    ensure_qdisc "$DEV"

    if ! iptables -t mangle -C OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE" 2>/dev/null; then
        iptables -t mangle -A OUTPUT -p "$PROTO" --sport "$PORT" -j MARK --set-mark "$HANDLE"
    fi

    if ! tc class replace dev "$DEV" parent 1: classid "$CLASS_ID" htb rate "$RATE" ceil "$RATE" >/dev/null 2>&1; then
        continue
    fi

    tc filter del dev "$DEV" parent 1: protocol ip handle "$HANDLE" fw >/dev/null 2>&1 || true
    tc filter add dev "$DEV" parent 1: protocol ip handle "$HANDLE" fw flowid "$CLASS_ID" >/dev/null 2>&1 || true
done
EOF

    chmod +x "$RESTORE_SCRIPT"
}

create_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Restore x-ui node limit rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$RESTORE_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

enable_autostart() {
    create_restore_script
    create_service
    systemctl daemon-reload
    systemctl enable xui-node-limit.service >/dev/null 2>&1 || true
    systemctl restart xui-node-limit.service
    msg "已启用开机自动恢复当前限速规则"
}

disable_autostart() {
    systemctl disable xui-node-limit.service >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    msg "已关闭开机自动恢复当前限速规则"
}

environment_check() {
    echo
    info "================ 环境检查 ================"

    if [ "$EUID" -eq 0 ]; then
        msg "[OK] root 权限"
    else
        err "[FAIL] 需要 root 权限"
    fi

    command -v iptables >/dev/null 2>&1 && msg "[OK] iptables 可用" || err "[FAIL] iptables 不可用"
    command -v tc >/dev/null 2>&1 && msg "[OK] tc 可用" || err "[FAIL] tc 不可用"
    command -v sqlite3 >/dev/null 2>&1 && msg "[OK] sqlite3 可用" || warn "[WARN] sqlite3 不可用"
    command -v column >/dev/null 2>&1 && msg "[OK] column 可用" || warn "[WARN] column 不可用"

    if detect_xui_db; then
        msg "[OK] 已检测到 x-ui.db：$XUI_DB_PATH"
    else
        warn "[WARN] 未检测到 x-ui.db"
    fi

    if systemctl is-enabled xui-node-limit.service >/dev/null 2>&1; then
        msg "[OK] 开机自动恢复当前限速规则：已启用"
    else
        warn "[WARN] 开机自动恢复当前限速规则：未启用"
    fi
}

repair_and_cleanup() {
    echo
    info "================ 修复 / 清理残留规则 ================"
    echo "此操作会："
    echo "1) 删除 rules.conf 中的重复记录"
    echo "2) 删除脚本规则对应的 iptables 标记"
    echo "3) 清空相关网卡上的 tc root qdisc"
    echo "4) 按当前 rules.conf 重新加载限速规则"
    echo
    read -rp "确认继续？[y/n]: " c
    case "$c" in
        y|Y) ;;
        *) warn "已取消"; return ;;
    esac

    if [ -s "$RULES_FILE" ]; then
        sort -u "$RULES_FILE" > "${RULES_FILE}.tmp" && mv "${RULES_FILE}.tmp" "$RULES_FILE"

        local devs=()
        while IFS='|' read -r dev port proto rate classid handle; do
            [ -z "$dev" ] && continue

            delete_iptables_rule "$proto" "$port" "$handle"

            if [[ ! " ${devs[*]} " =~ " ${dev} " ]]; then
                devs+=("$dev")
            fi
        done < "$RULES_FILE"

        for dev in "${devs[@]}"; do
            tc qdisc del dev "$dev" root >/dev/null 2>&1 || true
        done
    fi

    create_restore_script
    bash "$RESTORE_SCRIPT"
    msg "修复完成，已按当前规则重新加载"
}

add_limit_interactive() {
    echo
    info "================ 添加节点限速 ================"

    choose_interface || return
    local DEV="$SELECTED_DEV"

    choose_xui_node_or_manual_port
    local node_result=$?

    if [ "$node_result" -eq 1 ]; then
        info "已切换到手动输入端口模式"
        input_manual_port || return
    elif [ "$node_result" -eq 2 ]; then
        return
    fi

    local PORT="$SELECTED_PORT"
    local REMARK="$SELECTED_REMARK"
    local NODE_PROTO="$SELECTED_NODE_PROTO"

    echo
    read -rp "请输入限速值（单位 Mbps，例如 20）: " MBPS
    MBPS=$(trim "$MBPS")
    if ! [[ "$MBPS" =~ ^[0-9]+$ ]]; then
        err "速率必须是数字"
        return
    fi
    local RATE="${MBPS}mbit"

    choose_protocol_with_recommend "$NODE_PROTO"
    local PROTO="$SELECTED_PROTO"
    if [ "$PROTO" = "invalid" ]; then
        err "协议选择无效"
        return
    fi

    local PROTO_SHOW="$PROTO"
    [ "$PROTO_SHOW" = "both" ] && PROTO_SHOW="tcp+udp"

    confirm_action "添加限速" "$DEV" "$PORT" "$REMARK" "$PROTO_SHOW" "$RATE" || return

    local ok=1
    if [ "$PROTO" = "tcp" ]; then
        add_proto_rule "$DEV" "$PORT" "$RATE" "tcp" || ok=0
    elif [ "$PROTO" = "udp" ]; then
        add_proto_rule "$DEV" "$PORT" "$RATE" "udp" || ok=0
    else
        add_proto_rule "$DEV" "$PORT" "$RATE" "tcp" || ok=0
        add_proto_rule "$DEV" "$PORT" "$RATE" "udp" || ok=0
    fi

    if [ "$ok" -ne 1 ]; then
        err "添加限速未完全成功，请检查上方错误信息"
        return
    fi

    echo
    echo "说明：启用后，服务器重启时会自动重新加载当前已保存的限速规则。"
    read -rp "是否启用开机自动恢复当前限速规则？[y/n]: " AUTO
    case "$AUTO" in
        y|Y) enable_autostart ;;
        *) warn "未启用开机自动恢复当前限速规则" ;;
    esac
}

delete_limit_interactive() {
    echo
    info "================ 删除节点限速 ================"

    choose_existing_limited_rule || return

    local DEV="$SELECTED_DEV"
    local PORT="$SELECTED_PORT"
    local PROTO_SHOW="$SELECTED_PROTO_SHOW"
    local RATE="$SELECTED_RATE"

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

    local DELETE_MODE=""
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

    local show_proto="$PROTO_SHOW"
    [ "$DELETE_MODE" = "tcp" ] && show_proto="tcp"
    [ "$DELETE_MODE" = "udp" ] && show_proto="udp"
    [ "$DELETE_MODE" = "both" ] && show_proto="tcp+udp"

    confirm_action "删除限速" "$DEV" "$PORT" "-" "$show_proto" "$RATE" || return

    case "$DELETE_MODE" in
        all)
            grep -q "^${DEV}|${PORT}|tcp|" "$RULES_FILE" 2>/dev/null && delete_proto_rule "$DEV" "$PORT" "tcp"
            grep -q "^${DEV}|${PORT}|udp|" "$RULES_FILE" 2>/dev/null && delete_proto_rule "$DEV" "$PORT" "udp"
            ;;
        tcp)
            delete_proto_rule "$DEV" "$PORT" "tcp"
            ;;
        udp)
            delete_proto_rule "$DEV" "$PORT" "udp"
            ;;
        both)
            delete_proto_rule "$DEV" "$PORT" "tcp"
            delete_proto_rule "$DEV" "$PORT" "udp"
            ;;
    esac
}

modify_limit_interactive() {
    echo
    info "================ 修改节点限速 ================"

    choose_existing_limited_rule || return

    local DEV="$SELECTED_DEV"
    local PORT="$SELECTED_PORT"
    local PROTO_SHOW="$SELECTED_PROTO_SHOW"

    echo
    read -rp "请输入新的限速值（单位 Mbps，例如 20）: " MBPS
    MBPS=$(trim "$MBPS")
    if ! [[ "$MBPS" =~ ^[0-9]+$ ]]; then
        err "速率必须是数字"
        return
    fi
    local NEW_RATE="${MBPS}mbit"

    confirm_action "修改限速" "$DEV" "$PORT" "-" "$PROTO_SHOW" "$NEW_RATE" || return
    update_rate_for_port "$DEV" "$PORT" "$NEW_RATE"
}

delete_all_interactive() {
    echo
    info "================ 清空某网卡全部限速 ================"
    choose_interface || return
    local DEV="$SELECTED_DEV"

    confirm_action "清空某网卡全部限速" "$DEV" "-" "-" "-" "-" || return
    delete_all_rules_for_dev "$DEV"
}

autostart_menu() {
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
