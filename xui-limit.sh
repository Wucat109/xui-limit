#!/bin/bash

# 保持中文 UTF-8 正常显示，同时让外部命令消息、数字格式保持稳定。
unset LC_ALL

export LANG=C.UTF-8
export LC_CTYPE=C.UTF-8
export LC_MESSAGES=C
export LC_NUMERIC=C
export LC_COLLATE=C

umask 077

CONFIG_DIR="/etc/xui-limit"
RULES_FILE="$CONFIG_DIR/rules.conf"
IFB_MAP_FILE="$CONFIG_DIR/ifb.map"
APPLIED_FILE="$CONFIG_DIR/applied.conf"
ROOT_OWNED_FILE="$CONFIG_DIR/root-owned.conf"
INGRESS_OWNED_FILE="$CONFIG_DIR/ingress-owned.conf"
QDISC_BACKUP_DIR="$CONFIG_DIR/qdisc-backup"

RESTORE_SCRIPT="/usr/local/bin/xui-limit-restore.sh"
INSTALLED_SCRIPT="/usr/local/lib/xui-limit/xui-limit-manager.sh"
SERVICE_FILE="/etc/systemd/system/xui-limit.service"
LOG_FILE="/var/log/xui-limit.log"

# 旧版脚本使用的全流量 ingress → IFB 重定向优先级。
# 仅用于迁移和修复旧版残留规则。
LEGACY_INGRESS_PREF="49152"


# 本脚本用于确认 HTB root qdisc 所有权的专属标记 class。
# 受限端口 class ID 范围为 1:1000～1:9999，
# 因此选择 1:fffe，不会与端口 class 冲突。
ROOT_MARKER_CLASS="1:fffe"
ROOT_MARKER_RATE="1mbit"

# 开机恢复时，自动接管 root-owned.conf 中已经授权的网卡。
# 1：自动把系统默认 fq/fq_codel/cake/mq 等替换为 HTB。
# 0：开机恢复时也拒绝覆盖非 HTB root qdisc。
FORCE_RESTORE_OWNED_ROOT=1

mkdir -p "$CONFIG_DIR" "$QDISC_BACKUP_DIR"
chmod 700 "$CONFIG_DIR" "$QDISC_BACKUP_DIR"

touch \
    "$RULES_FILE" \
    "$IFB_MAP_FILE" \
    "$APPLIED_FILE" \
    "$ROOT_OWNED_FILE" \
    "$INGRESS_OWNED_FILE" \
    "$LOG_FILE"

chmod 600 \
    "$RULES_FILE" \
    "$IFB_MAP_FILE" \
    "$APPLIED_FILE" \
    "$ROOT_OWNED_FILE" \
    "$INGRESS_OWNED_FILE" \
    "$LOG_FILE"

color_green="\033[32m"
color_red="\033[31m"
color_yellow="\033[33m"
color_blue="\033[36m"
color_reset="\033[0m"

msg() {
    echo -e "${color_green}$1${color_reset}"
}

warn() {
    echo -e "${color_yellow}$1${color_reset}"
}

err() {
    echo -e "${color_red}$1${color_reset}"
}

info() {
    echo -e "${color_blue}$1${color_reset}"
}

declare -A ROOT_TAKEOVER_APPROVED=()

RESTORE_MODE=0

log_event() {
    local level="$1"
    shift

    local text="$*"
    local now

    now=$(date '+%Y-%m-%d %H:%M:%S')

    printf '%s [%s] %s\n' \
        "$now" "$level" "$text" >> "$LOG_FILE"

    if command -v logger >/dev/null 2>&1; then
        logger -t xui-limit "[$level] $text" 2>/dev/null || true
    fi
}

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

make_temp_file() {
    local base="$1"

    mktemp "${base}.tmp.XXXXXX"
}

valid_port() {
    local port="$1"

    [[ "$port" =~ ^[0-9]+$ ]] &&
        [ "$port" -ge 1 ] &&
        [ "$port" -le 65535 ]
}

valid_mbps() {
    local mbps="$1"

    [[ "$mbps" =~ ^[0-9]+$ ]] &&
        [ "$mbps" -gt 0 ]
}

valid_rate() {
    local rate="${1,,}"

    [[ "$rate" =~ ^[1-9][0-9]*(kbit|mbit|gbit)$ ]]
}

valid_interface_name() {
    local dev="$1"

    [ -n "$dev" ] &&
        [ "${#dev}" -le 15 ] &&
        [[ "$dev" =~ ^[a-zA-Z0-9_.:-]+$ ]]
}

file_contains_exact_line() {
    local file="$1"
    local line="$2"

    grep -Fxq "$line" "$file" 2>/dev/null
}

file_add_unique_line() {
    local file="$1"
    local line="$2"
    local tmp

    file_contains_exact_line "$file" "$line" && return 0

    tmp=$(make_temp_file "$file") || return 1

    cat "$file" > "$tmp"
    echo "$line" >> "$tmp"

    chmod 600 "$tmp"
    mv -f "$tmp" "$file"
}

file_remove_exact_line() {
    local file="$1"
    local line="$2"
    local tmp

    tmp=$(make_temp_file "$file") || return 1

    grep -Fvx "$line" "$file" > "$tmp" || true

    chmod 600 "$tmp"
    mv -f "$tmp" "$file"
}

clear_takeover_approvals() {
    ROOT_TAKEOVER_APPROVED=()
}

takeover_approved_this_run() {
    local dev="$1"

    [ "${ROOT_TAKEOVER_APPROVED[$dev]:-0}" = "1" ]
}

install_deps() {
    msg "正在安装依赖..."

    if ! command -v apt >/dev/null 2>&1; then
        err "当前脚本只正式支持 Debian/Ubuntu 的 apt"
        return 1
    fi

    apt update

    apt install -y \
        iproute2 \
        iptables \
        sqlite3 \
        util-linux \
        bsdextrautils \
        kmod

    modprobe sch_htb >/dev/null 2>&1 || true
    modprobe sch_fq_codel >/dev/null 2>&1 || true
    modprobe cls_flower >/dev/null 2>&1 || true
    modprobe act_mirred >/dev/null 2>&1 || true
    modprobe ifb >/dev/null 2>&1 || true

    if ! modprobe ifb >/dev/null 2>&1; then
        local extra_package
        local answer

        extra_package="linux-modules-extra-$(uname -r)"

        warn "当前内核的 IFB 模块加载失败"

        if apt-cache show "$extra_package" >/dev/null 2>&1; then
            read -rp "是否安装 $extra_package？[y/n]: " answer

            case "$answer" in
                y|Y)
                    apt install -y "$extra_package"
                    modprobe ifb >/dev/null 2>&1 || true
                    ;;
            esac
        fi
    fi

    if modprobe ifb >/dev/null 2>&1; then
        msg "依赖和 IFB 模块检查完成"
    else
        err "IFB 模块仍然不可用，上传限速无法生效"
        return 1
    fi

    log_event INFO "完成依赖安装"
}

get_default_interface() {
    ip route get 8.8.8.8 2>/dev/null |
        awk '
            /dev/ {
                for (i=1; i<=NF; i++) {
                    if ($i=="dev") {
                        print $(i+1)
                        exit
                    }
                }
            }
        '
}

interface_is_ifb() {
    local dev="$1"

    ip -d link show dev "$dev" 2>/dev/null |
        grep -qw ifb
}

list_interfaces() {
    local dev

    while IFS= read -r dev; do
        [ -z "$dev" ] && continue
        [ "$dev" = "lo" ] && continue
        interface_is_ifb "$dev" && continue

        echo "$dev"
    done < <(
        ip -o link show |
            awk -F': ' '{print $2}' |
            cut -d@ -f1
    )
}

choose_interface() {
    local default_dev
    local default_index=1
    local index
    local i=1
    local dev

    default_dev=$(get_default_interface)
    mapfile -t IFACES < <(list_interfaces)

    if [ "${#IFACES[@]}" -eq 0 ]; then
        err "未检测到可用网卡"
        return 1
    fi

    echo
    info "================ 选择网卡 ================"

    {
        echo "编号|网卡|说明"
        echo "----|----|----"

        for dev in "${IFACES[@]}"; do
            if [ "$dev" = "$default_dev" ]; then
                echo "$i|$dev|默认/推荐"
                default_index=$i
            else
                echo "$i|$dev|-"
            fi

            i=$((i+1))
        done
    } | show_table

    echo
    read -rp "请选择网卡编号 [默认: $default_index]: " index

    index=$(trim "$index")
    index=${index:-$default_index}

    if ! [[ "$index" =~ ^[0-9]+$ ]]; then
        err "网卡编号无效"
        return 1
    fi

    if [ "$index" -lt 1 ] ||
        [ "$index" -gt "${#IFACES[@]}" ]; then

        err "网卡编号超出范围"
        return 1
    fi

    SELECTED_DEV="${IFACES[$((index-1))]}"
}

calc_id() {
    local port="$1"

    echo $((port % 9000 + 1000))
}

class_id_for_port() {
    local port="$1"

    echo "1:$(calc_id "$port")"
}

leaf_handle_for_port() {
    local port="$1"
    local id

    id=$(calc_id "$port")

    printf '%x\n' "$id"
}

filter_pref() {
    local family="$1"
    local proto="$2"
    local port="$3"

    local id
    local base

    id=$(calc_id "$port")

    case "${family}:${proto}" in
        ip:tcp)
            base=10000
            ;;
        ip:udp)
            base=20000
            ;;
        ipv6:tcp)
            base=30000
            ;;
        ipv6:udp)
            base=40000
            ;;
        *)
            return 1
            ;;
    esac

    echo $((base + id))
}

filter_handle() {
    local family="$1"
    local proto="$2"
    local port="$3"
    local pref

    pref=$(filter_pref "$family" "$proto" "$port") || return 1

    printf '0x%x' "$pref"
}

rule_exists_in_file() {
    local file="$1"
    local dev="$2"
    local port="$3"
    local proto="$4"

    awk -F'|' \
        -v dev="$dev" \
        -v port="$port" \
        -v proto="$proto" '
            $1==dev && $2==port && $3==proto {
                found=1
                exit
            }
            END {
                exit !found
            }
        ' "$file" 2>/dev/null
}

rule_exists() {
    rule_exists_in_file "$RULES_FILE" "$1" "$2" "$3"
}

has_rules_for_dev_in_file() {
    local file="$1"
    local dev="$2"

    awk -F'|' \
        -v dev="$dev" '
            $1==dev {
                found=1
                exit
            }
            END {
                exit !found
            }
        ' "$file" 2>/dev/null
}

has_rules_for_port_in_file() {
    local file="$1"
    local dev="$2"
    local port="$3"

    awk -F'|' \
        -v dev="$dev" \
        -v port="$port" '
            $1==dev && $2==port {
                found=1
                exit
            }
            END {
                exit !found
            }
        ' "$file" 2>/dev/null
}

get_port_rate_from_file() {
    local file="$1"
    local dev="$2"
    local port="$3"

    awk -F'|' \
        -v dev="$dev" \
        -v port="$port" '
            $1==dev && $2==port {
                print $4
                exit
            }
        ' "$file" 2>/dev/null
}

normalize_rules_file() {
    local input="$1"
    local output="$2"

    local raw
    local dev
    local port
    local proto
    local rate
    local class_id
    local handle
    local extra

    local key
    local port_key
    local id_key
    local id
    local invalid=0

    declare -A seen=()
    declare -A key_dev=()
    declare -A key_port=()
    declare -A key_proto=()
    declare -A port_rate=()
    declare -A id_owner=()

    local -a keys=()

    : > "$output"

    while IFS= read -r raw || [ -n "$raw" ]; do
        raw="${raw%$'\r'}"

        [ -z "$raw" ] && continue
        [[ "$raw" =~ ^[[:space:]]*# ]] && continue

        dev=""
        port=""
        proto=""
        rate=""
        class_id=""
        handle=""
        extra=""

        IFS='|' read -r \
            dev port proto rate class_id handle extra <<< "$raw"

        dev=$(trim "$dev")
        port=$(trim "$port")
        proto=$(trim "${proto,,}")
        rate=$(trim "${rate,,}")

        if [ -n "$extra" ]; then
            err "配置字段数量错误：$raw"
            invalid=1
            continue
        fi

        if ! valid_interface_name "$dev"; then
            err "配置网卡名无效：$raw"
            invalid=1
            continue
        fi

        if ! valid_port "$port"; then
            err "配置端口无效：$raw"
            invalid=1
            continue
        fi

        if [ "$proto" != "tcp" ] &&
            [ "$proto" != "udp" ]; then

            err "配置协议无效：$raw"
            invalid=1
            continue
        fi

        if ! valid_rate "$rate"; then
            err "配置速率无效：$raw"
            invalid=1
            continue
        fi

        id=$(calc_id "$port")
        key="${dev}|${port}|${proto}"
        port_key="${dev}|${port}"
        id_key="${dev}|${id}"

        if [ -n "${id_owner[$id_key]+x}" ] &&
            [ "${id_owner[$id_key]}" != "$port" ]; then

            err "端口 ID 冲突：网卡=$dev，端口=$port 与 ${id_owner[$id_key]}"
            invalid=1
            continue
        fi

        id_owner["$id_key"]="$port"

        if [ -z "${seen[$key]+x}" ]; then
            seen["$key"]=1
            keys+=("$key")
        else
            warn "发现重复配置，保留最后一条：$key"
        fi

        if [ -n "${port_rate[$port_key]+x}" ] &&
            [ "${port_rate[$port_key]}" != "$rate" ]; then

            warn "同一端口 TCP/UDP 速率不一致，将统一为最后一条：$port_key=$rate"
        fi

        key_dev["$key"]="$dev"
        key_port["$key"]="$port"
        key_proto["$key"]="$proto"
        port_rate["$port_key"]="$rate"
    done < "$input"

    if [ "$invalid" -ne 0 ]; then
        rm -f "$output"
        return 1
    fi

    for key in "${keys[@]}"; do
        dev="${key_dev[$key]}"
        port="${key_port[$key]}"
        proto="${key_proto[$key]}"
        port_key="${dev}|${port}"
        rate="${port_rate[$port_key]}"
        id=$(calc_id "$port")

        echo "${dev}|${port}|${proto}|${rate}|1:${id}|${id}" \
            >> "$output"
    done

    chmod 600 "$output"
}

root_is_owned() {
    local dev="$1"

    file_contains_exact_line "$ROOT_OWNED_FILE" "$dev"
}

ingress_is_owned() {
    local dev="$1"

    file_contains_exact_line "$INGRESS_OWNED_FILE" "$dev"
}

root_qdisc_is_htb_base() {
    local dev="$1"

    tc qdisc show dev "$dev" 2>/dev/null |
        grep -qE 'qdisc htb 1: root'
}

root_marker_exists() {
    local dev="$1"

    tc class show dev "$dev" \
        classid "$ROOT_MARKER_CLASS" 2>/dev/null |
        grep -qE "class htb ${ROOT_MARKER_CLASS} "
}

root_qdisc_is_ours() {
    local dev="$1"

    root_qdisc_is_htb_base "$dev" &&
        root_marker_exists "$dev"
}

ensure_root_marker() {
    local dev="$1"

    if ! root_qdisc_is_htb_base "$dev"; then
        err "无法创建 HTB 所有权标记，root qdisc 不是预期 HTB：$dev"
        return 1
    fi

    if ! tc class replace dev "$dev" parent 1: \
        classid "$ROOT_MARKER_CLASS" \
        htb rate "$ROOT_MARKER_RATE" \
        ceil "$ROOT_MARKER_RATE" \
        >/dev/null 2>&1; then

        err "创建 HTB 所有权标记 class 失败：$dev/$ROOT_MARKER_CLASS"
        return 1
    fi

    if ! root_marker_exists "$dev"; then
        err "HTB 所有权标记校验失败：$dev/$ROOT_MARKER_CLASS"
        return 1
    fi

    return 0
}


root_qdisc_summary() {
    local dev="$1"

    tc qdisc show dev "$dev" 2>/dev/null |
        grep ' root ' || true
}

save_qdisc_reference() {
    local dev="$1"
    local safe_dev
    local timestamp
    local backup
    local latest

    safe_dev="${dev//[^a-zA-Z0-9_.:-]/_}"
    timestamp=$(date '+%Y%m%d-%H%M%S')

    backup="$QDISC_BACKUP_DIR/${safe_dev}-${timestamp}.txt"
    latest="$QDISC_BACKUP_DIR/${safe_dev}-latest.txt"

    {
        echo "保存时间：$(date '+%Y-%m-%d %H:%M:%S')"
        echo "网卡：$dev"
        echo
        echo "===== qdisc ====="
        tc qdisc show dev "$dev" 2>/dev/null
        echo
        echo "===== class ====="
        tc class show dev "$dev" 2>/dev/null
        echo
        echo "===== filter ====="
        tc filter show dev "$dev" 2>/dev/null
    } > "$backup"

    chmod 600 "$backup"
    cp -f "$backup" "$latest"
    chmod 600 "$latest"
}

approve_root_takeover() {
    local dev="$1"
    local current
    local answer

    current=$(root_qdisc_summary "$dev")

    if root_is_owned "$dev"; then
        if [ -z "$current" ] || root_qdisc_is_ours "$dev"; then
            return 0
        fi

        warn "网卡 $dev 曾由本脚本管理，但当前 root qdisc 已发生变化："
        echo "$current"
        echo
        if [ ! -r /dev/tty ]; then
            err "当前没有可用交互终端，无法确认重新接管网卡：$dev"
            return 1
        fi

        read -rp "是否重新接管网卡 $dev？[y/n]: " \
            answer < /dev/tty




        case "$answer" in
            y|Y)
                save_qdisc_reference "$dev"
                ROOT_TAKEOVER_APPROVED["$dev"]=1
                log_event WARN "用户确认重新接管 root qdisc：$dev"
                return 0
                ;;
            *)
                return 1
                ;;
        esac
    fi

    echo
    warn "脚本需要接管网卡 $dev 的 root qdisc"
    warn "这会覆盖当前 fq、fq_codel、CAKE、mq、HTB 或其他 root QoS"

    if [ -n "$current" ]; then
        echo
        echo "当前 root qdisc："
        echo "$current"
    fi

    echo
    echo "原状态会保存到：$QDISC_BACKUP_DIR"
    echo

    if [ ! -r /dev/tty ]; then
        err "当前没有可用交互终端，无法确认接管网卡：$dev"
        return 1
    fi

    read -rp "确认接管网卡 $dev？[y/n]: " \
        answer < /dev/tty



    case "$answer" in
        y|Y)
            save_qdisc_reference "$dev"

            if ! file_add_unique_line "$ROOT_OWNED_FILE" "$dev"; then
                err "写入 root 接管授权失败：$dev"
                return 1
            fi

            ROOT_TAKEOVER_APPROVED["$dev"]=1
            log_event WARN "用户确认接管 root qdisc：$dev"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

root_takeover_allowed() {
    local dev="$1"
    local current

    if ! root_is_owned "$dev"; then
        err "网卡 $dev 未获得 root qdisc 接管授权"
        return 1
    fi

    current=$(root_qdisc_summary "$dev")

    if [ -z "$current" ] || root_qdisc_is_ours "$dev"; then
        return 0
    fi

    if takeover_approved_this_run "$dev"; then
        return 0
    fi

    if [ "$RESTORE_MODE" -eq 1 ] &&
        [ "$FORCE_RESTORE_OWNED_ROOT" -eq 1 ]; then

        info "开机恢复：自动接管已授权网卡 $dev 的 root qdisc"
        log_event INFO "开机恢复接管 $dev；原状态：$current"

        ROOT_TAKEOVER_APPROVED["$dev"]=1
        return 0
    fi

    err "网卡 $dev 的 root qdisc 已被其他策略修改，拒绝自动覆盖"
    echo "$current"

    return 1
}

lookup_ifb_name() {
    local dev="$1"

    awk -F'|' \
        -v dev="$dev" '
            $1==dev {
                print $2
                exit
            }
        ' "$IFB_MAP_FILE" 2>/dev/null
}

ifb_name_used_by_other_dev() {
    local dev="$1"
    local ifb="$2"

    awk -F'|' \
        -v dev="$dev" \
        -v ifb="$ifb" '
            $1!=dev && $2==ifb {
                found=1
                exit
            }
            END {
                exit !found
            }
        ' "$IFB_MAP_FILE" 2>/dev/null
}

set_ifb_mapping() {
    local dev="$1"
    local ifb="$2"
    local tmp

    tmp=$(make_temp_file "$IFB_MAP_FILE") || return 1

    awk -F'|' \
        -v dev="$dev" '
            $1!=dev
        ' "$IFB_MAP_FILE" > "$tmp" || true

    echo "${dev}|${ifb}" >> "$tmp"

    chmod 600 "$tmp"
    mv -f "$tmp" "$IFB_MAP_FILE"
}

remove_ifb_mapping() {
    local dev="$1"
    local tmp

    tmp=$(make_temp_file "$IFB_MAP_FILE") || return 1

    awk -F'|' \
        -v dev="$dev" '
            $1!=dev
        ' "$IFB_MAP_FILE" > "$tmp" || true

    chmod 600 "$tmp"
    mv -f "$tmp" "$IFB_MAP_FILE"
}

resolve_ifb_name() {
    local dev="$1"
    local save_mapping="${2:-0}"

    local existing
    local salt=0
    local checksum
    local candidate

    existing=$(lookup_ifb_name "$dev")

    if [ -n "$existing" ]; then
        IFB_DEV="$existing"
        return 0
    fi

    while true; do
        checksum=$(
            printf '%s' "${dev}:${salt}" |
                cksum |
                awk '{print $1}'
        )

        candidate="xuil${checksum}"

        if ifb_name_used_by_other_dev "$dev" "$candidate"; then
            salt=$((salt+1))
            continue
        fi

        if ip link show dev "$candidate" >/dev/null 2>&1; then
            if interface_is_ifb "$candidate"; then
                break
            fi

            salt=$((salt+1))
            continue
        fi

        break
    done

    IFB_DEV="$candidate"

    if [ "$save_mapping" -eq 1 ]; then
        set_ifb_mapping "$dev" "$IFB_DEV"
    fi
}

ifb_name_is_safe() {
    local ifb="$1"

    [[ "$ifb" =~ ^xuil[0-9]+$ ]] &&
        [ "${#ifb}" -le 15 ]
}

ifb_alias_matches() {
    local dev="$1"
    local ifb="$2"

    [ -f "/sys/class/net/${ifb}/ifalias" ] || return 1

    [ "$(cat "/sys/class/net/${ifb}/ifalias" 2>/dev/null)" = "xui-limit:${dev}" ]
}

validate_owned_ifb() {
    local dev="$1"
    local ifb="$2"

    ifb_name_is_safe "$ifb" || return 1
    ip link show dev "$ifb" >/dev/null 2>&1 || return 1
    interface_is_ifb "$ifb" || return 1
    ifb_alias_matches "$dev" "$ifb" || return 1
}

ensure_ifb_device() {
    local dev="$1"
    local ifb
    local current_alias=""

    IFB_WAS_CREATED=0

    modprobe ifb >/dev/null 2>&1 || true

    resolve_ifb_name "$dev" 1 || return 1
    ifb="$IFB_DEV"

    if ! ifb_name_is_safe "$ifb"; then
        err "IFB 名称不安全：$ifb"
        return 1
    fi

    if ip link show dev "$ifb" >/dev/null 2>&1; then
        if ! interface_is_ifb "$ifb"; then
            err "$ifb 已存在，但不是 IFB"
            return 1
        fi

        if ! ifb_alias_matches "$dev" "$ifb"; then
            current_alias=$(cat "/sys/class/net/${ifb}/ifalias" 2>/dev/null)

            if [ -n "$current_alias" ]; then
                err "IFB $ifb 已属于其他配置：$current_alias"
                return 1
            fi

            ip link set dev "$ifb" \
                alias "xui-limit:${dev}" >/dev/null 2>&1 || {
                err "设置 IFB alias 失败：$ifb"
                return 1
            }
        fi
    else
        ip link add "$ifb" type ifb >/dev/null 2>&1 || {
            err "创建 IFB 失败：$ifb"
            return 1
        }

        IFB_WAS_CREATED=1

        ip link set dev "$ifb" \
            alias "xui-limit:${dev}" >/dev/null 2>&1 || {
            ip link del dev "$ifb" >/dev/null 2>&1 || true
            err "设置 IFB alias 失败：$ifb"
            return 1
        }
    fi

    ip link set dev "$ifb" up >/dev/null 2>&1 || {
        err "启动 IFB 失败：$ifb"
        return 1
    }

    validate_owned_ifb "$dev" "$ifb" || {
        err "IFB 所属校验失败：$dev → $ifb"
        return 1
    }
}

safe_delete_ifb() {
    local dev="$1"
    local ifb="$2"

    [ -z "$ifb" ] && return 0

    if ! ip link show dev "$ifb" >/dev/null 2>&1; then
        remove_ifb_mapping "$dev"
        return 0
    fi

    if ! validate_owned_ifb "$dev" "$ifb"; then
        err "拒绝删除未通过所属校验的接口：$ifb"
        return 1
    fi

    if ip link show dev "$dev" >/dev/null 2>&1; then
        if tc filter show dev "$dev" parent ffff: 2>/dev/null |
            grep -q "$ifb"; then

            warn "ingress 中仍有规则指向 $ifb，暂不删除"
            return 1
        fi
    fi

    tc qdisc del dev "$ifb" root >/dev/null 2>&1 || true
    ip link set dev "$ifb" down >/dev/null 2>&1 || true
    ip link del dev "$ifb" >/dev/null 2>&1 || return 1

    remove_ifb_mapping "$dev"
}

ensure_physical_root() {
    local dev="$1"

    PHYSICAL_ROOT_WAS_CREATED=0

    if root_qdisc_is_ours "$dev"; then
        return 0
    fi

    root_takeover_allowed "$dev" || return 1

    modprobe sch_htb >/dev/null 2>&1 || true

    if ! tc qdisc replace dev "$dev" root \
        handle 1: htb default 0 >/dev/null 2>&1; then

        err "创建物理网卡 HTB root qdisc 失败：$dev"
        return 1
    fi

    # 为 HTB 创建本脚本专属标记 class。
    if ! ensure_root_marker "$dev"; then
        tc qdisc del dev "$dev" root >/dev/null 2>&1 || true
        return 1
    fi

    PHYSICAL_ROOT_WAS_CREATED=1

    if ! root_qdisc_is_ours "$dev"; then
        err "物理网卡 HTB root qdisc 所有权校验失败：$dev"
        return 1
    fi

    return 0
}

ensure_ifb_root() {
    local physical_dev="$1"
    local ifb="$2"

    IFB_ROOT_WAS_CREATED=0

    if ! validate_owned_ifb "$physical_dev" "$ifb"; then
        err "IFB 所属校验失败：$physical_dev → $ifb"
        return 1
    fi

    if root_qdisc_is_ours "$ifb"; then
        return 0
    fi

    modprobe sch_htb >/dev/null 2>&1 || true

    if ! tc qdisc replace dev "$ifb" root \
        handle 1: htb default 0 >/dev/null 2>&1; then

        err "创建 IFB HTB root qdisc 失败：$ifb"
        return 1
    fi

    # IFB 上的 HTB 同样创建专属标记。
    if ! ensure_root_marker "$ifb"; then
        tc qdisc del dev "$ifb" root >/dev/null 2>&1 || true
        return 1
    fi

    IFB_ROOT_WAS_CREATED=1

    if ! root_qdisc_is_ours "$ifb"; then
        err "IFB HTB root qdisc 所有权校验失败：$ifb"
        return 1
    fi

    return 0
}


ensure_ingress_qdisc() {
    local dev="$1"

    INGRESS_WAS_CREATED=0

    if tc qdisc show dev "$dev" 2>/dev/null |
        grep -qE 'qdisc (ingress|clsact) ffff:'; then

        return 0
    fi

    tc qdisc add dev "$dev" \
        handle ffff: ingress >/dev/null 2>&1 || {
        err "创建 ingress qdisc 失败：$dev"
        return 1
    }

    INGRESS_WAS_CREATED=1

    if ! file_add_unique_line "$INGRESS_OWNED_FILE" "$dev"; then
        tc qdisc del dev "$dev" ingress >/dev/null 2>&1 || true
        return 1
    fi
}

cleanup_owned_ingress_if_empty() {
    local dev="$1"
    local filters

    ingress_is_owned "$dev" || return 0

    filters=$(tc filter show dev "$dev" parent ffff: 2>/dev/null)

    [ -n "$filters" ] && return 0

    if tc qdisc show dev "$dev" 2>/dev/null |
        grep -qE 'qdisc ingress ffff:'; then

        tc qdisc del dev "$dev" ingress >/dev/null 2>&1 || return 1
    fi

    file_remove_exact_line "$INGRESS_OWNED_FILE" "$dev"
}

ensure_rate_class() {
    local dev="$1"
    local port="$2"
    local rate="$3"

    local class_id
    local leaf_handle

    class_id=$(class_id_for_port "$port")
    leaf_handle=$(leaf_handle_for_port "$port")

    tc class replace dev "$dev" parent 1: \
        classid "$class_id" \
        htb rate "$rate" ceil "$rate" >/dev/null 2>&1 || {
        err "创建或更新 HTB class 失败：$dev/$class_id"
        return 1
    }

    if ! fq_codel_exists "$dev" "$class_id"; then
        modprobe sch_fq_codel >/dev/null 2>&1 || true

        tc qdisc replace dev "$dev" \
            parent "$class_id" \
            handle "${leaf_handle}:" \
            fq_codel >/dev/null 2>&1 || {
            err "创建 fq_codel 失败：$dev/$class_id"
            return 1
        }
    fi
}

delete_rate_class() {
    local dev="$1"
    local port="$2"
    local class_id

    class_id=$(class_id_for_port "$port")

    tc qdisc del dev "$dev" \
        parent "$class_id" >/dev/null 2>&1 || true

    tc class del dev "$dev" \
        classid "$class_id" >/dev/null 2>&1 || true
}

tc_class_exists() {
    local dev="$1"
    local class_id="$2"

    tc class show dev "$dev" 2>/dev/null |
        grep -q "class htb ${class_id} "
}

fq_codel_exists() {
    local dev="$1"
    local class_id="$2"

    tc qdisc show dev "$dev" 2>/dev/null |
        grep -qE "qdisc fq_codel .* parent ${class_id} "
}

filter_output() {
    local dev="$1"
    local parent="$2"
    local family="$3"
    local pref="$4"

    tc filter show dev "$dev" \
        parent "$parent" \
        protocol "$family" \
        pref "$pref" 2>/dev/null
}

filter_output_has_handle() {
    local output="$1"
    local expected="$2"
    local hex

    hex="${expected#0x}"

    echo "$output" |
        grep -Eq "handle (0x)?${hex}([[:space:]]|$)"
}

download_filter_is_ours() {
    local dev="$1"
    local family="$2"
    local port="$3"
    local proto="$4"
    local class_id="$5"

    local pref
    local handle
    local output

    pref=$(filter_pref "$family" "$proto" "$port") || return 1
    handle=$(filter_handle "$family" "$proto" "$port") || return 1
    output=$(filter_output "$dev" "1:" "$family" "$pref")

    [ -n "$output" ] || return 1
    filter_output_has_handle "$output" "$handle" || return 1

    echo "$output" | grep -q "src_port $port" || return 1
    echo "$output" | grep -q "ip_proto $proto" || return 1
    echo "$output" |
        grep -Eq "(classid|flowid)[[:space:]]+${class_id}" || return 1
}

upload_filter_is_ours() {
    local ifb="$1"
    local family="$2"
    local port="$3"
    local proto="$4"
    local class_id="$5"

    local pref
    local handle
    local output

    pref=$(filter_pref "$family" "$proto" "$port") || return 1
    handle=$(filter_handle "$family" "$proto" "$port") || return 1
    output=$(filter_output "$ifb" "1:" "$family" "$pref")

    [ -n "$output" ] || return 1
    filter_output_has_handle "$output" "$handle" || return 1

    echo "$output" | grep -q "dst_port $port" || return 1
    echo "$output" | grep -q "ip_proto $proto" || return 1
    echo "$output" |
        grep -Eq "(classid|flowid)[[:space:]]+${class_id}" || return 1
}

ingress_filter_is_ours() {
    local dev="$1"
    local ifb="$2"
    local family="$3"
    local port="$4"
    local proto="$5"

    local pref
    local handle
    local output

    pref=$(filter_pref "$family" "$proto" "$port") || return 1
    handle=$(filter_handle "$family" "$proto" "$port") || return 1
    output=$(filter_output "$dev" "ffff:" "$family" "$pref")

    [ -n "$output" ] || return 1
    filter_output_has_handle "$output" "$handle" || return 1

    echo "$output" | grep -q "dst_port $port" || return 1
    echo "$output" | grep -q "ip_proto $proto" || return 1
    echo "$output" | grep -q "$ifb" || return 1
    echo "$output" | grep -qi "mirred" || return 1
}

delete_exact_flower_filter() {
    local dev="$1"
    local parent="$2"
    local family="$3"
    local pref="$4"
    local handle="$5"

    tc filter del dev "$dev" \
        parent "$parent" \
        protocol "$family" \
        pref "$pref" \
        handle "$handle" \
        flower >/dev/null 2>&1
}

ensure_download_filter() {
    local dev="$1"
    local family="$2"
    local port="$3"
    local proto="$4"

    local class_id
    local pref
    local handle
    local output

    class_id=$(class_id_for_port "$port")
    pref=$(filter_pref "$family" "$proto" "$port") || return 1
    handle=$(filter_handle "$family" "$proto" "$port") || return 1

    if download_filter_is_ours \
        "$dev" "$family" "$port" "$proto" "$class_id"; then

        return 0
    fi

    output=$(filter_output "$dev" "1:" "$family" "$pref")

    if [ -n "$output" ]; then
        err "下载 filter pref 冲突：$dev/$family/pref=$pref"
        return 1
    fi

    tc filter add dev "$dev" \
        parent 1: \
        protocol "$family" \
        pref "$pref" \
        handle "$handle" \
        flower \
        skip_hw \
        ip_proto "$proto" \
        src_port "$port" \
        flowid "$class_id" >/dev/null 2>&1 || {
        err "创建下载 filter 失败：$dev/$family/$proto/$port"
        return 1
    }

    download_filter_is_ours \
        "$dev" "$family" "$port" "$proto" "$class_id"
}

ensure_upload_filter() {
    local ifb="$1"
    local family="$2"
    local port="$3"
    local proto="$4"

    local class_id
    local pref
    local handle
    local output

    class_id=$(class_id_for_port "$port")
    pref=$(filter_pref "$family" "$proto" "$port") || return 1
    handle=$(filter_handle "$family" "$proto" "$port") || return 1

    if upload_filter_is_ours \
        "$ifb" "$family" "$port" "$proto" "$class_id"; then

        return 0
    fi

    output=$(filter_output "$ifb" "1:" "$family" "$pref")

    if [ -n "$output" ]; then
        err "上传 filter pref 冲突：$ifb/$family/pref=$pref"
        return 1
    fi

    tc filter add dev "$ifb" \
        parent 1: \
        protocol "$family" \
        pref "$pref" \
        handle "$handle" \
        flower \
        skip_hw \
        ip_proto "$proto" \
        dst_port "$port" \
        flowid "$class_id" >/dev/null 2>&1 || {
        err "创建上传 filter 失败：$ifb/$family/$proto/$port"
        return 1
    }

    upload_filter_is_ours \
        "$ifb" "$family" "$port" "$proto" "$class_id"
}

ensure_ingress_filter() {
    local dev="$1"
    local ifb="$2"
    local family="$3"
    local port="$4"
    local proto="$5"

    local pref
    local handle
    local output

    pref=$(filter_pref "$family" "$proto" "$port") || return 1
    handle=$(filter_handle "$family" "$proto" "$port") || return 1

    if ingress_filter_is_ours \
        "$dev" "$ifb" "$family" "$port" "$proto"; then

        return 0
    fi

    output=$(filter_output "$dev" "ffff:" "$family" "$pref")

    if [ -n "$output" ]; then
        err "ingress filter pref 冲突：$dev/$family/pref=$pref"
        return 1
    fi

    tc filter add dev "$dev" \
        parent ffff: \
        protocol "$family" \
        pref "$pref" \
        handle "$handle" \
        flower \
        skip_hw \
        ip_proto "$proto" \
        dst_port "$port" \
        action mirred egress redirect dev "$ifb" \
        >/dev/null 2>&1 || {
        err "创建 ingress → IFB 规则失败：$dev/$family/$proto/$port"
        return 1
    }

    ingress_filter_is_ours \
        "$dev" "$ifb" "$family" "$port" "$proto"
}

delete_download_filter() {
    local dev="$1"
    local family="$2"
    local port="$3"
    local proto="$4"

    local class_id
    local pref
    local handle
    local output

    class_id=$(class_id_for_port "$port")
    pref=$(filter_pref "$family" "$proto" "$port") || return 0
    handle=$(filter_handle "$family" "$proto" "$port") || return 0
    output=$(filter_output "$dev" "1:" "$family" "$pref")

    [ -z "$output" ] && return 0

    if ! download_filter_is_ours \
        "$dev" "$family" "$port" "$proto" "$class_id"; then

        warn "拒绝删除非本脚本下载 filter：$dev/$family/pref=$pref"
        return 1
    fi

    delete_exact_flower_filter \
        "$dev" "1:" "$family" "$pref" "$handle"
}

delete_upload_filter() {
    local ifb="$1"
    local family="$2"
    local port="$3"
    local proto="$4"

    local class_id
    local pref
    local handle
    local output

    [ -z "$ifb" ] && return 0
    ip link show dev "$ifb" >/dev/null 2>&1 || return 0

    class_id=$(class_id_for_port "$port")
    pref=$(filter_pref "$family" "$proto" "$port") || return 0
    handle=$(filter_handle "$family" "$proto" "$port") || return 0
    output=$(filter_output "$ifb" "1:" "$family" "$pref")

    [ -z "$output" ] && return 0

    if ! upload_filter_is_ours \
        "$ifb" "$family" "$port" "$proto" "$class_id"; then

        warn "拒绝删除非本脚本上传 filter：$ifb/$family/pref=$pref"
        return 1
    fi

    delete_exact_flower_filter \
        "$ifb" "1:" "$family" "$pref" "$handle"
}

delete_ingress_filter() {
    local dev="$1"
    local ifb="$2"
    local family="$3"
    local port="$4"
    local proto="$5"

    local pref
    local handle
    local output

    [ -z "$ifb" ] && return 0

    pref=$(filter_pref "$family" "$proto" "$port") || return 0
    handle=$(filter_handle "$family" "$proto" "$port") || return 0
    output=$(filter_output "$dev" "ffff:" "$family" "$pref")

    [ -z "$output" ] && return 0

    if ! ingress_filter_is_ours \
        "$dev" "$ifb" "$family" "$port" "$proto"; then

        warn "拒绝删除非本脚本 ingress filter：$dev/$family/pref=$pref"
        return 1
    fi

    delete_exact_flower_filter \
        "$dev" "ffff:" "$family" "$pref" "$handle"
}

ensure_proto_rules() {
    local dev="$1"
    local ifb="$2"
    local port="$3"
    local proto="$4"
    local family

    for family in ip ipv6; do
        ensure_download_filter \
            "$dev" "$family" "$port" "$proto" || return 1

        ensure_upload_filter \
            "$ifb" "$family" "$port" "$proto" || return 1

        ensure_ingress_filter \
            "$dev" "$ifb" "$family" "$port" "$proto" || return 1
    done
}

delete_proto_rules() {
    local dev="$1"
    local ifb="$2"
    local port="$3"
    local proto="$4"
    local family
    local failed=0

    for family in ip ipv6; do
        delete_download_filter \
            "$dev" "$family" "$port" "$proto" || failed=1

        delete_upload_filter \
            "$ifb" "$family" "$port" "$proto" || failed=1

        delete_ingress_filter \
            "$dev" "$ifb" "$family" "$port" "$proto" || failed=1
    done

    return "$failed"
}

cleanup_legacy_matchall() {
    local dev="$1"
    local ifb="$2"
    local output

    [ -z "$ifb" ] && return 0

    output=$(
        tc filter show dev "$dev" \
            parent ffff: \
            protocol all \
            pref "$LEGACY_INGRESS_PREF" 2>/dev/null
    )

    [ -z "$output" ] && return 0

    if echo "$output" | grep -qi "matchall" &&
        echo "$output" | grep -qi "mirred" &&
        echo "$output" | grep -q "$ifb"; then

        tc filter del dev "$dev" \
            parent ffff: \
            protocol all \
            pref "$LEGACY_INGRESS_PREF" \
            >/dev/null 2>&1 || return 1
    fi
}

delete_legacy_mark_rule() {
    local tool="$1"
    local dev="$2"
    local proto="$3"
    local port="$4"
    local handle="$5"

    command -v "$tool" >/dev/null 2>&1 || return 0

    while "$tool" -t mangle -C OUTPUT \
        -o "$dev" \
        -p "$proto" \
        --sport "$port" \
        -j MARK \
        --set-mark "$handle" 2>/dev/null; do

        "$tool" -t mangle -D OUTPUT \
            -o "$dev" \
            -p "$proto" \
            --sport "$port" \
            -j MARK \
            --set-mark "$handle" 2>/dev/null || break
    done

    while "$tool" -t mangle -C OUTPUT \
        -p "$proto" \
        --sport "$port" \
        -j MARK \
        --set-mark "$handle" 2>/dev/null; do

        "$tool" -t mangle -D OUTPUT \
            -p "$proto" \
            --sport "$port" \
            -j MARK \
            --set-mark "$handle" 2>/dev/null || break
    done
}

cleanup_legacy_marks_for_file() {
    local file="$1"
    local target_dev="${2:-}"

    local dev
    local port
    local proto
    local rate
    local class_id
    local handle

    [ -f "$file" ] || return 0

    while IFS='|' read -r \
        dev port proto rate class_id handle; do

        [ -z "$dev" ] && continue

        if [ -n "$target_dev" ] &&
            [ "$dev" != "$target_dev" ]; then

            continue
        fi

        delete_legacy_mark_rule \
            iptables "$dev" "$proto" "$port" "$handle"

        delete_legacy_mark_rule \
            ip6tables "$dev" "$proto" "$port" "$handle"
    done < "$file"
}

cleanup_ingress_for_file() {
    local file="$1"
    local target_dev="$2"
    local ifb="$3"

    local dev
    local port
    local proto
    local rate
    local class_id
    local handle
    local family
    local failed=0

    [ -f "$file" ] || return 0

    while IFS='|' read -r \
        dev port proto rate class_id handle; do

        [ "$dev" = "$target_dev" ] || continue

        for family in ip ipv6; do
            if ! delete_ingress_filter \
                "$dev" "$ifb" "$family" "$port" "$proto"; then

                failed=1
            fi
        done
    done < "$file"

    return "$failed"
}


wait_for_interface() {
    local dev="$1"
    local timeout="${2:-0}"
    local elapsed=0

    while ! ip link show dev "$dev" >/dev/null 2>&1; do
        if [ "$elapsed" -ge "$timeout" ]; then
            return 1
        fi

        sleep 2
        elapsed=$((elapsed+2))
    done
}

cleanup_device_state() {
    local dev="$1"
    shift

    local ifb
    local file
    local failed=0

    ifb=$(lookup_ifb_name "$dev")

    if [ -z "$ifb" ]; then
        resolve_ifb_name "$dev" 0 || true
        ifb="$IFB_DEV"
    fi

    # 先停止所有指向 IFB 的流量重定向。
    if ! cleanup_legacy_matchall "$dev" "$ifb"; then
        err "删除旧版全流量 ingress 重定向失败：$dev"
        failed=1
    fi

    for file in "$@"; do
        cleanup_legacy_marks_for_file "$file" "$dev"

        if ! cleanup_ingress_for_file \
            "$file" "$dev" "$ifb"; then

            err "删除 ingress 端口重定向规则失败：$dev"
            failed=1
        fi
    done

    # ingress 规则未能完整删除时，不能继续删除 IFB，
    # 否则可能残留指向一个不完整 IFB 的重定向规则。
    if [ "$failed" -ne 0 ]; then
        err "网卡清理未完成，已停止后续 IFB/root 删除：$dev"
        return 1
    fi

    if ! cleanup_owned_ingress_if_empty "$dev"; then
        err "删除本脚本拥有的空 ingress qdisc 失败：$dev"
        return 1
    fi

    # 只自动删除带本脚本专属标记的 HTB。
    if root_qdisc_is_ours "$dev"; then
        if ! tc qdisc del dev "$dev" root >/dev/null 2>&1; then
            err "删除物理网卡 HTB root qdisc 失败：$dev"
            return 1
        fi

    elif root_qdisc_is_htb_base "$dev" &&
         root_is_owned "$dev"; then

        # 这通常表示当前仍是旧版脚本建立的无标记 HTB，
        # 或 root 已被另一个 handle 1: HTB 替换。
        # 在无法确认所有权时，拒绝静默删除。
        err "检测到未带本脚本专属标记的 HTB：$dev"
        err "请先执行菜单 7，并确认重新接管后再删除"
        return 1
    fi

    # safe_delete_ifb() 会再次确认：
    # 1) 接口类型是 IFB；
    # 2) alias 属于当前物理网卡；
    # 3) ingress 中不再有规则指向该 IFB。
    if [ -n "$ifb" ]; then
        if ! safe_delete_ifb "$dev" "$ifb"; then
            err "删除 IFB 失败：$dev → $ifb"
            return 1
        fi
    fi

    # 只有内核资源全部清理成功后，才解除 root 接管授权。
    if ! file_remove_exact_line "$ROOT_OWNED_FILE" "$dev"; then
        err "删除 root 接管授权记录失败：$dev"
        return 1
    fi

    return 0
}


full_rebuild_device() {
    local dev="$1"
    local desired_file="$2"
    local wait_seconds="$3"
    shift 3

    local context_file
    local ifb
    local port
    local rate
    local proto
    local class_id
    local handle

    if ! has_rules_for_dev_in_file "$desired_file" "$dev"; then
        cleanup_device_state "$dev" "$desired_file" "$@"
        return $?
    fi

    if ! wait_for_interface "$dev" "$wait_seconds"; then
        err "等待网卡超时：$dev"
        return 1
    fi

    root_takeover_allowed "$dev" || return 1
    ROOT_TAKEOVER_APPROVED["$dev"]=1

    ifb=$(lookup_ifb_name "$dev")

    if [ -z "$ifb" ]; then
        resolve_ifb_name "$dev" 0 || true
        ifb="$IFB_DEV"
    fi

    cleanup_legacy_matchall "$dev" "$ifb" || return 1
    cleanup_legacy_marks_for_file "$desired_file" "$dev"

    if ! cleanup_ingress_for_file \
        "$desired_file" "$dev" "$ifb"; then

        err "完整重建前删除当前 ingress 规则失败：$dev"
        return 1
    fi

    for context_file in "$@"; do
        cleanup_legacy_marks_for_file "$context_file" "$dev"

        if ! cleanup_ingress_for_file \
            "$context_file" "$dev" "$ifb"; then

            err "完整重建前删除历史 ingress 规则失败：$dev"
            return 1
        fi
    done


    # full_rebuild_device() 运行到这里时，已经通过
    # root_takeover_allowed() 验证，并记录了本次接管授权。
    #
    # 如果当前是 HTB handle 1:，无论它是旧版脚本建立的
    # 无标记 HTB，还是用户刚确认允许覆盖的第三方 HTB，
    # 都先删除后从配置完整重建，避免残留旧 class/filter。
    if root_qdisc_is_htb_base "$dev"; then
        tc qdisc del dev "$dev" root >/dev/null 2>&1 || {
            err "删除旧物理网卡 HTB 失败：$dev"
            return 1
        }
    fi


    ensure_ifb_device "$dev" || return 1
    ifb="$IFB_DEV"

    tc qdisc del dev "$ifb" root >/dev/null 2>&1 || true

    ensure_physical_root "$dev" || return 1
    ensure_ifb_root "$dev" "$ifb" || return 1
    ensure_ingress_qdisc "$dev" || return 1

    while IFS='|' read -r port rate; do
        [ -z "$port" ] && continue

        ensure_rate_class "$dev" "$port" "$rate" || return 1
        ensure_rate_class "$ifb" "$port" "$rate" || return 1
    done < <(
        awk -F'|' \
            -v dev="$dev" '
                $1==dev && !seen[$2]++ {
                    print $2 "|" $4
                }
            ' "$desired_file"
    )

    while IFS='|' read -r \
        _ port proto rate class_id handle; do

        [ -z "$port" ] && continue

        ensure_proto_rules \
            "$dev" "$ifb" "$port" "$proto" || return 1
    done < <(
        awk -F'|' \
            -v dev="$dev" '
                $1==dev {
                    print
                }
            ' "$desired_file"
    )
}

ensure_incremental_base() {
    local dev="$1"
    local ifb

    BASE_REBUILD_REQUIRED=0

    wait_for_interface "$dev" 0 || {
        err "网卡不存在：$dev"
        return 1
    }

    ensure_physical_root "$dev" || return 1

    if [ "$PHYSICAL_ROOT_WAS_CREATED" -eq 1 ]; then
        BASE_REBUILD_REQUIRED=1
    fi

    ensure_ifb_device "$dev" || return 1
    ifb="$IFB_DEV"

    if [ "$IFB_WAS_CREATED" -eq 1 ]; then
        BASE_REBUILD_REQUIRED=1
    fi

    ensure_ifb_root "$dev" "$ifb" || return 1

    if [ "$IFB_ROOT_WAS_CREATED" -eq 1 ]; then
        BASE_REBUILD_REQUIRED=1
    fi

    ensure_ingress_qdisc "$dev" || return 1

    if [ "$INGRESS_WAS_CREATED" -eq 1 ]; then
        BASE_REBUILD_REQUIRED=1
    fi
}

incremental_apply_device() {
    local dev="$1"
    local old_file="$2"
    local new_file="$3"

    local ifb
    local port
    local proto
    local rate
    local class_id
    local handle
    local old_rate

    if ! has_rules_for_dev_in_file "$new_file" "$dev"; then
        cleanup_device_state \
            "$dev" "$old_file" "$new_file" "$APPLIED_FILE"

        return $?
    fi

    ensure_incremental_base "$dev" || return 1
    ifb="$IFB_DEV"

    if [ "$BASE_REBUILD_REQUIRED" -eq 1 ]; then
        info "基础 qdisc/IFB 不完整，只重建网卡 $dev"

        full_rebuild_device \
            "$dev" "$new_file" 0 \
            "$old_file" "$APPLIED_FILE"

        return $?
    fi

    cleanup_legacy_marks_for_file "$old_file" "$dev"
    cleanup_legacy_marks_for_file "$new_file" "$dev"
    cleanup_legacy_matchall "$dev" "$ifb" || return 1

    while IFS='|' read -r \
        _ port proto rate class_id handle; do

        [ -z "$port" ] && continue

        if ! rule_exists_in_file \
            "$new_file" "$dev" "$port" "$proto"; then

            delete_proto_rules \
                "$dev" "$ifb" "$port" "$proto" || return 1
        fi
    done < <(
        awk -F'|' \
            -v dev="$dev" '
                $1==dev {
                    print
                }
            ' "$old_file"
    )

    while IFS='|' read -r port rate; do
        [ -z "$port" ] && continue

        old_rate=$(get_port_rate_from_file \
            "$old_file" "$dev" "$port")

        class_id=$(class_id_for_port "$port")

        if [ -z "$old_rate" ] ||
            [ "$old_rate" != "$rate" ] ||
            ! tc_class_exists "$dev" "$class_id" ||
            ! fq_codel_exists "$dev" "$class_id" ||
            ! tc_class_exists "$ifb" "$class_id" ||
            ! fq_codel_exists "$ifb" "$class_id"; then

            ensure_rate_class "$dev" "$port" "$rate" || return 1
            ensure_rate_class "$ifb" "$port" "$rate" || return 1
        fi
    done < <(
        awk -F'|' \
            -v dev="$dev" '
                $1==dev && !seen[$2]++ {
                    print $2 "|" $4
                }
            ' "$new_file"
    )

    while IFS='|' read -r \
        _ port proto rate class_id handle; do

        [ -z "$port" ] && continue

        ensure_proto_rules \
            "$dev" "$ifb" "$port" "$proto" || return 1
    done < <(
        awk -F'|' \
            -v dev="$dev" '
                $1==dev {
                    print
                }
            ' "$new_file"
    )

    while IFS='|' read -r port; do
        [ -z "$port" ] && continue

        if ! has_rules_for_port_in_file \
            "$new_file" "$dev" "$port"; then

            delete_rate_class "$dev" "$port"
            delete_rate_class "$ifb" "$port"
        fi
    done < <(
        awk -F'|' \
            -v dev="$dev" '
                $1==dev && !seen[$2]++ {
                    print $2
                }
            ' "$old_file"
    )
}

update_applied_for_device() {
    local dev="$1"
    local source_file="$2"
    local tmp

    tmp=$(make_temp_file "$APPLIED_FILE") || return 1

    awk -F'|' \
        -v dev="$dev" '
            $1!=dev
        ' "$APPLIED_FILE" > "$tmp" || true

    awk -F'|' \
        -v dev="$dev" '
            $1==dev
        ' "$source_file" >> "$tmp"

    chmod 600 "$tmp"
    mv -f "$tmp" "$APPLIED_FILE"
}

commit_incremental() {
    local candidate="$1"
    local action="$2"
    local dev="$3"

    local normalized
    local root_backup
    local old_rules

    clear_takeover_approvals

    normalized=$(make_temp_file "$RULES_FILE") || return 1
    root_backup=$(make_temp_file "$ROOT_OWNED_FILE") || {
        rm -f "$normalized"
        return 1
    }
    old_rules=$(make_temp_file "$RULES_FILE") || {
        rm -f "$normalized" "$root_backup"
        return 1
    }

    cp -f "$ROOT_OWNED_FILE" "$root_backup"
    cp -f "$RULES_FILE" "$old_rules"

    chmod 600 "$root_backup" "$old_rules"

    if ! normalize_rules_file "$candidate" "$normalized"; then
        rm -f "$normalized" "$root_backup" "$old_rules"
        return 1
    fi

    if has_rules_for_dev_in_file "$normalized" "$dev"; then
        if ! approve_root_takeover "$dev"; then
            cp -f "$root_backup" "$ROOT_OWNED_FILE"

            clear_takeover_approvals
            rm -f "$normalized" "$root_backup" "$old_rules"

            warn "操作已取消"
            return 1
        fi
    fi

    if incremental_apply_device \
        "$dev" "$old_rules" "$normalized"; then

        mv -f "$normalized" "$RULES_FILE"
        chmod 600 "$RULES_FILE"

        update_applied_for_device "$dev" "$RULES_FILE" || true
        create_restore_assets_if_enabled

        clear_takeover_approvals
        rm -f "$root_backup" "$old_rules"

        msg "$action 成功"
        log_event INFO "$action 成功：$dev"

        return 0
    fi

    err "$action 失败，正在回滚网卡 $dev"

    # 必须在重建旧规则之前恢复 root 接管授权。
    # 删除/清空操作可能已经移除授权记录或物理网卡 HTB；
    # 如果先调用 full_rebuild_device，回滚可能因无授权而失败。
    if ! cp -f "$root_backup" "$ROOT_OWNED_FILE"; then
        err "回滚前恢复 root 接管授权失败：$dev"
        log_event ERROR "$action 回滚前恢复 root-owned.conf 失败：$dev"
    else
        chmod 600 "$ROOT_OWNED_FILE"
    fi

    # 本次操作的目标就是恢复修改前状态。
    # 如果失败操作已经使 root 变成系统默认 fq/fq_codel/cake，
    # 允许本次回滚重新接管并恢复旧 HTB。
    if root_is_owned "$dev"; then
        ROOT_TAKEOVER_APPROVED["$dev"]=1
    fi

    if ! full_rebuild_device \
        "$dev" "$old_rules" 0 \
        "$normalized" "$APPLIED_FILE"; then

        err "回滚网卡 $dev 失败，请立即执行菜单 7"
        log_event ERROR "$action 回滚失败：$dev"
    else
        warn "已恢复网卡 $dev 的操作前规则"

        if ! update_applied_for_device "$dev" "$old_rules"; then
            warn "旧规则已恢复，但 applied.conf 更新失败：$dev"
            log_event ERROR "$action 回滚后更新 applied.conf 失败：$dev"
        fi
    fi


    clear_takeover_approvals
    rm -f "$normalized" "$root_backup" "$old_rules"

    return 1
}

device_config_equal() {
    local file_a="$1"
    local file_b="$2"
    local dev="$3"

    diff -q \
        <(
            awk -F'|' -v dev="$dev" '$1==dev {print}' "$file_a" |
                sort
        ) \
        <(
            awk -F'|' -v dev="$dev" '$1==dev {print}' "$file_b" |
                sort
        ) >/dev/null 2>&1
}

rate_to_bps() {
    local rate="${1,,}"

    awk -v rate="$rate" '
        BEGIN {
            if (!match(rate, /^[0-9.]+/)) {
                exit 1
            }

            value=substr(rate, RSTART, RLENGTH)
            unit=substr(rate, RLENGTH+1)

            if (unit=="bit") {
                multiplier=1
            } else if (unit=="kbit") {
                multiplier=1000
            } else if (unit=="mbit") {
                multiplier=1000000
            } else if (unit=="gbit") {
                multiplier=1000000000
            } else if (unit=="tbit") {
                multiplier=1000000000000
            } else {
                exit 1
            }

            printf "%.0f\n", value*multiplier
        }
    '
}

class_rate_pair() {
    local dev="$1"
    local class_id="$2"

    tc class show dev "$dev" \
        classid "$class_id" 2>/dev/null |
        awk '
            /class htb/ {
                rate=""
                ceil=""

                for (i=1; i<=NF; i++) {
                    if ($i=="rate") {
                        rate=$(i+1)
                    }

                    if ($i=="ceil") {
                        ceil=$(i+1)
                    }
                }

                print rate "|" ceil
                exit
            }
        '
}

class_rate_matches() {
    local dev="$1"
    local class_id="$2"
    local expected="$3"

    local pair
    local actual_rate
    local actual_ceil
    local expected_bps
    local actual_rate_bps
    local actual_ceil_bps

    pair=$(class_rate_pair "$dev" "$class_id")
    [ -n "$pair" ] || return 1

    actual_rate="${pair%%|*}"
    actual_ceil="${pair#*|}"

    expected_bps=$(rate_to_bps "$expected") || return 1
    actual_rate_bps=$(rate_to_bps "$actual_rate") || return 1
    actual_ceil_bps=$(rate_to_bps "$actual_ceil") || return 1

    [ "$expected_bps" = "$actual_rate_bps" ] &&
        [ "$expected_bps" = "$actual_ceil_bps" ]
}

device_state_ok() {
    local dev="$1"
    local file="$2"

    local ifb
    local port
    local proto
    local rate
    local class_id
    local handle
    local family

    has_rules_for_dev_in_file "$file" "$dev" || return 1
    root_is_owned "$dev" || return 1
    root_qdisc_is_ours "$dev" || return 1

    ifb=$(lookup_ifb_name "$dev")
    [ -n "$ifb" ] || return 1

    validate_owned_ifb "$dev" "$ifb" || return 1
    root_qdisc_is_ours "$ifb" || return 1

    while IFS='|' read -r port rate; do
        [ -z "$port" ] && continue

        class_id=$(class_id_for_port "$port")

        tc_class_exists "$dev" "$class_id" || return 1
        fq_codel_exists "$dev" "$class_id" || return 1
        class_rate_matches "$dev" "$class_id" "$rate" || return 1

        tc_class_exists "$ifb" "$class_id" || return 1
        fq_codel_exists "$ifb" "$class_id" || return 1
        class_rate_matches "$ifb" "$class_id" "$rate" || return 1
    done < <(
        awk -F'|' \
            -v dev="$dev" '
                $1==dev && !seen[$2]++ {
                    print $2 "|" $4
                }
            ' "$file"
    )

    while IFS='|' read -r \
        _ port proto rate class_id handle; do

        [ -z "$port" ] && continue
        class_id=$(class_id_for_port "$port")

        for family in ip ipv6; do
            download_filter_is_ours \
                "$dev" "$family" "$port" "$proto" "$class_id" ||
                return 1

            upload_filter_is_ours \
                "$ifb" "$family" "$port" "$proto" "$class_id" ||
                return 1

            ingress_filter_is_ours \
                "$dev" "$ifb" "$family" "$port" "$proto" ||
                return 1
        done
    done < <(
        awk -F'|' \
            -v dev="$dev" '
                $1==dev {
                    print
                }
            ' "$file"
    )

    return 0
}

collect_managed_devices() {
    {
        awk -F'|' '$1!="" {print $1}' "$RULES_FILE" 2>/dev/null
        awk -F'|' '$1!="" {print $1}' "$APPLIED_FILE" 2>/dev/null
        awk -F'|' '$1!="" {print $1}' "$IFB_MAP_FILE" 2>/dev/null
        cat "$ROOT_OWNED_FILE" 2>/dev/null
        cat "$INGRESS_OWNED_FILE" 2>/dev/null
    } |
        sed '/^[[:space:]]*$/d' |
        sort -u
}

restore_all_devices_independently() {
    local wait_seconds="${1:-120}"
    local dev
    local failed=0

    while IFS= read -r dev; do
        [ -z "$dev" ] && continue

        if has_rules_for_dev_in_file "$RULES_FILE" "$dev" &&
            device_config_equal "$RULES_FILE" "$APPLIED_FILE" "$dev" &&
            device_state_ok "$dev" "$RULES_FILE"; then

            log_event INFO "网卡状态已正常，跳过重建：$dev"
            continue
        fi

        if full_rebuild_device \
            "$dev" "$RULES_FILE" "$wait_seconds" \
            "$APPLIED_FILE"; then

            update_applied_for_device "$dev" "$RULES_FILE" || true
            log_event INFO "网卡规则恢复成功：$dev"
        else
            err "同步网卡规则失败：$dev"
            log_event ERROR "同步网卡规则失败：$dev"
            failed=1
        fi
    done < <(collect_managed_devices)

    return "$failed"
}

tc_class_stats() {
    local dev="$1"
    local class_id="$2"

    local line
    local bytes
    local packets
    local dropped
    local overlimits

    line=$(
        tc -s class show dev "$dev" \
            classid "$class_id" 2>/dev/null |
            grep -m1 'Sent [0-9]'
    )

    if [ -z "$line" ]; then
        echo "0|0|0|0"
        return
    fi

    bytes=$(
        echo "$line" |
            awk '{
                for (i=1; i<=NF; i++) {
                    if ($i=="Sent") {
                        print $(i+1)
                        exit
                    }
                }
            }'
    )

    packets=$(
        echo "$line" |
            awk '{
                for (i=1; i<=NF; i++) {
                    if ($i=="pkt") {
                        print $(i-1)
                        exit
                    }
                }
            }'
    )

    dropped=$(
        echo "$line" |
            sed -n 's/.*dropped \([0-9][0-9]*\).*/\1/p'
    )

    overlimits=$(
        echo "$line" |
            sed -n 's/.*overlimits \([0-9][0-9]*\).*/\1/p'
    )

    echo "${bytes:-0}|${packets:-0}|${dropped:-0}|${overlimits:-0}"
}

human_bytes() {
    local bytes="${1:-0}"

    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec-i --suffix=B "$bytes" 2>/dev/null ||
            echo "${bytes}B"
    else
        echo "${bytes}B"
    fi
}

rule_loaded_status() {
    local dev="$1"
    local port="$2"
    local proto_show="$3"
    local rate="$4"

    local ifb
    local class_id
    local proto
    local family
    local -a protos=()
    local -a problems=()

    class_id=$(class_id_for_port "$port")
    ifb=$(lookup_ifb_name "$dev")

    root_qdisc_is_ours "$dev" ||
        problems+=("下载qdisc")

    tc_class_exists "$dev" "$class_id" ||
        problems+=("下载class")

    fq_codel_exists "$dev" "$class_id" ||
        problems+=("下载fq_codel")

    class_rate_matches "$dev" "$class_id" "$rate" ||
        problems+=("下载速率")

    if [ -z "$ifb" ] ||
        ! validate_owned_ifb "$dev" "$ifb"; then

        problems+=("IFB")
    else
        root_qdisc_is_ours "$ifb" ||
            problems+=("上传qdisc")

        tc_class_exists "$ifb" "$class_id" ||
            problems+=("上传class")

        fq_codel_exists "$ifb" "$class_id" ||
            problems+=("上传fq_codel")

        class_rate_matches "$ifb" "$class_id" "$rate" ||
            problems+=("上传速率")
    fi

    case "$proto_show" in
        tcp)
            protos=(tcp)
            ;;
        udp)
            protos=(udp)
            ;;
        *)
            protos=(tcp udp)
            ;;
    esac

    for proto in "${protos[@]}"; do
        for family in ip ipv6; do
            download_filter_is_ours \
                "$dev" "$family" "$port" "$proto" "$class_id" ||
                problems+=("下载${family}/${proto}")

            if [ -n "$ifb" ]; then
                upload_filter_is_ours \
                    "$ifb" "$family" "$port" "$proto" "$class_id" ||
                    problems+=("上传${family}/${proto}")

                ingress_filter_is_ours \
                    "$dev" "$ifb" "$family" "$port" "$proto" ||
                    problems+=("重定向${family}/${proto}")
            fi
        done
    done

    if [ "${#problems[@]}" -eq 0 ]; then
        echo "双向正常"
    else
        local joined

        joined=$(IFS=,; echo "${problems[*]}")
        echo "异常:${joined}"
    fi
}

create_merged_rules_cache() {
    MERGED_RULES=()

    local dev
    local port
    local rate
    local key
    local proto_show
    local tcp_exists
    local udp_exists

    declare -A seen=()
    local -a keys=()

    while IFS='|' read -r \
        dev port _ rate _ _; do

        [ -z "$dev" ] && continue

        key="${dev}|${port}"

        if [ -z "${seen[$key]+x}" ]; then
            seen["$key"]=1
            keys+=("$key")
        fi
    done < "$RULES_FILE"

    for key in "${keys[@]}"; do
        dev="${key%%|*}"
        port="${key#*|}"
        rate=$(get_port_rate_from_file "$RULES_FILE" "$dev" "$port")

        tcp_exists=0
        udp_exists=0

        rule_exists "$dev" "$port" tcp && tcp_exists=1
        rule_exists "$dev" "$port" udp && udp_exists=1

        if [ "$tcp_exists" -eq 1 ] &&
            [ "$udp_exists" -eq 1 ]; then

            proto_show="tcp+udp"
        elif [ "$tcp_exists" -eq 1 ]; then
            proto_show="tcp"
        else
            proto_show="udp"
        fi

        MERGED_RULES+=(
            "${dev}|${port}|${proto_show}|${rate}"
        )
    done
}

show_status_simple() {
    local i=1
    local row
    local dev
    local port
    local proto
    local rate
    local ifb
    local class_id
    local up_stats
    local down_stats
    local up_bytes
    local up_packets
    local up_dropped
    local up_over
    local down_bytes
    local down_packets
    local down_dropped
    local down_over
    local status

    create_merged_rules_cache

    echo
    info "================ 当前双向限速状态 ================"

    if [ "${#MERGED_RULES[@]}" -eq 0 ]; then
        warn "当前没有限速规则"
        return
    fi

    {
        echo "编号|网卡|IFB|端口|协议|配置速率|上传流量|下载流量|丢包(上/下)|超限(上/下)|状态"
        echo "----|----|---|----|----|--------|--------|--------|-----------|-----------|----"

        for row in "${MERGED_RULES[@]}"; do
            IFS='|' read -r \
                dev port proto rate <<< "$row"

            ifb=$(lookup_ifb_name "$dev")
            class_id=$(class_id_for_port "$port")

            down_stats=$(tc_class_stats "$dev" "$class_id")

            IFS='|' read -r \
                down_bytes down_packets down_dropped down_over \
                <<< "$down_stats"

            if [ -n "$ifb" ]; then
                up_stats=$(tc_class_stats "$ifb" "$class_id")
            else
                up_stats="0|0|0|0"
                ifb="-"
            fi

            IFS='|' read -r \
                up_bytes up_packets up_dropped up_over \
                <<< "$up_stats"

            status=$(
                rule_loaded_status \
                    "$dev" "$port" "$proto" "$rate"
            )

            echo "${i}|${dev}|${ifb}|${port}|${proto}|${rate}|$(human_bytes "$up_bytes")/${up_packets}包|$(human_bytes "$down_bytes")/${down_packets}包|${up_dropped}/${down_dropped}|${up_over}/${down_over}|${status}"

            i=$((i+1))
        done
    } | show_table
}

show_status() {
    show_status_simple

    echo
    echo "说明："
    echo "1) 上传、下载分别使用相同上限。"
    echo "2) 普通添加、删除、修改使用增量更新。"
    echo "3) 菜单 7 和开机恢复执行完整状态同步。"
    echo "4) TCP ACK、协议头和代理封装开销会计入带宽。"
}

detect_xui_db() {
    local -a candidates=(
        "/etc/x-ui/x-ui.db"
        "/usr/local/x-ui/x-ui.db"
        "/etc/3x-ui/x-ui.db"
        "/usr/local/3x-ui/x-ui.db"
        "/opt/x-ui/x-ui.db"
        "/opt/3x-ui/x-ui.db"
        "/root/x-ui.db"
    )

    local db
    local found

    for db in "${candidates[@]}"; do
        if [ -f "$db" ]; then
            XUI_DB_PATH="$db"
            return 0
        fi
    done

    found=$(find / -name "x-ui.db" 2>/dev/null | head -n1)

    if [ -n "$found" ]; then
        XUI_DB_PATH="$found"
        return 0
    fi

    return 1
}

query_xui_nodes() {
    local db="$1"

    sqlite3 -separator '|' "$db" "
        SELECT
            COALESCE(id,''),
            REPLACE(
                REPLACE(
                    REPLACE(COALESCE(remark,''),'|','/'),
                    CHAR(10),
                    ' '
                ),
                CHAR(13),
                ' '
            ),
            COALESCE(port,''),
            REPLACE(COALESCE(protocol,''),'|','/'),
            COALESCE(enable,'')
        FROM inbounds
        ORDER BY
            CASE
                WHEN enable IN (1,'1',true,'true') THEN 0
                ELSE 1
            END,
            id ASC;
    " 2>/dev/null
}

port_is_limited_anywhere() {
    local port="$1"

    awk -F'|' \
        -v port="$port" '
            $2==port {
                found=1
                exit
            }
            END {
                exit !found
            }
        ' "$RULES_FILE" 2>/dev/null
}

choose_xui_node_or_manual() {
    local rows
    local row
    local id
    local remark
    local port
    local proto
    local enable
    local state
    local limited
    local choice
    local selected
    local i=1

    if ! command -v sqlite3 >/dev/null 2>&1 ||
        ! detect_xui_db; then

        return 1
    fi

    rows=$(query_xui_nodes "$XUI_DB_PATH")

    [ -n "$rows" ] || return 1

    mapfile -t NODE_ROWS <<< "$rows"

    echo
    info "================ 选择 x-ui 节点 ================"
    echo "数据库：$XUI_DB_PATH"

    {
        echo "编号|状态|端口|协议|备注|限速状态"
        echo "----|----|----|----|----|--------"

        for row in "${NODE_ROWS[@]}"; do
            IFS='|' read -r \
                id remark port proto enable <<< "$row"

            [ -z "$remark" ] && remark="-"
            [ -z "$proto" ] && proto="-"

            state="停用"

            if [[ "$enable" == "1" ||
                  "$enable" == "true" ||
                  "$enable" == "TRUE" ]]; then
                state="启用"
            fi

            limited="未限速"

            if valid_port "$port" &&
                port_is_limited_anywhere "$port"; then
                limited="已限速"
            fi

            echo "$i|$state|$port|$proto|$remark|$limited"
            i=$((i+1))
        done
    } | show_table

    echo
    read -rp "请选择节点编号（m=手动输入）: " choice

    choice=$(trim "$choice")

    if [[ "$choice" == "m" || "$choice" == "M" ]]; then
        return 1
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]] ||
        [ "$choice" -lt 1 ] ||
        [ "$choice" -gt "${#NODE_ROWS[@]}" ]; then

        err "节点编号无效"
        return 2
    fi

    selected="${NODE_ROWS[$((choice-1))]}"

    IFS='|' read -r \
        id remark port proto enable <<< "$selected"

    valid_port "$port" || return 1

    SELECTED_PORT="$port"
    SELECTED_REMARK="${remark:--}"
    SELECTED_NODE_PROTO="${proto:--}"

    return 0
}

input_manual_port() {
    local port

    read -rp "请输入节点端口: " port
    port=$(trim "$port")

    if ! valid_port "$port"; then
        err "端口必须为 1～65535"
        return 1
    fi

    SELECTED_PORT="$port"
    SELECTED_REMARK="-"
    SELECTED_NODE_PROTO="-"
}

choose_protocol() {
    local choice

    echo

    {
        echo "编号|协议"
        echo "----|----"
        echo "1|仅 TCP"
        echo "2|仅 UDP"
        echo "3|TCP + UDP"
    } | show_table

    read -rp "请选择协议 [1-3]: " choice

    case "$choice" in
        1)
            SELECTED_PROTO="tcp"
            ;;
        2)
            SELECTED_PROTO="udp"
            ;;
        3)
            SELECTED_PROTO="both"
            ;;
        *)
            return 1
            ;;
    esac
}

confirm_action() {
    local action="$1"
    local dev="$2"
    local port="$3"
    local remark="$4"
    local proto="$5"
    local rate="$6"
    local answer

    echo
    info "================ 操作确认 ================"

    {
        echo "项目|内容"
        echo "----|----"
        echo "动作|$action"
        echo "网卡|$dev"
        echo "端口|$port"
        echo "备注|$remark"
        echo "协议|$proto"
        echo "上传速率|$rate"
        echo "下载速率|$rate"
        echo "IP版本|IPv4 + IPv6"
    } | show_table

    echo
    read -rp "确认继续？[y/n]: " answer

    [[ "$answer" == "y" || "$answer" == "Y" ]]
}

choose_existing_rule() {
    local index
    local i=1
    local row
    local dev
    local port
    local proto
    local rate
    local selected

    create_merged_rules_cache

    if [ "${#MERGED_RULES[@]}" -eq 0 ]; then
        warn "当前没有限速规则"
        return 1
    fi

    {
        echo "编号|网卡|端口|协议|速率"
        echo "----|----|----|----|----"

        for row in "${MERGED_RULES[@]}"; do
            IFS='|' read -r \
                dev port proto rate <<< "$row"

            echo "$i|$dev|$port|$proto|$rate"
            i=$((i+1))
        done
    } | show_table

    echo
    read -rp "请选择规则编号: " index

    if ! [[ "$index" =~ ^[0-9]+$ ]] ||
        [ "$index" -lt 1 ] ||
        [ "$index" -gt "${#MERGED_RULES[@]}" ]; then

        err "规则编号无效"
        return 1
    fi

    selected="${MERGED_RULES[$((index-1))]}"

    IFS='|' read -r \
        SELECTED_DEV \
        SELECTED_PORT \
        SELECTED_PROTO_SHOW \
        SELECTED_RATE <<< "$selected"
}

add_limit_interactive() {
    local dev
    local node_result
    local port
    local remark
    local mbps
    local rate
    local id
    local class_id
    local conflict
    local existing_rate
    local answer
    local candidate
    local proto_show
    local proto
    local -a protos=()

    choose_interface || return
    dev="$SELECTED_DEV"

    choose_xui_node_or_manual
    node_result=$?

    if [ "$node_result" -eq 1 ]; then
        input_manual_port || return
    elif [ "$node_result" -eq 2 ]; then
        return
    fi

    port="$SELECTED_PORT"
    remark="$SELECTED_REMARK"

    id=$(calc_id "$port")
    class_id="1:${id}"

    conflict=$(
        awk -F'|' \
            -v dev="$dev" \
            -v port="$port" \
            -v class_id="$class_id" '
                $1==dev && $2!=port && $5==class_id {
                    print $2
                    exit
                }
            ' "$RULES_FILE"
    )

    if [ -n "$conflict" ]; then
        err "端口 $port 与端口 $conflict 的 class ID 冲突"
        return
    fi

    read -rp "请输入上传和下载限速（整数 Mbps）: " mbps

    mbps=$(trim "$mbps")

    valid_mbps "$mbps" || {
        err "速率必须是大于 0 的整数"
        return
    }

    rate="${mbps}mbit"
    existing_rate=$(get_port_rate_from_file "$RULES_FILE" "$dev" "$port")

    if [ -n "$existing_rate" ] &&
        [ "$existing_rate" != "$rate" ]; then

        warn "端口已有规则，TCP/UDP 必须使用相同速率：$existing_rate"
        read -rp "是否使用已有速率？[y/n]: " answer

        [[ "$answer" == "y" || "$answer" == "Y" ]] || return
        rate="$existing_rate"
    fi

    choose_protocol || {
        err "协议选择无效"
        return
    }

    case "$SELECTED_PROTO" in
        tcp)
            protos=(tcp)
            proto_show="tcp"
            ;;
        udp)
            protos=(udp)
            proto_show="udp"
            ;;
        both)
            protos=(tcp udp)
            proto_show="tcp+udp"
            ;;
    esac

    confirm_action \
        "添加双向限速" \
        "$dev" "$port" "$remark" "$proto_show" "$rate" || return

    candidate=$(make_temp_file "$RULES_FILE") || return
    cat "$RULES_FILE" > "$candidate"

    for proto in "${protos[@]}"; do
        if ! rule_exists_in_file \
            "$candidate" "$dev" "$port" "$proto"; then

            echo "${dev}|${port}|${proto}|${rate}|${class_id}|${id}" \
                >> "$candidate"
        fi
    done

    commit_incremental \
        "$candidate" "添加双向限速" "$dev"

    rm -f "$candidate"
}

delete_limit_interactive() {
    local dev
    local port
    local rate
    local mode
    local delete_proto
    local candidate

    choose_existing_rule || return

    dev="$SELECTED_DEV"
    port="$SELECTED_PORT"
    rate="$SELECTED_RATE"

    echo
    echo "1) 删除整个端口的 TCP/UDP 规则"
    echo "2) 仅删除指定协议"
    read -rp "请选择 [1-2]: " mode

    candidate=$(make_temp_file "$RULES_FILE") || return

    case "$mode" in
        1)
            confirm_action \
                "删除双向限速" \
                "$dev" "$port" "-" "$SELECTED_PROTO_SHOW" "$rate" || {
                rm -f "$candidate"
                return
            }

            awk -F'|' \
                -v dev="$dev" \
                -v port="$port" '
                    !($1==dev && $2==port)
                ' "$RULES_FILE" > "$candidate"
            ;;
        2)
            choose_protocol || {
                rm -f "$candidate"
                return
            }

            case "$SELECTED_PROTO" in
                tcp)
                    delete_proto="tcp"
                    ;;
                udp)
                    delete_proto="udp"
                    ;;
                *)
                    err "单协议删除时请选择 TCP 或 UDP"
                    rm -f "$candidate"
                    return
                    ;;
            esac

            confirm_action \
                "删除双向限速" \
                "$dev" "$port" "-" "$delete_proto" "$rate" || {
                rm -f "$candidate"
                return
            }

            awk -F'|' \
                -v dev="$dev" \
                -v port="$port" \
                -v proto="$delete_proto" '
                    !($1==dev && $2==port && $3==proto)
                ' "$RULES_FILE" > "$candidate"
            ;;
        *)
            err "选项无效"
            rm -f "$candidate"
            return
            ;;
    esac

    chmod 600 "$candidate"

    commit_incremental \
        "$candidate" "删除双向限速" "$dev"

    rm -f "$candidate"
}

modify_limit_interactive() {
    local dev
    local port
    local mbps
    local rate
    local candidate

    choose_existing_rule || return

    dev="$SELECTED_DEV"
    port="$SELECTED_PORT"

    read -rp "请输入新的上传和下载限速（整数 Mbps）: " mbps

    mbps=$(trim "$mbps")

    valid_mbps "$mbps" || {
        err "速率必须是大于 0 的整数"
        return
    }

    rate="${mbps}mbit"

    confirm_action \
        "修改双向限速" \
        "$dev" "$port" "-" "$SELECTED_PROTO_SHOW" "$rate" || return

    candidate=$(make_temp_file "$RULES_FILE") || return

    awk -F'|' \
        -v dev="$dev" \
        -v port="$port" \
        -v rate="$rate" '
            BEGIN {
                OFS="|"
            }
            {
                if ($1==dev && $2==port) {
                    $4=rate
                }

                print
            }
        ' "$RULES_FILE" > "$candidate"

    chmod 600 "$candidate"

    commit_incremental \
        "$candidate" "修改双向限速" "$dev"

    rm -f "$candidate"
}

delete_all_interactive() {
    local dev
    local candidate

    choose_interface || return
    dev="$SELECTED_DEV"

    if ! has_rules_for_dev_in_file "$RULES_FILE" "$dev"; then
        warn "网卡 $dev 没有限速规则"
        return
    fi

    confirm_action \
        "清空网卡全部双向限速" \
        "$dev" "-" "-" "-" "-" || return

    candidate=$(make_temp_file "$RULES_FILE") || return

    awk -F'|' \
        -v dev="$dev" '
            $1!=dev
        ' "$RULES_FILE" > "$candidate"

    chmod 600 "$candidate"

    commit_incremental \
        "$candidate" "清空网卡全部双向限速" "$dev"

    rm -f "$candidate"
}

repair_and_cleanup() {
    local normalized
    local root_backup
    local dev
    local answer
    local failed=0

    local -a repair_devs=()

    echo
    warn "此操作会完整重建所有受管理网卡的规则，相关统计会清零。"
    read -rp "确认继续？[y/n]: " answer

    [[ "$answer" == "y" || "$answer" == "Y" ]] || return

    normalized=$(make_temp_file "$RULES_FILE") || return

    if ! normalize_rules_file "$RULES_FILE" "$normalized"; then
        rm -f "$normalized"
        return
    fi

    # 接管确认过程中 approve_root_takeover() 可能修改
    # root-owned.conf，因此先进行事务备份。
    root_backup=$(make_temp_file "$ROOT_OWNED_FILE") || {
        rm -f "$normalized"
        err "创建 root 接管授权备份失败"
        return
    }

    if ! cp -f "$ROOT_OWNED_FILE" "$root_backup"; then
        rm -f "$normalized" "$root_backup"
        err "备份 root 接管授权失败"
        return
    fi

    chmod 600 "$root_backup"

    clear_takeover_approvals

    # 先将受管理网卡完整读入数组。
    # 后面的接管确认将继续从终端读取，不会与网卡列表争用 stdin。
    mapfile -t repair_devs < <(
        {
            awk -F'|' '$1!="" {print $1}' "$RULES_FILE"
            awk -F'|' '$1!="" {print $1}' "$normalized"
            awk -F'|' '$1!="" {print $1}' "$APPLIED_FILE"
            awk -F'|' '$1!="" {print $1}' "$IFB_MAP_FILE"
            cat "$ROOT_OWNED_FILE"
            cat "$INGRESS_OWNED_FILE"
        } |
            sed '/^[[:space:]]*$/d' |
            sort -u
    )

    # 逐张网卡进行交互式接管确认。
    for dev in "${repair_devs[@]}"; do
        [ -z "$dev" ] && continue

        if has_rules_for_dev_in_file "$normalized" "$dev"; then
            if ! approve_root_takeover "$dev"; then
                failed=1
            fi
        fi
    done

    if [ "$failed" -ne 0 ]; then
        # 任意一张网卡拒绝接管时，恢复操作开始前的授权文件。
        if ! cp -f "$root_backup" "$ROOT_OWNED_FILE"; then
            err "恢复 root 接管授权记录失败"
            log_event ERROR "菜单 7 取消后恢复 root-owned.conf 失败"
        else
            chmod 600 "$ROOT_OWNED_FILE"
        fi

        clear_takeover_approvals
        rm -f "$normalized" "$root_backup"

        err "接管授权未完成，已取消修复并恢复原授权记录"
        return
    fi

    if ! mv -f "$normalized" "$RULES_FILE"; then
        cp -f "$root_backup" "$ROOT_OWNED_FILE" 2>/dev/null || true
        chmod 600 "$ROOT_OWNED_FILE" 2>/dev/null || true

        clear_takeover_approvals
        rm -f "$normalized" "$root_backup"

        err "更新 rules.conf 失败，已恢复原授权记录"
        return
    fi

    chmod 600 "$RULES_FILE"

    # 使用同一个数组执行重建，不再重新占用标准输入。
    for dev in "${repair_devs[@]}"; do
        [ -z "$dev" ] && continue

        if full_rebuild_device \
            "$dev" "$RULES_FILE" 0 "$APPLIED_FILE"; then

            if ! update_applied_for_device "$dev" "$RULES_FILE"; then
                warn "网卡规则已重建，但 applied.conf 更新失败：$dev"
                log_event ERROR "修复后更新 applied.conf 失败：$dev"
                failed=1
            fi
        else
            err "重建网卡失败：$dev"
            log_event ERROR "修复时重建网卡失败：$dev"
            failed=1
        fi
    done

    clear_takeover_approvals
    rm -f "$root_backup"

    create_restore_assets_if_enabled

    if [ "$failed" -eq 0 ]; then
        msg "修复和完整重建完成"
    else
        err "部分网卡重建或状态保存失败，请查看日志"
    fi

    show_status_simple
}



generate_test_ifb_name() {
    local attempt
    local candidate

    for attempt in $(seq 1 100); do
        candidate="xlt$(printf '%04x%04x' "$RANDOM" "$RANDOM")"
        candidate="${candidate:0:15}"

        if ! ip link show dev "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

test_ifb_alias_matches() {
    local ifb="$1"
    local expected="$2"

    [ -f "/sys/class/net/${ifb}/ifalias" ] || return 1

    [ "$(cat "/sys/class/net/${ifb}/ifalias" 2>/dev/null)" = "$expected" ]
}

safe_delete_test_ifb() {
    local ifb="$1"
    local expected_alias="$2"

    [ -z "$ifb" ] && return 0
    ip link show dev "$ifb" >/dev/null 2>&1 || return 0

    if ! interface_is_ifb "$ifb"; then
        warn "拒绝删除非 IFB 测试接口：$ifb"
        return 1
    fi

    if ! test_ifb_alias_matches "$ifb" "$expected_alias"; then
        warn "拒绝删除 alias 不匹配的测试接口：$ifb"
        return 1
    fi

    ip link del dev "$ifb" >/dev/null 2>&1
}

run_feature_test() {
    local ok_message="$1"
    local fail_message="$2"
    shift 2

    local output
    local status

    output=$("$@" 2>&1)
    status=$?

    if [ "$status" -eq 0 ]; then
        msg "[OK] $ok_message"
        return 0
    fi

    err "[FAIL] $fail_message"
    [ -n "$output" ] && echo "       $output"

    return 1
}

test_tc_features() {
    local test_a
    local test_b
    local alias_a
    local alias_b
    local failed=0

    test_a=$(generate_test_ifb_name) || {
        err "[FAIL] 无法分配临时 IFB 名称"
        return 1
    }

    test_b=$(generate_test_ifb_name) || {
        err "[FAIL] 无法分配第二个临时 IFB 名称"
        return 1
    }

    while [ "$test_b" = "$test_a" ]; do
        test_b=$(generate_test_ifb_name) || return 1
    done

    alias_a="xui-limit:test-a:$$:$RANDOM"
    alias_b="xui-limit:test-b:$$:$RANDOM"

    modprobe ifb >/dev/null 2>&1 || true
    modprobe sch_htb >/dev/null 2>&1 || true
    modprobe sch_fq_codel >/dev/null 2>&1 || true
    modprobe cls_flower >/dev/null 2>&1 || true
    modprobe act_mirred >/dev/null 2>&1 || true

    run_feature_test \
        "创建临时 IFB A" \
        "无法创建临时 IFB A" \
        ip link add "$test_a" type ifb || return 1

    ip link set dev "$test_a" alias "$alias_a" >/dev/null 2>&1 || {
        ip link del dev "$test_a" >/dev/null 2>&1 || true
        return 1
    }

    if ! run_feature_test \
        "创建临时 IFB B" \
        "无法创建临时 IFB B" \
        ip link add "$test_b" type ifb; then

        safe_delete_test_ifb "$test_a" "$alias_a" || true
        return 1
    fi

    ip link set dev "$test_b" alias "$alias_b" >/dev/null 2>&1 || {
        safe_delete_test_ifb "$test_a" "$alias_a" || true
        ip link del dev "$test_b" >/dev/null 2>&1 || true
        return 1
    }

    ip link set dev "$test_a" up >/dev/null 2>&1
    ip link set dev "$test_b" up >/dev/null 2>&1

    run_feature_test \
        "HTB root qdisc" \
        "HTB root qdisc 不可用" \
        tc qdisc replace dev "$test_a" root \
        handle 1: htb default 0 || failed=1

    run_feature_test \
        "HTB class" \
        "HTB class 不可用" \
        tc class replace dev "$test_a" parent 1: \
        classid 1:10 htb rate 10mbit ceil 10mbit || failed=1

    run_feature_test \
        "fq_codel" \
        "fq_codel 不可用" \
        tc qdisc replace dev "$test_a" \
        parent 1:10 handle 10: fq_codel || failed=1

    run_feature_test \
        "IPv4 flower src_port" \
        "IPv4 flower src_port 不可用" \
        tc filter add dev "$test_a" parent 1: \
        protocol ip pref 60001 flower skip_hw \
        ip_proto tcp src_port 12345 flowid 1:10 || failed=1

    run_feature_test \
        "IPv6 flower src_port" \
        "IPv6 flower src_port 不可用" \
        tc filter add dev "$test_a" parent 1: \
        protocol ipv6 pref 60002 flower skip_hw \
        ip_proto tcp src_port 12345 flowid 1:10 || failed=1

    run_feature_test \
        "ingress qdisc" \
        "ingress qdisc 不可用" \
        tc qdisc add dev "$test_a" handle ffff: ingress || failed=1

    run_feature_test \
        "IPv4 flower + mirred" \
        "IPv4 flower + mirred 不可用" \
        tc filter add dev "$test_a" parent ffff: \
        protocol ip pref 60003 flower skip_hw \
        ip_proto tcp dst_port 12345 \
        action mirred egress redirect dev "$test_b" || failed=1

    run_feature_test \
        "IPv6 flower + mirred" \
        "IPv6 flower + mirred 不可用" \
        tc filter add dev "$test_a" parent ffff: \
        protocol ipv6 pref 60004 flower skip_hw \
        ip_proto tcp dst_port 12345 \
        action mirred egress redirect dev "$test_b" || failed=1

    run_feature_test \
        "IFB 上传 HTB root" \
        "IFB 上传 HTB root 不可用" \
        tc qdisc replace dev "$test_b" root \
        handle 1: htb default 0 || failed=1

    run_feature_test \
        "IFB 上传 HTB class" \
        "IFB 上传 HTB class 不可用" \
        tc class replace dev "$test_b" parent 1: \
        classid 1:10 htb rate 10mbit ceil 10mbit || failed=1

    run_feature_test \
        "IFB 上传 fq_codel" \
        "IFB 上传 fq_codel 不可用" \
        tc qdisc replace dev "$test_b" \
        parent 1:10 handle 10: fq_codel || failed=1

    run_feature_test \
        "IFB IPv4 dst_port 分类" \
        "IFB IPv4 dst_port 分类不可用" \
        tc filter add dev "$test_b" parent 1: \
        protocol ip pref 60005 flower skip_hw \
        ip_proto tcp dst_port 12345 flowid 1:10 || failed=1

    run_feature_test \
        "IFB IPv6 dst_port 分类" \
        "IFB IPv6 dst_port 分类不可用" \
        tc filter add dev "$test_b" parent 1: \
        protocol ipv6 pref 60006 flower skip_hw \
        ip_proto tcp dst_port 12345 flowid 1:10 || failed=1

    safe_delete_test_ifb "$test_a" "$alias_a" || failed=1
    safe_delete_test_ifb "$test_b" "$alias_b" || failed=1

    return "$failed"
}

check_rules_ownership_consistency() {
    local dev
    local ifb
    local failed=0

    echo
    info "rules.conf ↔ root-owned.conf 一致性检查："

    while IFS= read -r dev; do
        [ -z "$dev" ] && continue

        if root_is_owned "$dev"; then
            msg "[OK] $dev：规则与 root 接管授权一致"
        else
            err "[FAIL] $dev 有规则，但未记录 root 接管授权"
            echo "       请执行菜单 7 并确认接管"
            failed=1
        fi

        ifb=$(lookup_ifb_name "$dev")

        if [ -z "$ifb" ]; then
            warn "[WARN] $dev 尚无 IFB 映射"
        elif validate_owned_ifb "$dev" "$ifb"; then
            msg "[OK] $dev → $ifb：IFB 正常"
        else
            warn "[WARN] $dev → $ifb：IFB 当前不存在或所属校验失败"
        fi
    done < <(
        awk -F'|' '
            $1!="" && !seen[$1]++ {
                print $1
            }
        ' "$RULES_FILE"
    )

    while IFS= read -r dev; do
        [ -z "$dev" ] && continue

        if ! has_rules_for_dev_in_file "$RULES_FILE" "$dev"; then
            warn "[WARN] $dev 已授权接管，但 rules.conf 中已无规则"
        fi
    done < "$ROOT_OWNED_FILE"

    return "$failed"
}

environment_check() {
    echo
    info "================ 环境检查 ================"

    command -v ip >/dev/null 2>&1 &&
        msg "[OK] ip 可用" ||
        err "[FAIL] ip 不可用"

    command -v tc >/dev/null 2>&1 &&
        msg "[OK] tc 可用" ||
        err "[FAIL] tc 不可用"

    command -v modprobe >/dev/null 2>&1 &&
        msg "[OK] modprobe 可用" ||
        err "[FAIL] modprobe 不可用"

    command -v sqlite3 >/dev/null 2>&1 &&
        msg "[OK] sqlite3 可用" ||
        warn "[WARN] sqlite3 不可用"

    command -v column >/dev/null 2>&1 &&
        msg "[OK] column 可用" ||
        warn "[WARN] column 不可用，仅影响表格"

    if detect_xui_db; then
        msg "[OK] x-ui.db：$XUI_DB_PATH"
    else
        warn "[WARN] 未找到 x-ui.db"
    fi

    if systemctl is-enabled xui-limit.service >/dev/null 2>&1; then
        msg "[OK] 开机自动恢复已启用"
    else
        warn "[WARN] 开机自动恢复未启用"
    fi

    check_rules_ownership_consistency || true

    echo
    info "正在执行安全的临时 IFB/tc 完整测试..."

    if test_tc_features; then
        msg "[OK] 双向限速内核功能测试全部通过"
    else
        err "[FAIL] 部分内核功能测试失败"
    fi
}

create_restore_assets() {
    local current_script

    current_script=$(readlink -f "$0" 2>/dev/null || echo "$0")

    mkdir -p "$(dirname "$INSTALLED_SCRIPT")"
    chmod 700 "$(dirname "$INSTALLED_SCRIPT")"

    if [ "$current_script" != "$INSTALLED_SCRIPT" ]; then
        install -m 700 \
            "$current_script" "$INSTALLED_SCRIPT" || {
            err "安装固定路径脚本失败"
            return 1
        }
    else
        chmod 700 "$INSTALLED_SCRIPT"
    fi

    cat > "$RESTORE_SCRIPT" <<RESTORE_EOF
#!/bin/bash
exec "$INSTALLED_SCRIPT" --restore
RESTORE_EOF

    chmod 700 "$RESTORE_SCRIPT"

    cat > "$SERVICE_FILE" <<SERVICE_EOF
[Unit]
Description=Restore xui-limit bidirectional traffic shaping
After=systemd-sysctl.service network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=12

[Service]
Type=oneshot
ExecStart=$RESTORE_SCRIPT
RemainAfterExit=yes
Restart=on-failure
RestartSec=10
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    chmod 644 "$SERVICE_FILE"
    systemctl daemon-reload
}

create_restore_assets_if_enabled() {
    if systemctl is-enabled xui-limit.service >/dev/null 2>&1; then
        create_restore_assets >/dev/null 2>&1 || true
    fi
}

enable_autostart() {
    create_restore_assets || return 1

    systemctl enable xui-limit.service >/dev/null 2>&1 || {
        err "启用 systemd 服务失败"
        return 1
    }

    systemctl reset-failed xui-limit.service >/dev/null 2>&1 || true

    if systemctl restart xui-limit.service; then
        msg "开机自动恢复已启用"
    else
        err "服务启动失败，请查看："
        echo "journalctl -u xui-limit.service -n 100 --no-pager"
    fi
}

disable_autostart() {
    systemctl disable --now xui-limit.service \
        >/dev/null 2>&1 || true

    systemctl reset-failed xui-limit.service \
        >/dev/null 2>&1 || true

    rm -f "$SERVICE_FILE" "$RESTORE_SCRIPT"

    systemctl daemon-reload
    msg "开机自动恢复已关闭"
}

autostart_menu() {
    local choice

    echo
    echo "1) 启用开机自动恢复"
    echo "2) 关闭开机自动恢复"
    read -rp "请选择 [1-2]: " choice

    case "$choice" in
        1)
            enable_autostart
            ;;
        2)
            disable_autostart
            ;;
        *)
            err "选项无效"
            ;;
    esac
}

show_logs() {
    echo
    info "================ 最近运行日志 ================"

    if [ -s "$LOG_FILE" ]; then
        tail -n 100 "$LOG_FILE"
    else
        warn "暂无日志"
    fi

    echo
    echo "systemd 日志："
    echo "journalctl -u xui-limit.service -n 100 --no-pager"
}

refresh_service_files_if_enabled() {
    if systemctl is-enabled xui-limit.service >/dev/null 2>&1; then
        create_restore_assets >/dev/null 2>&1 || true
    fi
}

restore_main() {
    local normalized

    clear_takeover_approvals
    log_event INFO "开始执行开机规则恢复"

    normalized=$(make_temp_file "$RULES_FILE") || {
        log_event ERROR "创建规则临时文件失败"
        return 1
    }

    if ! normalize_rules_file "$RULES_FILE" "$normalized"; then
        rm -f "$normalized"
        log_event ERROR "rules.conf 校验失败"
        return 1
    fi

    mv -f "$normalized" "$RULES_FILE"
    chmod 600 "$RULES_FILE"

    if restore_all_devices_independently 120; then
        log_event INFO "开机双向限速规则恢复成功"
        return 0
    fi

    log_event ERROR "开机双向限速规则部分或全部恢复失败"
    return 1
}

main_menu() {
    local choice

    while true; do
        echo
        info "================ x-ui 节点双向限速管理 ================"
        echo "1) 安装依赖"
        echo "2) 添加节点双向限速"
        echo "3) 查看当前双向限速状态"
        echo "4) 删除节点双向限速"
        echo "5) 修改节点双向限速"
        echo "6) 清空某网卡全部双向限速"
        echo "7) 修复/清理并完整重建规则"
        echo "8) 开机自启设置"
        echo "9) 环境检查"
        echo "10) 查看最近运行日志"
        echo "0) 退出"
        echo "======================================================="

        read -rp "请输入选项: " choice

        case "$choice" in
            1)
                install_deps
                pause_enter
                ;;
            2)
                add_limit_interactive
                pause_enter
                ;;
            3)
                show_status
                pause_enter
                ;;
            4)
                delete_limit_interactive
                pause_enter
                ;;
            5)
                modify_limit_interactive
                pause_enter
                ;;
            6)
                delete_all_interactive
                pause_enter
                ;;
            7)
                repair_and_cleanup
                pause_enter
                ;;
            8)
                autostart_menu
                pause_enter
                ;;
            9)
                environment_check
                pause_enter
                ;;
            10)
                show_logs
                pause_enter
                ;;
            0)
                exit 0
                ;;
            *)
                err "无效选项"
                ;;
        esac
    done
}

check_root

case "${1:-}" in
    --restore)
        RESTORE_MODE=1
        restore_main
        exit $?
        ;;
esac

refresh_service_files_if_enabled
main_menu
