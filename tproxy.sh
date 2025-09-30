#!/system/bin/sh
# =====================================================================
# 🔥 tproxy.sh - 透明代理 iptables 规则管理脚本
# ---------------------------------------------------------------------
# - 支持 IPv4/IPv6、TPROXY、策略路由
# - 增强：LAN 噪声提前放行、回环显式放行、自吃保护(含 UDP)、更稳的白名单
# - 兼容：Clash/Mihomo/Hysteria DNS 模式
# =====================================================================

set -e

MODDIR=$(dirname "$0")
. "$MODDIR/common.sh"

# --- 全局默认变量 ------------------------------------------------------------
MARK_ID=${MARK_ID:-"16777216/16777216"}
TABLE_ID=${TABLE_ID:-"2024"}
CHAIN_NAME=${CHAIN_NAME:-"FIREFLY"}
CHAIN_PRE=${CHAIN_PRE:-"${CHAIN_NAME}_PRE"}
CHAIN_OUT=${CHAIN_OUT:-"${CHAIN_NAME}_OUT"}

INTRANET=${INTRANET:-"0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32"}
INTRANET6=${INTRANET6:-"::/128 ::1/128 ::ffff:0:0/96 fc00::/7 fe80::/10 ff00::/8 64:ff9b::/96 2001:db8::/32"}

IFACES_LIST="${IFACES_LIST:-"wlan+ ap+ rndis+ usb+"}"
IGNORE_LIST="${IGNORE_LIST:-""}"

TPROXY_USER=${TPROXY_USER:-"root:net_admin"}

FAIR4=${FAIR4:-"198.18.0.0/15"}
FAIR6=${FAIR6:-"fc00::/18"}
TPROXY_PORT=${TPROXY_PORT:-"1536"}
IPV6_SUPPORT=${IPV6_SUPPORT:-0}
if [ "$(read_setting "IPV6" "0")" = "1" ] && ip -6 route show >/dev/null 2>&1; then
  IPV6_SUPPORT=1
fi
CLASH_DNS_PORT=${CLASH_DNS_PORT:-"1053"}

log_safe "❤️ === [tproxy] ==="

read -r USER_ID GROUP_ID <<EOF
$(resolve_user_group "$TPROXY_USER")
EOF

# --- 参数探测：FakeIP 网段、TProxy 端口 --------------------------------------
detect_tproxy_params() {
  if [ -f "$BIN_CONF" ]; then
    fair4="$(grep -m1 '"inet4_range"' "$BIN_CONF" | cut -d'"' -f4 || true)"
    fair6="$(grep -m1 '"inet6_range"' "$BIN_CONF" | cut -d'"' -f4 || true)"
    t_port="$(grep -A 5 '"type": "tproxy"' "$BIN_CONF" | grep -m1 '"listen_port"' | grep -o '[0-9]\+' || true)"
  fi
  if [ -n "$fair4" ]; then
    log_safe "🕹️ 检测到 FakeIP 网段: $fair4"
    FAIR4="$fair4"
  fi
  if [ -n "$fair6" ]; then
    log_safe "🕹️ 检测到 FakeIP 网段: $fair6"
    FAIR6="$fair6"
  fi
  if [ -n "$t_port" ]; then
    log_safe "🕹️ 检测到 TProxy 端口: $t_port"
    TPROXY_PORT="$t_port"
  fi
}

# --- 策略路由设置/清理 (TPROXY 所需) -----------------------------------------
setup_routes() {
  log_safe "🗺️ 正在设置策略路由..."
  sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
  ip route add local default dev lo table "$TABLE_ID" 2>/dev/null || true
  # 删除可能存在的同名规则，避免重复添加
  ip rule  del fwmark "$MARK_ID" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
  ip rule  add fwmark "$MARK_ID" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
  if [ "$IPV6_SUPPORT" = "1" ]; then
    sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
    ip -6 route add local default dev lo table "$TABLE_ID" 2>/dev/null || true
    ip -6 rule  del fwmark "$MARK_ID" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
    ip -6 rule  add fwmark "$MARK_ID" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
  fi
}

unset_routes() {
  log_safe "🗺️ 正在清除策略路由..."
  ip rule  del fwmark "$MARK_ID" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
  ip route flush table "$TABLE_ID" 2>/dev/null || true
  if [ "$IPV6_SUPPORT" = "1" ]; then
    ip -6 rule  del fwmark "$MARK_ID" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
    ip -6 route flush table "$TABLE_ID" 2>/dev/null || true
  fi
}

# --- 应用级分流规则（保持你原逻辑） -------------------------------------------
add_app_rules() {
  ip_cmd="${1:-iptables}"

  if ! command -v dumpsys >/dev/null 2>&1; then
    log_safe "❗ dumpsys 不可用, 回退全局代理模式..."
    add_global_proxy_rules "$ip_cmd"
    return
  fi

  case "$PROXY_MODE" in
    whitelist)
      log_safe "📱 应用白名单代理模式..."
      add_whitelist_rules "$ip_cmd"
      ;;
    blacklist)
      log_safe "📱 应用黑名单代理模式..."
      add_blacklist_rules "$ip_cmd"
      ;;
    *)
      log_safe "🔥 应用全局代理模式..."
      add_global_proxy_rules "$ip_cmd"
      ;;
  esac
}

add_global_proxy_rules() {
  ip_cmd="${1:-iptables}"
  $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p tcp -j MARK --set-xmark "$MARK_ID"
  $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p udp -j MARK --set-xmark "$MARK_ID"
}

add_blacklist_rules() {
  ip_cmd="${1:-iptables}"
  if [ -n "$APP_PACKAGES" ]; then
    for app_pkg in $APP_PACKAGES; do
      uid=$(dumpsys package "$app_pkg" 2>/dev/null | grep 'userId=' | cut -d'=' -f2)
      if [ -n "$uid" ]; then
        log_safe "⚫ 应用 '$app_pkg' ($uid) 已加入黑名单"
        $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -m owner --uid-owner "$uid" -j RETURN
      else
        log_safe "❗ 应用 '$app_pkg' UID 解析失败"
      fi
    done
  fi
  add_global_proxy_rules "$ip_cmd"
}

add_whitelist_rules() {
  ip_cmd="${1:-iptables}"
  if [ -z "$APP_PACKAGES" ]; then
    log_safe "❗ 白名单为空, 除 DNS 外本机流量将不经代理"
    return
  fi
  for app_pkg in $APP_PACKAGES; do
    uid=$(dumpsys package "$app_pkg" 2>/dev/null | grep 'userId=' | cut -d'=' -f2)
    if [ -n "$uid" ]; then
      log_safe "⚪ 应用 '$app_pkg' ($uid) 已加入白名单"
      $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner "$uid" -j MARK --set-xmark "$MARK_ID"
      $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p udp -m owner --uid-owner "$uid" -j MARK --set-xmark "$MARK_ID"
    else
      log_safe "❗ 应用 '$app_pkg' UID 解析失败"
    fi
  done
  # 系统关键 UID 可按需补充（示例保留）
  $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner 0    -j MARK --set-xmark "$MARK_ID"
  $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p udp -m owner --uid-owner 0    -j MARK --set-xmark "$MARK_ID"
  $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner 1052 -j MARK --set-xmark "$MARK_ID"
  $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p udp -m owner --uid-owner 1052 -j MARK --set-xmark "$MARK_ID"
}

# --- TProxy 规则主体 ----------------------------------------------------------
add_tproxy_rules() {
  ip_cmd="${1:-iptables}"

  if [ "$ip_cmd" = "iptables" ]; then
    fire="$FAIR4"; local_ip="127.0.0.1"; lan_ips="$INTRANET"
  else
    fire="$FAIR6"; local_ip="::1";       lan_ips="$INTRANET6"
  fi

  log_safe "🎫 正在添加 $ip_cmd 规则..."

  log_safe "🔗 创建自定义 PREROUTING 链..."
  $ip_cmd -w 100 -t mangle -N "$CHAIN_PRE" 2>/dev/null || true
  $ip_cmd -w 100 -t mangle -F "$CHAIN_PRE" 2>/dev/null || true

  if [ "$BIN_NAME" = "mihomo" ] || [ "$BIN_NAME" = "hysteria" ] || [ "$BIN_NAME" = "clash" ]; then
    log_safe "🚦 $CHAIN_PRE 放行 53 端口(DNS)..."
    $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p tcp --dport 53 -j RETURN
    $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p udp --dport 53 -j RETURN
  else
    log_safe "🚥 $CHAIN_PRE 重定向 53 端口(DNS)..."
    $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p tcp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_ID"
    $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p udp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_ID"
  fi

  log_safe "🔌 $CHAIN_PRE 标记透明代理接管..."
  $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p tcp -m socket --transparent -j MARK --set-xmark "$MARK_ID"
  $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p udp -m socket --transparent -j MARK --set-xmark "$MARK_ID"
  $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -m socket -j RETURN

  for ip in $lan_ips; do
    log_safe "🚦 $CHAIN_PRE 放行内网($ip)..."
    $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -d "$ip" -j RETURN
  done

  $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p tcp -i lo -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_ID"
  $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p udp -i lo -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_ID"

  if [ -n "$IFACES_LIST" ]; then
    for iface in $IFACES_LIST; do
      log_safe "📡 $CHAIN_PRE 重定向来宾接口($iface)..."
      $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p tcp -i "$iface" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_ID"
      $ip_cmd -w 100 -t mangle -A "$CHAIN_PRE" -p udp -i "$iface" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_ID"
    done
  fi

  log_safe "🏁 $CHAIN_PRE 应用至 PREROUTING..."
  $ip_cmd -w 100 -t mangle -C PREROUTING -j "$CHAIN_PRE" 2>/dev/null || \
  $ip_cmd -w 100 -t mangle -I PREROUTING -j "$CHAIN_PRE"

  log_safe "🔗 创建自定义 OUTPUT 链..."
  $ip_cmd -w 100 -t mangle -N "$CHAIN_OUT" 2>/dev/null || true
  $ip_cmd -w 100 -t mangle -F "$CHAIN_OUT" 2>/dev/null || true

  log_safe "👤 $CHAIN_OUT 放行 $TPROXY_USER($USER_ID:$GROUP_ID)..."
  $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -j RETURN

  if [ -n "$IGNORE_LIST" ]; then
    for ignore in $IGNORE_LIST; do
      log_safe "🙈 $CHAIN_OUT 放行忽略列表接口($ignore)..."
      $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -o "$ignore" -j RETURN
    done
  fi

  if [ "$BIN_NAME" = "mihomo" ] || [ "$BIN_NAME" = "hysteria" ] || [ "$BIN_NAME" = "clash" ]; then
    log_safe "🚦 $CHAIN_OUT 放行 53 端口(DNS)..."
    $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p tcp --dport 53 -j RETURN
    $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p udp --dport 53 -j RETURN
  else
    log_safe "🚥 $CHAIN_OUT 重定向 53 端口(DNS)..."
    $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p tcp --dport 53 -j MARK --set-xmark "$MARK_ID"
    $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -p udp --dport 53 -j MARK --set-xmark "$MARK_ID"
  fi

  for ip in $lan_ips; do
    log_safe "🚦 $CHAIN_OUT 放行内网($ip)..."
    $ip_cmd -w 100 -t mangle -A "$CHAIN_OUT" -d "$ip" -j RETURN
  done

  add_app_rules "$ip_cmd"

  # 挂接到 OUTPUT
  log_safe "🏁 $CHAIN_OUT 应用至 OUTPUT..."
  $ip_cmd -w 100 -t mangle -C OUTPUT -j "$CHAIN_OUT" 2>/dev/null || \
  $ip_cmd -w 100 -t mangle -I OUTPUT -j "$CHAIN_OUT"

  # [OPT] 自吃保护(含 UDP)：阻止本地服务访问 TPROXY 端口，防环
  log_safe "🛡️ 阻止本地服务访问 tproxy 端口..."
  $ip_cmd -w 100 -C OUTPUT -d "$local_ip" -p tcp -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -m tcp --dport "$TPROXY_PORT" -j REJECT 2>/dev/null || \
  $ip_cmd -w 100 -A OUTPUT -d "$local_ip" -p tcp -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -m tcp --dport "$TPROXY_PORT" -j REJECT
  $ip_cmd -w 100 -C OUTPUT -d "$local_ip" -p udp -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -m udp --dport "$TPROXY_PORT" -j REJECT 2>/dev/null || \
  $ip_cmd -w 100 -A OUTPUT -d "$local_ip" -p udp -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -m udp --dport "$TPROXY_PORT" -j REJECT

  # Clash 全局 DNS 模式（仅当 nat 可用）
  if $ip_cmd -t nat -nL >/dev/null 2>&1; then
    if [ "$BIN_NAME" = "mihomo" ] || [ "$BIN_NAME" = "hysteria" ] || [ "$BIN_NAME" = "clash" ]; then
      log_safe "🚀 开启全局 DNS 模式..."
      $ip_cmd -w 100 -t nat -N CLASH_DNS_PRE 2>/dev/null || true
      $ip_cmd -w 100 -t nat -F CLASH_DNS_PRE 2>/dev/null || true
      $ip_cmd -w 100 -t nat -A CLASH_DNS_PRE -p udp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      $ip_cmd -w 100 -t nat -C PREROUTING -j CLASH_DNS_PRE 2>/dev/null || \
      $ip_cmd -w 100 -t nat -I PREROUTING -j CLASH_DNS_PRE

      $ip_cmd -w 100 -t nat -N CLASH_DNS_OUT 2>/dev/null || true
      $ip_cmd -w 100 -t nat -F CLASH_DNS_OUT 2>/dev/null || true
      $ip_cmd -w 100 -t nat -A CLASH_DNS_OUT -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -j RETURN
      $ip_cmd -w 100 -t nat -A CLASH_DNS_OUT -p udp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      $ip_cmd -w 100 -t nat -C OUTPUT -j CLASH_DNS_OUT 2>/dev/null || \
      $ip_cmd -w 100 -t nat -I OUTPUT -j CLASH_DNS_OUT
    fi
    # FakeIP 的 ICMP 修复（与原版一致）
    if [ -n "$fire" ]; then
      log_safe "👻 修复 FakeIP($fire) ICMP..."
      $ip_cmd -w 100 -t nat -A OUTPUT     -d "$fire" -p icmp -j DNAT --to-destination "$local_ip" 2>/dev/null || true
      $ip_cmd -w 100 -t nat -A PREROUTING -d "$fire" -p icmp -j DNAT --to-destination "$local_ip" 2>/dev/null || true
    fi
  else
    log_safe "❗ $ip_cmd 不支持 NAT 表, 已跳过"
  fi
}

# --- 删除规则 ----------------------------------------------------------------
remove_tproxy_rules() {
  ip_cmd="${1:-iptables}"

  if [ "$ip_cmd" = "iptables" ]; then
    fire="$FAIR4"; local_ip="127.0.0.1"
  else
    fire="$FAIR6"; local_ip="::1"
  fi

  log_safe "🧹 正在删除 $ip_cmd 规则..."
  $ip_cmd -w 100 -t mangle -D OUTPUT     -j "$CHAIN_OUT" 2>/dev/null || true
  $ip_cmd -w 100 -t mangle -D PREROUTING -j "$CHAIN_PRE" 2>/dev/null || true

  $ip_cmd -w 100 -t mangle -F "$CHAIN_OUT" 2>/dev/null || true
  $ip_cmd -w 100 -t mangle -X "$CHAIN_OUT" 2>/dev/null || true
  $ip_cmd -w 100 -t mangle -F "$CHAIN_PRE" 2>/dev/null || true
  $ip_cmd -w 100 -t mangle -X "$CHAIN_PRE" 2>/dev/null || true

  $ip_cmd -w 100 -D OUTPUT -d "$local_ip" -p tcp -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -m tcp --dport "$TPROXY_PORT" -j REJECT 2>/dev/null || true
  $ip_cmd -w 100 -D OUTPUT -d "$local_ip" -p udp -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -m udp --dport "$TPROXY_PORT" -j REJECT 2>/dev/null || true

  if $ip_cmd -t nat -nL >/dev/null 2>&1; then
    if [ "$BIN_NAME" = "mihomo" ] || [ "$BIN_NAME" = "hysteria" ] || [ "$BIN_NAME" = "clash" ]; then
      $ip_cmd -w 100 -t nat -D OUTPUT     -j CLASH_DNS_OUT 2>/dev/null || true
      $ip_cmd -w 100 -t nat -D PREROUTING -j CLASH_DNS_PRE 2>/dev/null || true
      $ip_cmd -w 100 -t nat -F CLASH_DNS_OUT 2>/dev/null || true
      $ip_cmd -w 100 -t nat -X CLASH_DNS_OUT 2>/dev/null || true
      $ip_cmd -w 100 -t nat -F CLASH_DNS_PRE 2>/dev/null || true
      $ip_cmd -w 100 -t nat -X CLASH_DNS_PRE 2>/dev/null || true
    fi
    if [ -n "$fire" ]; then
      $ip_cmd -w 100 -t nat -D OUTPUT     -d "$fire" -p icmp -j DNAT --to-destination "$local_ip" 2>/dev/null || true
      $ip_cmd -w 100 -t nat -D PREROUTING -d "$fire" -p icmp -j DNAT --to-destination "$local_ip" 2>/dev/null || true
    fi
  fi
}

detect_tproxy_params

case "$1" in
  stop)
    log_safe "🛑 清除防火墙规则中..."
    remove_tproxy_rules iptables
    if [ "$IPV6_SUPPORT" = "1" ]; then
      remove_tproxy_rules ip6tables
    fi
    unset_routes
    log_safe "✅ 防火墙规则已清除"
    ;;
  *)
    log_safe "🚀 防火墙规则应用中..."
    setup_routes
    add_tproxy_rules iptables
    if [ "$IPV6_SUPPORT" = "1" ]; then
      add_tproxy_rules ip6tables
    fi
    log_safe "✅ 防火墙规则已应用"
    ;;
esac

exit 0