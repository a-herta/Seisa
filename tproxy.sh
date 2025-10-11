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

# --- Defaults ---------------------------------------------------------------
MARK_HEX=${MARK_HEX:-"0x1/0x1"}
TABLE_ID=${TABLE_ID:-"100"}

CHAIN_NAME=${CHAIN_NAME:-"FIREFLY"}
CHAIN_PRE=${CHAIN_PRE:-"${CHAIN_NAME}_PRE"}
CHAIN_OUT=${CHAIN_OUT:-"${CHAIN_NAME}_OUT"}

INTRANET4=${INTRANET4:-"0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32"}
INTRANET6=${INTRANET6:-"::/128 ::1/128 ::ffff:0:0/96 fe80::/10 ff00::/8 64:ff9b::/96 2001:db8::/32"}

# OUTPUT 忽略的 egress 接口
IGNORE_LIST="${IGNORE_LIST:-""}"

TPROXY_USER=${TPROXY_USER:-"root:net_admin"}

FAIR4=${FAIR4:-"198.18.0.0/15"}
FAIR6=${FAIR6:-"fc00::/18"}

TPROXY_PORT=${TPROXY_PORT:-"1536"}
CLASH_DNS_PORT=${CLASH_DNS_PORT:-"1053"}

IPV6_SUPPORT=${IPV6_SUPPORT:-0}
if [ "$(read_setting "IPV6" "0")" = "1" ] && ip -6 route show >/dev/null 2>&1; then
  IPV6_SUPPORT=1
fi

log_safe "❤️ === [tproxy] ==="

read -r USER_ID GROUP_ID <<EOF
$(resolve_user_group "$TPROXY_USER")
EOF

# --- 参数探测：FakeIP 网段、TProxy 端口 --------------------------------------
detect_tproxy_params() {
  if [ -f "$BIN_CONF" ]; then
    fair4="$(grep -m1 '"inet4_range"' "$BIN_CONF" | cut -d'"' -f4 || true)"
    fair6="$(grep -m1 '"inet6_range"' "$BIN_CONF" | cut -d'"' -f4 || true)"
    t_port="$(grep -A 3 '"type": "tproxy"' "$BIN_CONF" | grep -m1 '"listen_port"' | tr -cd '0-9' || true)"
  fi

  [ -n "$fair4" ] && FAIR4="$fair4" && log_safe "🕹️ FakeIP v4: $FAIR4"
  [ -n "$fair6" ] && FAIR6="$fair6" && log_safe "🕹️ FakeIP v6: $FAIR6"
  [ -n "$t_port" ] && TPROXY_PORT="$t_port" && log_safe "🕹️ TProxy port: $TPROXY_PORT"
}

detect_tproxy_params

# Helper: add rule if not exist
add_rule() {
  # $@ is full rule after iptables/ip6tables
  "$@" 2>/dev/null || true
}

ensure_hook() {
  # $1=ip_cmd, $2=table, $3=hook, $4=jump-chain
  ip_cmd="$1" table="$2" hook="$3" jump="$4"
  $ip_cmd -w 100 -t "$table" -C "$hook" -j "$jump" 2>/dev/null || \
  $ip_cmd -w 100 -t "$table" -I "$hook" -j "$jump"
}

# --- Policy routing ---------------------------------------------------------
setup_routes() {
  log_safe "🗺️ 设置策略路由..."
  sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
  sysctl -w net.ipv4.conf.all.rp_filter=2  >/dev/null 2>&1 || true
  ip rule  del fwmark "$MARK_HEX" lookup "$TABLE_ID" 2>/dev/null || true
  ip rule  add fwmark "$MARK_HEX" lookup "$TABLE_ID"
  ip route add local 0.0.0.0/0 dev lo table "$TABLE_ID" 2>/dev/null || true

  if [ "$IPV6_SUPPORT" = "1" ]; then
    sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
    ip -6 rule  del fwmark "$MARK_HEX" lookup "$TABLE_ID" 2>/dev/null || true
    ip -6 rule  add fwmark "$MARK_HEX" lookup "$TABLE_ID"
    ip -6 route add local ::/0 dev lo table "$TABLE_ID" 2>/dev/null || true
  fi
}

unset_routes() {
  log_safe "🗺️ 清除策略路由..."
  ip rule  del fwmark "$MARK_HEX" lookup "$TABLE_ID" 2>/dev/null || true
  ip route flush table "$TABLE_ID" 2>/dev/null || true
  if [ "$IPV6_SUPPORT" = "1" ]; then
    ip -6 rule  del fwmark "$MARK_HEX" lookup "$TABLE_ID" 2>/dev/null || true
    ip -6 route flush table "$TABLE_ID" 2>/dev/null || true
  fi
}

# --- App split rules --------------------------------------------------------
add_global_proxy_rules() {
  ip_cmd="${1:-iptables}"
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p tcp -j MARK --set-xmark "$MARK_HEX"
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p udp -j MARK --set-xmark "$MARK_HEX"
}

add_blacklist_rules() {
  ip_cmd="${1:-iptables}"
  if [ -n "$APP_PACKAGES" ]; then
    for app_pkg in $APP_PACKAGES; do
      uid=$(dumpsys package "$app_pkg" 2>/dev/null | grep 'userId=' | cut -d'=' -f2)
      if [ -n "$uid" ]; then
        log_safe "⚫ 黑名单放行: $app_pkg ($uid)"
        add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -m owner --uid-owner "$uid" -j RETURN
      fi
    done
  fi
  add_global_proxy_rules "$ip_cmd"
}

add_whitelist_rules() {
  ip_cmd="${1:-iptables}"
  if [ -z "$APP_PACKAGES" ]; then
    log_safe "❗ 白名单为空, 除 DNS 外本机流量不代理"
    return
  fi
  for app_pkg in $APP_PACKAGES; do
    uid=$(dumpsys package "$app_pkg" 2>/dev/null | grep 'userId=' | cut -d'=' -f2)
    if [ -n "$uid" ]; then
      log_safe "⚪ 白名单代理: $app_pkg ($uid)"
      add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner "$uid" -j MARK --set-xmark "$MARK_HEX"
      add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p udp -m owner --uid-owner "$uid" -j MARK --set-xmark "$MARK_HEX"
    fi
  done
  # 必要系统 UID, 可按需保留
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner 0    -j MARK --set-xmark "$MARK_HEX"
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p udp -m owner --uid-owner 0    -j MARK --set-xmark "$MARK_HEX"
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner 1052 -j MARK --set-xmark "$MARK_HEX"
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p udp -m owner --uid-owner 1052 -j MARK --set-xmark "$MARK_HEX"
}

add_app_rules() {
  ip_cmd="${1:-iptables}"
  if ! command -v dumpsys >/dev/null 2>&1; then
    log_safe "❗ dumpsys 不可用, 回退全局模式"
    add_global_proxy_rules "$ip_cmd"
    return
  fi
  case "$PROXY_MODE" in
    whitelist) add_whitelist_rules "$ip_cmd" ;;
    blacklist) add_blacklist_rules "$ip_cmd" ;;
    *)         add_global_proxy_rules "$ip_cmd" ;;
  esac
}

# --- TPROXY main ------------------------------------------------------------
add_tproxy_rules() {
  ip_cmd="${1:-iptables}"

  if [ "$ip_cmd" = "iptables" ]; then
    local_ip="127.0.0.1"; lan_ips="$INTRANET4"; fire="$FAIR4"; proto_icmp="icmp"
  else
    local_ip="::1";       lan_ips="$INTRANET6"; fire="$FAIR6"; proto_icmp="icmpv6"
  fi

  log_safe "🎫 添加 $ip_cmd 规则..."

  # Create/flush chains
  add_rule "$ip_cmd" -w 100 -t mangle -N DIVERT
  add_rule "$ip_cmd" -w 100 -t mangle -F DIVERT
  add_rule "$ip_cmd" -w 100 -t mangle -N "$CHAIN_PRE"
  add_rule "$ip_cmd" -w 100 -t mangle -F "$CHAIN_PRE"
  add_rule "$ip_cmd" -w 100 -t mangle -N "$CHAIN_OUT"
  add_rule "$ip_cmd" -w 100 -t mangle -F "$CHAIN_OUT"

  add_rule "$ip_cmd" -w 100 -t mangle -A DIVERT -j MARK --set-xmark "$MARK_HEX"
  add_rule "$ip_cmd" -w 100 -t mangle -A DIVERT -j ACCEPT

  # Bypass intranet/reserved ranges
  for ip in $lan_ips; do
    add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -d "$ip" -j RETURN
  done

  # Global mode: catch-all TPROXY after bypass/socket rules
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -p tcp -j TPROXY --on-ip "$local_ip" --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -p udp -j TPROXY --on-ip "$local_ip" --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"

  # Hook PREROUTING -> CHAIN_PRE
  ensure_hook "$ip_cmd" mangle PREROUTING "$CHAIN_PRE"

  add_rule "$ip_cmd" -w 100 -t mangle -I PREROUTING 1 -p tcp -m socket --transparent -j DIVERT

  # OUTPUT chain: bypass proxy user
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" --suppl-groups -j RETURN

  # OUTPUT: ignore specific egress interfaces
  if [ -n "$IGNORE_LIST" ]; then
    for ignore in $IGNORE_LIST; do
      add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -o "$ignore" -j RETURN
    done
  fi

  # OUTPUT: bypass intranet
  for ip in $lan_ips; do
    add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -d "$ip" -j RETURN
  done

  # OUTPUT: app split
  add_app_rules "$ip_cmd"

  # DNS: sing-box => mangle/TPROXY; clash/mihomo/hysteria => nat/REDIRECT
  case $BIN_NAME in
  clash|mihomo|hysteria)
    log_safe "🚦 DNS 走 nat 重定向到 $CLASH_DNS_PORT"
    if $ip_cmd -t nat -nL >/dev/null 2>&1; then
      add_rule "$ip_cmd" -w 100 -t nat -N CLASH_DNS_PRE
      add_rule "$ip_cmd" -w 100 -t nat -F CLASH_DNS_PRE
      add_rule "$ip_cmd" -w 100 -t nat -A CLASH_DNS_PRE -p tcp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      add_rule "$ip_cmd" -w 100 -t nat -A CLASH_DNS_PRE -p udp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      ensure_hook "$ip_cmd" nat PREROUTING CLASH_DNS_PRE

      add_rule "$ip_cmd" -w 100 -t nat -N CLASH_DNS_OUT
      add_rule "$ip_cmd" -w 100 -t nat -F CLASH_DNS_OUT
      add_rule "$ip_cmd" -w 100 -t nat -A CLASH_DNS_OUT -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" --suppl-groups -j RETURN
      add_rule "$ip_cmd" -w 100 -t nat -A CLASH_DNS_OUT -p tcp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      add_rule "$ip_cmd" -w 100 -t nat -A CLASH_DNS_OUT -p udp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      ensure_hook "$ip_cmd" nat OUTPUT CLASH_DNS_OUT
    else
      log_safe "❗ $ip_cmd 不支持 nat 表, 跳过 DNS REDIRECT"
    fi
    ;;
  esac

  # OUTPUT: hook
  ensure_hook "$ip_cmd" mangle OUTPUT "$CHAIN_OUT"

  # Self-protection: block local service hitting tproxy port (TCP+UDP)
  log_safe "🛡️ 阻止本地服务访问 tproxy 端口 $TPROXY_PORT"
  add_rule "$ip_cmd" -w 100 -A OUTPUT -d "$local_ip" -p tcp --dport "$TPROXY_PORT" -j REJECT
  add_rule "$ip_cmd" -w 100 -A OUTPUT -d "$local_ip" -p udp --dport "$TPROXY_PORT" -j REJECT

  # FakeIP ICMP fix (if nat available)
  if $ip_cmd -t nat -nL >/dev/null 2>&1 && [ -n "$fire" ]; then
    log_safe "👻 修复 FakeIP($fire) ICMP"
    add_rule "$ip_cmd" -w 100 -t nat -A OUTPUT     -d "$fire" -p $proto_icmp -j DNAT --to-destination "$local_ip"
    add_rule "$ip_cmd" -w 100 -t nat -A PREROUTING -d "$fire" -p $proto_icmp -j DNAT --to-destination "$local_ip"
  fi
}

# --- Remove rules -----------------------------------------------------------
remove_tproxy_rules() {
  ip_cmd="${1:-iptables}"

  if [ "$ip_cmd" = "iptables" ]; then local_ip="127.0.0.1"; fire="$FAIR4"; else local_ip="::1"; fire="$FAIR6"; fi

  log_safe "🧹 删除 $ip_cmd 规则..."

  add_rule "$ip_cmd" -w 100 -t mangle -D PREROUTING -j "$CHAIN_PRE"
  add_rule "$ip_cmd" -w 100 -t mangle -D OUTPUT     -j "$CHAIN_OUT"
  add_rule "$ip_cmd" -w 100 -t mangle -D PREROUTING -p tcp -m socket --transparent -j DIVERT

  add_rule "$ip_cmd" -w 100 -t mangle -F DIVERT
  add_rule "$ip_cmd" -w 100 -t mangle -X DIVERT
  add_rule "$ip_cmd" -w 100 -t mangle -F "$CHAIN_PRE"
  add_rule "$ip_cmd" -w 100 -t mangle -X "$CHAIN_PRE"
  add_rule "$ip_cmd" -w 100 -t mangle -F "$CHAIN_OUT"
  add_rule "$ip_cmd" -w 100 -t mangle -X "$CHAIN_OUT"

  # Remove self-protection rejects
  add_rule "$ip_cmd" -w 100 -D OUTPUT -d "$local_ip" -p tcp --dport "$TPROXY_PORT" -j REJECT
  add_rule "$ip_cmd" -w 100 -D OUTPUT -d "$local_ip" -p udp --dport "$TPROXY_PORT" -j REJECT

  # nat DNS and FakeIP ICMP cleanup
  if $ip_cmd -t nat -nL >/dev/null 2>&1; then
    add_rule "$ip_cmd" -w 100 -t nat -D OUTPUT     -j CLASH_DNS_OUT
    add_rule "$ip_cmd" -w 100 -t nat -D PREROUTING -j CLASH_DNS_PRE
    add_rule "$ip_cmd" -w 100 -t nat -F CLASH_DNS_OUT
    add_rule "$ip_cmd" -w 100 -t nat -X CLASH_DNS_OUT
    add_rule "$ip_cmd" -w 100 -t nat -F CLASH_DNS_PRE
    add_rule "$ip_cmd" -w 100 -t nat -X CLASH_DNS_PRE

    if [ -n "$fire" ]; then
      add_rule "$ip_cmd" -w 100 -t nat -D OUTPUT     -d "$fire" -p icmp -j DNAT --to-destination "$local_ip"
      add_rule "$ip_cmd" -w 100 -t nat -D PREROUTING -d "$fire" -p icmp -j DNAT --to-destination "$local_ip"
    fi
  fi
}

# --- Entrypoint -------------------------------------------------------------
case "$1" in
  stop)
    log_safe "🛑 清除防火墙规则..."
    remove_tproxy_rules iptables
    [ "$IPV6_SUPPORT" = "1" ] && remove_tproxy_rules ip6tables
    unset_routes
    log_safe "✅ 完成"
    ;;
  *)
    log_safe "🚀 应用防火墙规则..."
    setup_routes
    add_tproxy_rules iptables
    [ "$IPV6_SUPPORT" = "1" ] && add_tproxy_rules ip6tables
    log_safe "✅ 完成"
    ;;
esac

exit 0