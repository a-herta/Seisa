#!/system/bin/sh
# =====================================================================
# 🔥 tproxy.sh - 透明代理 iptables 规则管理脚本
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
INTRANET6=${INTRANET6:-"::/128 ::1/128 ::ffff:0:0/96 100::/64 64:ff9b::/96 2001:10::/28 2001:20::/28 2001:db8::/32 2002::/16 2001::/32 fc00::/7 fe80::/10 ff00::/8"}

IFACES_LIST="${IFACES_LIST:-"lo wlan+ ap+ rndis+ usb+ ncm+ eth+ p2p+"}"
IGNORE_LIST="${IGNORE_LIST:-""}" # OUTPUT 忽略的 egress 接口

FAIR4=${FAIR4:-"198.18.0.0/15"}
FAIR6=${FAIR6:-"fc00::/18"}

TPROXY_PORT=${TPROXY_PORT:-"1536"}
CLASH_DNS_PORT=${CLASH_DNS_PORT:-"1053"}

IPV6_SUPPORT=${IPV6_SUPPORT:-"true"}
PROXY_MODE=${PROXY_MODE:-"$(read_setting "PROXY_MODE" "blacklist")"}
APP_PACKAGES=${APP_PACKAGES:-$(read_setting "APP_PACKAGES" "")}

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
  "$@" 2>/dev/null || true
}

ensure_hook() {
  ip_cmd="$1" table="$2" hook="$3" jump="$4"
  $ip_cmd -w 100 -t "$table" -C "$hook" -j "$jump" 2>/dev/null ||
    $ip_cmd -w 100 -t "$table" -I "$hook" -j "$jump"
}

# --- Policy routing ---------------------------------------------------------
setup_routes() {
  log_safe "🗺️ 设置策略路由..."
  add_rule ip rule add fwmark "$MARK_HEX" lookup "$TABLE_ID" pref "$TABLE_ID"
  add_rule ip route add local default dev lo table "$TABLE_ID"
  if [ "$IPV6_SUPPORT" = "true" ]; then
    add_rule ip -6 rule add fwmark "$MARK_HEX" lookup "$TABLE_ID" pref "$TABLE_ID"
    add_rule ip -6 route add local default dev lo table "$TABLE_ID"
  else
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
  fi
}

unset_routes() {
  log_safe "🗺️ 清除策略路由..."
  add_rule ip rule del fwmark "$MARK_HEX" lookup "$TABLE_ID" pref "$TABLE_ID"
  add_rule ip route flush table "$TABLE_ID"
  if [ "$IPV6_SUPPORT" = "true" ]; then
    add_rule ip -6 rule del fwmark "$MARK_HEX" lookup "$TABLE_ID" pref "$TABLE_ID"
    add_rule ip -6 route flush table "$TABLE_ID"
  fi
  sysctl -w net.ipv6.conf.all.disable_ipv6=0
  sysctl -w net.ipv6.conf.default.disable_ipv6=0
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
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner 0 -j MARK --set-xmark "$MARK_HEX"
  add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p udp -m owner --uid-owner 0 -j MARK --set-xmark "$MARK_HEX"
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
  *) add_global_proxy_rules "$ip_cmd" ;;
  esac
}

# --- TPROXY main ------------------------------------------------------------
add_tproxy_rules() {
  ip_cmd="${1:-iptables}"

  if [ "$ip_cmd" = "iptables" ]; then
    local_ip="127.0.0.1"
    fire="$FAIR4"
    proto_icmp="icmp"
    lan_ips="${INTRANET4:+$INTRANET4 }$(ip -4 a | awk '/inet/ {print $2}' | grep -vE "^127.0.0.1")"
  else
    local_ip="::1"
    fire="$FAIR6"
    proto_icmp="icmpv6"
    lan_ips="${INTRANET6:+$INTRANET6 }$(ip -6 a | awk '/inet6/ {print $2}' | grep -vE "^fe80|^::1")"
  fi

  log_safe "🎫 添加 $ip_cmd 规则..."

  # Create/flush chains
  add_rule "$ip_cmd" -w 100 -t mangle -N DIVERT
  add_rule "$ip_cmd" -w 100 -t mangle -F DIVERT
  log_safe "🔗 创建自定义 PREROUTING 链..."
  add_rule "$ip_cmd" -w 100 -t mangle -N "$CHAIN_PRE"
  add_rule "$ip_cmd" -w 100 -t mangle -F "$CHAIN_PRE"
  log_safe "🔗 创建自定义 OUTPUT 链..."
  add_rule "$ip_cmd" -w 100 -t mangle -N "$CHAIN_OUT"
  add_rule "$ip_cmd" -w 100 -t mangle -F "$CHAIN_OUT"

  add_rule "$ip_cmd" -w 100 -t mangle -A DIVERT -j MARK --set-xmark "$MARK_HEX"
  add_rule "$ip_cmd" -w 100 -t mangle -A DIVERT -j ACCEPT

  # Bypass intranet/reserved ranges
  for ip in $lan_ips; do
    log_safe "🚦 $CHAIN_PRE 放行内网 ($ip)..."
    add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -d "$ip" -j RETURN
  done

  if [ -n "$IFACES_LIST" ]; then
    for iface in $IFACES_LIST; do
      log_safe "🔄 $CHAIN_PRE 路由 ($iface)..."
      add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -p tcp -i "$iface" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"
      add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -p udp -i "$iface" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"
    done
  else
    # Global mode: catch-all TPROXY after bypass/socket rules
    log_safe "🔄 $CHAIN_PRE 路由所有流量..."
    add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -p tcp -j TPROXY --on-ip "$local_ip" --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"
    add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -p udp -j TPROXY --on-ip "$local_ip" --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"
  fi

  # Hook PREROUTING -> CHAIN_PRE
  ensure_hook "$ip_cmd" mangle PREROUTING "$CHAIN_PRE"

  log_safe "🔌 $CHAIN_PRE 标记透明代理接管..."
  add_rule "$ip_cmd" -w 100 -t mangle -I PREROUTING 1 -p tcp -m socket --transparent -j DIVERT

  # OUTPUT chain: bypass proxy user
  log_safe "👤 $CHAIN_OUT 放行 $TPROXY_USER($USER_ID:$GROUP_ID)..."
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
  clash | mihomo | hysteria)
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
      # add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -p tcp --dport 53 -j RETURN
      # add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_PRE" -p udp --dport 53 -j RETURN
      # add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p tcp --dport 53 -j RETURN
      # add_rule "$ip_cmd" -w 100 -t mangle -A "$CHAIN_OUT" -p udp --dport 53 -j RETURN
    fi
    ;;
  esac

  # OUTPUT: hook
  ensure_hook "$ip_cmd" mangle OUTPUT "$CHAIN_OUT"

  # Self-protection: block local service hitting tproxy port (TCP+UDP)
  log_safe "🛡️ 阻止本地服务访问 tproxy 端口 $TPROXY_PORT"
  add_rule "$ip_cmd" -w 100 -A OUTPUT -d "$local_ip" -p tcp --dport "$TPROXY_PORT" -j REJECT
  add_rule "$ip_cmd" -w 100 -A OUTPUT -d "$local_ip" -p udp --dport "$TPROXY_PORT" -j REJECT

  if [ "$ip_cmd" = "ip6tables" ]; then
    add_rule "$ip_cmd" -w 100 -A OUTPUT -p udp --dport 53 -j DROP
    add_rule "$ip_cmd" -w 100 -A OUTPUT -p tcp --dport 853 -j DROP
  fi

  # FakeIP ICMP fix (if nat available)
  if $ip_cmd -t nat -nL >/dev/null 2>&1 && [ -n "$fire" ]; then
    log_safe "👻 修复 FakeIP($fire) ICMP"
    add_rule "$ip_cmd" -w 100 -t nat -A OUTPUT -d "$fire" -p $proto_icmp -j DNAT --to-destination "$local_ip"
    add_rule "$ip_cmd" -w 100 -t nat -A PREROUTING -d "$fire" -p $proto_icmp -j DNAT --to-destination "$local_ip"
  fi
}

# --- Remove rules -----------------------------------------------------------
remove_tproxy_rules() {
  ip_cmd="${1:-iptables}"

  if [ "$ip_cmd" = "iptables" ]; then
    local_ip="127.0.0.1"
    fire="$FAIR4"
  else
    local_ip="::1"
    fire="$FAIR6"
  fi

  log_safe "🧹 删除 $ip_cmd 规则..."

  add_rule "$ip_cmd" -w 100 -t mangle -D PREROUTING -j "$CHAIN_PRE"
  add_rule "$ip_cmd" -w 100 -t mangle -D OUTPUT -j "$CHAIN_OUT"
  add_rule "$ip_cmd" -w 100 -t mangle -D PREROUTING -p tcp -m socket --transparent -j DIVERT

  add_rule "$ip_cmd" -w 100 -t mangle -F DIVERT
  add_rule "$ip_cmd" -w 100 -t mangle -X DIVERT
  add_rule "$ip_cmd" -w 100 -t mangle -F "$CHAIN_PRE"
  add_rule "$ip_cmd" -w 100 -t mangle -X "$CHAIN_PRE"
  add_rule "$ip_cmd" -w 100 -t mangle -F "$CHAIN_OUT"
  add_rule "$ip_cmd" -w 100 -t mangle -X "$CHAIN_OUT"

  if [ "$ip_cmd" = "ip6tables" ]; then
    add_rule "$ip_cmd" -w 100 -D OUTPUT -p udp --dport 53 -j DROP
    add_rule "$ip_cmd" -w 100 -D OUTPUT -p tcp --dport 853 -j DROP
  fi

  # Remove self-protection rejects
  add_rule "$ip_cmd" -w 100 -D OUTPUT -d "$local_ip" -p tcp --dport "$TPROXY_PORT" -j REJECT
  add_rule "$ip_cmd" -w 100 -D OUTPUT -d "$local_ip" -p udp --dport "$TPROXY_PORT" -j REJECT

  # nat DNS and FakeIP ICMP cleanup
  if $ip_cmd -t nat -nL >/dev/null 2>&1; then
    add_rule "$ip_cmd" -w 100 -t nat -D OUTPUT -j CLASH_DNS_OUT
    add_rule "$ip_cmd" -w 100 -t nat -D PREROUTING -j CLASH_DNS_PRE
    add_rule "$ip_cmd" -w 100 -t nat -F CLASH_DNS_OUT
    add_rule "$ip_cmd" -w 100 -t nat -X CLASH_DNS_OUT
    add_rule "$ip_cmd" -w 100 -t nat -F CLASH_DNS_PRE
    add_rule "$ip_cmd" -w 100 -t nat -X CLASH_DNS_PRE

    add_rule "$ip_cmd" -w 100 -t nat -D OUTPUT -d "$fire" -p icmp -j DNAT --to-destination "$local_ip"
    add_rule "$ip_cmd" -w 100 -t nat -D PREROUTING -d "$fire" -p icmp -j DNAT --to-destination "$local_ip"
  fi
}

# --- Entrypoint -------------------------------------------------------------
case "$1" in
stop)
  log_safe "🛑 清除防火墙规则..."
  remove_tproxy_rules iptables
  [ "$IPV6_SUPPORT" = "true" ] && remove_tproxy_rules ip6tables
  unset_routes
  log_safe "✅ 完成"
  ;;
*)
  log_safe "🚀 应用防火墙规则..."
  setup_routes
  add_tproxy_rules iptables
  [ "$IPV6_SUPPORT" = "true" ] && add_tproxy_rules ip6tables
  log_safe "✅ 完成"
  ;;
esac
