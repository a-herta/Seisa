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

CHAIN_NAME=${CHAIN_NAME:-"SEISA"}
CHAIN_PRE=${CHAIN_PRE:-"${CHAIN_NAME}_PRE"}
CHAIN_OUT=${CHAIN_OUT:-"${CHAIN_NAME}_OUT"}
CHAIN_LAN=${CHAIN_LAN:-"${CHAIN_NAME}_LAN"}
CHAIN_LOCAL=${CHAIN_LOCAL:-"${CHAIN_NAME}_LOCAL"}
CUSTOM_CHAIN=${CUSTOM_CHAIN:-"DIVERT $CHAIN_PRE $CHAIN_OUT $CHAIN_LAN $CHAIN_LOCAL"}

INTRANET4=${INTRANET4:-"10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"}
INTRANET6=${INTRANET6:-"::1/128 fe80::/10 fc00::/7 ff00::/8"}

UID_LIST="${UID_LIST:-""}"
IGNORE_LIST="${IGNORE_LIST:-""}"

FAIR4=${FAIR4:-"198.18.0.0/15"}
FAIR6=${FAIR6:-"fc00::/18"}

TPROXY_PORT=${TPROXY_PORT:-"1536"}
CLASH_DNS_PORT=${CLASH_DNS_PORT:-"1053"}

IPV6_SUPPORT=${IPV6_SUPPORT:-"$(read_setting "IPV6_SUPPORT" "true")"}
PROXY_MODE=${PROXY_MODE:-"$(read_setting "PROXY_MODE" "blacklist")"}

log_safe "✨ === [tproxy] ==="

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

  [ -n "$fair4" ] && FAIR4="$fair4" && log_safe "📌 FakeIP v4: $FAIR4"
  [ -n "$fair6" ] && FAIR6="$fair6" && log_safe "📌 FakeIP v6: $FAIR6"
  [ -n "$t_port" ] && TPROXY_PORT="$t_port" && log_safe "📌 TProxy port: $TPROXY_PORT"
}

detect_tproxy_params

ensure_hook() {
  ip_cmd="$1" table="$2" hook="$3" jump="$4"
  $ip_cmd -t "$table" -C "$hook" -j "$jump" 2>/dev/null ||
    $ip_cmd -t "$table" -I "$hook" -j "$jump"
}

# --- Policy routing ---------------------------------------------------------
setup_routes() {
  log_safe "🗺️ 设置策略路由..."
  ip rule add fwmark "$MARK_HEX" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
  ip route add local default dev lo table "$TABLE_ID" 2>/dev/null || true
  sysctl -w net.ipv4.ip_nonlocal_bind=1
  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.ipv4.conf.all.rp_filter=0
  sysctl -w net.ipv4.conf.default.rp_filter=0

  if [ "$IPV6_SUPPORT" = "true" ]; then
    ip -6 rule add fwmark "$MARK_HEX" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
    ip -6 route add local default dev lo table "$TABLE_ID" 2>/dev/null || true
    sysctl -w net.ipv6.ip_nonlocal_bind=1
    sysctl -w net.ipv6.conf.all.forwarding=1
  fi
}

unset_routes() {
  log_safe "🗺️ 清除策略路由..."
  ip rule del fwmark "$MARK_HEX" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
  ip route flush table "$TABLE_ID" 2>/dev/null || true
  if [ "$IPV6_SUPPORT" = "true" ]; then
    ip -6 rule del fwmark "$MARK_HEX" lookup "$TABLE_ID" pref "$TABLE_ID" 2>/dev/null || true
    ip -6 route flush table "$TABLE_ID" 2>/dev/null || true
  fi
}

# --- App split rules --------------------------------------------------------
find_packages_uid() {
  up=$(read_setting "USER_PACKAGES" "")
  for user_pkg in $up; do
    user="${user_pkg%%:*}"
    pkg="${user_pkg##*:}"
    uid="$(awk -v p="$pkg" '$1==p {print $2}' /data/system/packages.list)"
    if [ -n "$uid" ]; then
      UID_LIST="${UID_LIST:+$UID_LIST }$((user * 100000 + uid))"
    fi
  done
  log_safe "🔍 找到 $(echo "$UID_LIST" | wc -w) 个应用"
}

find_packages_uid

add_global_proxy_rules() {
  ip_cmd="${1:-iptables}"
  log_safe "🎯 $CHAIN_OUT MARK 剩余流量 到 策略路由 $MARK_HEX"
  $ip_cmd -t mangle -A "$CHAIN_OUT" -p tcp -j MARK --set-xmark "$MARK_HEX"
  $ip_cmd -t mangle -A "$CHAIN_OUT" -p udp -j MARK --set-xmark "$MARK_HEX"
}

add_blacklist_rules() {
  ip_cmd="${1:-iptables}"
  for uid in $UID_LIST; do
    log_safe "⚫ $CHAIN_OUT 忽略程序黑名单: ($uid)"
    $ip_cmd -t mangle -A "$CHAIN_OUT" -m owner --uid-owner "$uid" -j RETURN
  done
  add_global_proxy_rules "$ip_cmd"
}

add_whitelist_rules() {
  ip_cmd="${1:-iptables}"
  if [ -z "$UID_LIST" ]; then
    log_safe "⭕ $CHAIN_OUT 白名单为空, 将仅代理本机 DNS 流量"
    return
  fi
  for uid in $UID_LIST; do
    log_safe "⚪ $CHAIN_OUT 标记程序白名单: ($uid)"
    $ip_cmd -t mangle -A "$CHAIN_OUT" -p tcp -m owner --uid-owner "$uid" -j MARK --set-xmark "$MARK_HEX"
    $ip_cmd -t mangle -A "$CHAIN_OUT" -p udp -m owner --uid-owner "$uid" -j MARK --set-xmark "$MARK_HEX"
  done
}

add_app_rules() {
  ip_cmd="${1:-iptables}"
  case "$PROXY_MODE" in
  whitelist) add_whitelist_rules "$ip_cmd" ;;
  blacklist) add_blacklist_rules "$ip_cmd" ;;
  *) add_global_proxy_rules "$ip_cmd" ;;
  esac
}

# --- TPROXY main ------------------------------------------------------------
add_tproxy_rules() {
  ip_cmd="${1:-iptables}"
  log_safe "🎫 添加 $ip_cmd 规则..."

  case "$ip_cmd" in
  iptables*)
    local_ip="127.0.0.1"
    fire="$FAIR4"
    proto_icmp="icmp"
    lan_ips="$INTRANET4"
    ;;
  ip6tables*)
    local_ip="::1"
    fire="$FAIR6"
    proto_icmp="icmpv6"
    lan_ips="$INTRANET6"
    ;;
  esac

  for chain in $CUSTOM_CHAIN; do
    log_safe "🔗 创建自定义 $chain 链..."
    $ip_cmd -t mangle -N "$chain" 2>/dev/null || true
    $ip_cmd -t mangle -F "$chain"
  done

  log_safe "⭕ $CHAIN_PRE 忽略来自 lo 且未标记的流量"
  $ip_cmd -t mangle -A "$CHAIN_PRE" -i lo -m mark --mark 0/1 -j RETURN

  $ip_cmd -t mangle -A DIVERT -j MARK --set-xmark "$MARK_HEX"
  $ip_cmd -t mangle -A DIVERT -j ACCEPT
  $ip_cmd -t mangle -I PREROUTING 1 -p tcp -m socket --transparent -j DIVERT

  log_safe "📢 $CHAIN_OUT 忽略程序 $TPROXY_USER($USER_ID:$GROUP_ID)..."
  $ip_cmd -t mangle -A "$CHAIN_OUT" -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -j RETURN

  log_safe "➰ $CHAIN_PRE & $CHAIN_OUT 跳转至 $CHAIN_LAN"
  $ip_cmd -t mangle -A "$CHAIN_PRE" -j "$CHAIN_LAN"
  $ip_cmd -t mangle -A "$CHAIN_OUT" -j "$CHAIN_LAN"

  # 静态内网地址
  for ip in $lan_ips; do
    log_safe "🚩 $CHAIN_LAN 忽略静态内网 ($ip)..."
    $ip_cmd -t mangle -A "$CHAIN_LAN" -d "$ip" -j RETURN
  done

  for ignore in $IGNORE_LIST; do
    log_safe "🎈 $CHAIN_OUT 忽略接口 ($ignore)..."
    $ip_cmd -t mangle -A "$CHAIN_OUT" -o "$ignore" -j RETURN
  done

  case $BIN_NAME in
  clash | mihomo | hysteria)
    log_safe "🚥 DNS 走 nat REDIRECT 到 $CLASH_DNS_PORT"
    if $ip_cmd -t nat -nL >/dev/null 2>&1; then
      $ip_cmd -t nat -N CLASH_DNS_PRE 2>/dev/null || true
      $ip_cmd -t nat -F CLASH_DNS_PRE
      $ip_cmd -t nat -A CLASH_DNS_PRE -p tcp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      $ip_cmd -t nat -A CLASH_DNS_PRE -p udp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      ensure_hook "$ip_cmd" nat PREROUTING CLASH_DNS_PRE

      $ip_cmd -t nat -N CLASH_DNS_OUT 2>/dev/null || true
      $ip_cmd -t nat -F CLASH_DNS_OUT
      $ip_cmd -t nat -A CLASH_DNS_OUT -m owner --uid-owner "$USER_ID" --gid-owner "$GROUP_ID" -j RETURN
      $ip_cmd -t nat -A CLASH_DNS_OUT -p tcp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      $ip_cmd -t nat -A CLASH_DNS_OUT -p udp --dport 53 -j REDIRECT --to-ports "$CLASH_DNS_PORT"
      ensure_hook "$ip_cmd" nat OUTPUT CLASH_DNS_OUT
    else
      log_safe "❗ $ip_cmd 不支持 nat 表, 跳过 DNS REDIRECT"
      $ip_cmd -t mangle -A "$CHAIN_PRE" -p tcp --dport 53 -j RETURN
      $ip_cmd -t mangle -A "$CHAIN_PRE" -p udp --dport 53 -j RETURN
      $ip_cmd -t mangle -A "$CHAIN_OUT" -p tcp --dport 53 -j RETURN
      $ip_cmd -t mangle -A "$CHAIN_OUT" -p udp --dport 53 -j RETURN
    fi
    ;;
  *)
    log_safe "🚥 DNS 走 mangle TPROXY 到 $TPROXY_PORT"
    $ip_cmd -t mangle -A "$CHAIN_PRE" -p tcp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"
    $ip_cmd -t mangle -A "$CHAIN_PRE" -p udp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"
    $ip_cmd -t mangle -A "$CHAIN_OUT" -p tcp --dport 53 -j MARK --set-xmark "$MARK_HEX"
    $ip_cmd -t mangle -A "$CHAIN_OUT" -p udp --dport 53 -j MARK --set-xmark "$MARK_HEX"
    ;;
  esac

  log_safe "🔄 $CHAIN_PRE TPROXY 所有剩余流量到 $TPROXY_PORT..."
  $ip_cmd -t mangle -A "$CHAIN_PRE" -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"
  $ip_cmd -t mangle -A "$CHAIN_PRE" -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK_HEX"

  add_app_rules "$ip_cmd"

  log_safe "💉 $CHAIN_PRE 挂接至 PREROUTING"
  ensure_hook "$ip_cmd" mangle PREROUTING "$CHAIN_PRE"

  log_safe "💉 $CHAIN_OUT 挂接至 OUTPUT"
  ensure_hook "$ip_cmd" mangle OUTPUT "$CHAIN_OUT"

  # Self-protection: block local service hitting tproxy port (TCP+UDP)
  log_safe "⛔ OUTPUT 阻止本地服务访问 $TPROXY_PORT"
  $ip_cmd -A OUTPUT -d "$local_ip" -p tcp --dport "$TPROXY_PORT" -j REJECT
  $ip_cmd -A OUTPUT -d "$local_ip" -p udp --dport "$TPROXY_PORT" -j REJECT

  # FakeIP ICMP fix (if nat available)
  if $ip_cmd -t nat -nL >/dev/null 2>&1 && [ "$FAKEIP_ICMP_FIX" = "true" ]; then
    log_safe "👻 PREROUTING & OUTPUT 修复 FakeIP($fire) ICMP"
    $ip_cmd -t nat -A OUTPUT -d "$fire" -p "$proto_icmp" -j DNAT --to-destination "$local_ip"
    $ip_cmd -t nat -A PREROUTING -d "$fire" -p "$proto_icmp" -j DNAT --to-destination "$local_ip"
  fi
}

# --- Remove rules -----------------------------------------------------------
remove_tproxy_rules() {
  ip_cmd="${1:-iptables}"

  case "$ip_cmd" in
  iptables*)
    local_ip="127.0.0.1"
    fire="$FAIR4"
    proto_icmp="icmp"
    ;;
  ip6tables*)
    local_ip="::1"
    fire="$FAIR6"
    proto_icmp="icmpv6"
    ;;
  esac

  log_safe "🧹 删除 $ip_cmd 规则..."

  log_safe "💉 移除自定义链挂接策略"
  $ip_cmd -t mangle -D PREROUTING -j "$CHAIN_PRE" 2>/dev/null || true
  $ip_cmd -t mangle -D OUTPUT -j "$CHAIN_OUT" 2>/dev/null || true
  $ip_cmd -t mangle -D PREROUTING 1 -p tcp -m socket --transparent -j DIVERT 2>/dev/null || true

  for chain in $CUSTOM_CHAIN; do
    log_safe "🔗 移除自定义 $chain 链"
    $ip_cmd -t mangle -F "$chain" 2>/dev/null || true
    $ip_cmd -t mangle -X "$chain" 2>/dev/null || true
  done

  log_safe "⛔ 移除 OUTPUT 阻止本地服务策略"
  $ip_cmd -D OUTPUT -d "$local_ip" -p tcp --dport "$TPROXY_PORT" -j REJECT 2>/dev/null || true
  $ip_cmd -D OUTPUT -d "$local_ip" -p udp --dport "$TPROXY_PORT" -j REJECT 2>/dev/null || true

  if $ip_cmd -t nat -nL >/dev/null 2>&1; then
    log_safe "💉 移除 CLASH_DNS 挂接策略"
    $ip_cmd -t nat -D OUTPUT -j CLASH_DNS_OUT 2>/dev/null || true
    $ip_cmd -t nat -D PREROUTING -j CLASH_DNS_PRE 2>/dev/null || true

    for chain in CLASH_DNS_PRE CLASH_DNS_OUT; do
      log_safe "🔗 移除 CLASH_DNS 自定义 $chain 链"
      $ip_cmd -t nat -F "$chain" 2>/dev/null || true
      $ip_cmd -t nat -X "$chain" 2>/dev/null || true
    done

    if [ "$FAKEIP_ICMP_FIX" = "true" ]; then
      log_safe "👻 移除 PREROUTING & OUTPUT 修复 FakeIP ICMP 策略"
      $ip_cmd -t nat -D OUTPUT -d "$fire" -p "$proto_icmp" -j DNAT --to-destination "$local_ip"
      $ip_cmd -t nat -D PREROUTING -d "$fire" -p "$proto_icmp" -j DNAT --to-destination "$local_ip"
    fi
  fi
}

# --- Entrypoint -------------------------------------------------------------
case "$1" in
stop)
  log_safe "🛑 清除网络规则..."
  remove_tproxy_rules "iptables -w 100"
  [ "$IPV6_SUPPORT" = "true" ] && remove_tproxy_rules "ip6tables -w 100"
  unset_routes
  log_safe "✅ 规则已清除"
  ;;
*)
  log_safe "🚀 应用网络规则..."
  setup_routes
  add_tproxy_rules "iptables -w 100"
  [ "$IPV6_SUPPORT" = "true" ] && add_tproxy_rules "ip6tables -w 100"
  log_safe "✅ 规则已应用"
  ;;
esac
