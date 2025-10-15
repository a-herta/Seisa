#!/system/bin/sh
# =====================================================================
# 👀 monitor.sh - 核心进程及网络状态守护脚本
# =====================================================================

set -e

MODDIR=$(dirname "$0")
. "$MODDIR/common.sh"

MAX_RESTARTS=${MAX_RESTARTS:-6}     # 时间窗口内最大重启次数
WINDOW=${WINDOW:-300}               # 时间窗口（秒）
CHECK_INTERVAL=${CHECK_INTERVAL:-5} # 检查间隔（秒）
RESTARTS_FILE="$PERSIST_DIR/.restart_timestamps"

touch "$RESTARTS_FILE" 2>/dev/null || true

# 获取主 IP 地址的函数
get_primary_ip() {
  ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1); exit}'
}

log_safe "✨ === [monitor] ==="

# 初始化网络状态
last_ip=$(get_primary_ip)
log_safe "🌏 初始网络 IP: ${last_ip:-'未连接'}"

while true; do
  sleep "$CHECK_INTERVAL"

  # 1. 检查网络状态
  current_ip=$(get_primary_ip)
  if [ "$current_ip" != "$last_ip" ]; then
    log_safe "🛜 网络切换: ${last_ip:-'N/A'} -> ${current_ip:-'N/A'}"
    if [ -n "$current_ip" ]; then
      log_safe "🔄 正在应用新的网络规则..."
      sh "$TPROXY" stop >/dev/null 2>&1 || true
      sh "$TPROXY" >/dev/null 2>&1 || log_safe "❓ 新网络规则应用失败"
    else
      log_safe "🔌 网络连接断开, 清理规则..."
      sh "$TPROXY" stop >/dev/null 2>&1 || true
    fi
    last_ip=$current_ip
    # 网络变化后，给一点时间稳定，然后立即重新检查进程状态
    sleep 2
  fi

  # 2. 检查核心进程状态
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    continue # 进程正常，开始下一次循环
  fi

  log_safe "🛑 检测到核心已停止"

  # 如果 service.sh 正在运行, 等待
  if [ -f "$LOCK_FILE" ]; then
    log_safe "⏳ 服务启动中, 等待..."
    sleep 10
    continue
  fi

  # 3. 执行重启（带频率限制）
  now=$(date +%s)
  tmpfile=$(mktemp)
  awk -v now="$now" -v win="$WINDOW" '$1 >= now-win {print $1}' "$RESTARTS_FILE" 2>/dev/null >"$tmpfile" || true
  mv -f "$tmpfile" "$RESTARTS_FILE" 2>/dev/null || true
  count=$(wc -l <"$RESTARTS_FILE" 2>/dev/null || echo 0)

  if [ "$count" -ge "$MAX_RESTARTS" ]; then
    log_safe "❗ $WINDOW 秒内重启次数超限($count), 休眠 60 秒"
    sleep 60
    continue
  fi

  log_safe "🚀 核心未运行, 尝试重启"

  # 执行重启 (service.sh 内部会负责启动 tproxy)
  sh "$SERVICE" >/dev/null 2>&1 || log_safe "❓ 代理服务重启失败"

  "$(date +%s)" >>"$RESTARTS_FILE"

  # 重启后，更新IP记录，防止网络没变但IP被误判为变化
  last_ip=$(get_primary_ip)
  sleep 2
done
