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

# 使用 head -n 1 确保在多 Wi-Fi 接口时只返回一个 SSID
get_current_ssid() {
  cmd wifi status | grep 'SSID:' | head -n 1 | sed -n 's/.*SSID: \"\([^\"]*\)\".*/\1/p'
}

log_safe "✨ === [monitor] ==="

# 初始化网络状态
last_ip=$(get_primary_ip)
log_safe "🌏 初始网络 IP: ${last_ip:-'未连接'}"

# 读取忽略的 SSID 列表
IGNORE_SSID=$(read_setting "IGNORE_SSID" "")
[ -n "$IGNORE_SSID" ] && log_safe "🚫 忽略的 SSID: $IGNORE_SSID"

proxy_status="" # 跟踪代理状态: running, stopped, paused

while true; do
  sleep "$CHECK_INTERVAL"

  # 1. 检查是否连接到被忽略的 SSID
  current_ssid=$(get_current_ssid)
  should_be_paused=false
  if [ -n "$current_ssid" ]; then
    for ignored in $IGNORE_SSID; do
      if [ "$current_ssid" = "$ignored" ]; then
        should_be_paused=true
        break
      fi
    done
  fi

  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  is_running=false
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && is_running=true

  new_status=""

  if [ "$should_be_paused" = "true" ]; then
    if [ "$is_running" = "true" ]; then
      log_safe "⏸️ 连接到忽略的 SSID ($current_ssid), 正在暂停服务..."
      sh "$SERVICE" stop >/dev/null 2>&1 || log_safe "❓ 服务停止失败"
    fi
    new_status="paused"
    last_ip=$(get_primary_ip) # 持续更新IP，以便切换网络后能正确识别变化
  else
    # 2. 检查网络状态 (仅在非忽略网络下)
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
      sleep 2
    fi

    # 3. 检查核心进程状态 (仅在非忽略网络下)
    if [ "$is_running" = "true" ]; then
      new_status="running"
    else
      new_status="stopped"
      log_safe "🛑 检测到核心已停止 (当前网络: ${current_ssid:-'N/A'}, IP: ${current_ip:-'N/A'})"

      if [ -f "$LOCK_FILE" ]; then
        log_safe "⏳ 服务启动中, 等待..."
        sleep 10
        continue
      fi

      # 4. 执行重启（带频率限制）
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
      sh "$SERVICE" >/dev/null 2>&1 || log_safe "❓ 代理服务重启失败"
      "$(date +%s)" >>"$RESTARTS_FILE"
      last_ip=$(get_primary_ip)
      sleep 2
    fi
  fi

  # 5. 更新模块状态描述
  if [ "$new_status" != "$proxy_status" ]; then
    case "$new_status" in
    "running") update_desc "✅" ;;
    "paused") update_desc "⏸️" ;;
    "stopped") update_desc "⛔" ;;
    esac
    proxy_status=$new_status
    log_safe "ℹ️ 模块状态更新为: $proxy_status"
  fi
done
