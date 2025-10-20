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

# --- 函数定义 ---

# 获取主 IP 地址的函数
get_primary_ip() {
  ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1); exit}'
}

# 使用 head -n 1 确保在多 Wi-Fi 接口时只返回一个 SSID
get_current_ssid() {
  cmd wifi status | grep 'SSID:' | head -n 1 | sed -n 's/.*SSID: \"\([^\"]*\)\".*/\1/p'
}

# 记录资源使用情况
log_resource_usage() {
  # 检查 PIDFILE 是否存在且有内容
  if [ -s "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE")
    # 检查进程是否存在
    if kill -0 "$pid" 2>/dev/null; then
      # 从 /proc/[pid]/status 获取 VmRSS (Resident Set Size)
      mem_kb=$(grep VmRSS "/proc/$pid/status" | awk '{print $2}')
      if [ -n "$mem_kb" ] && [ "$mem_kb" -gt 0 ]; then
        mem_mb=$((mem_kb / 1024))
        # 计算内存变化量
        if [ -n "$LAST_MEM_MB" ]; then
          diff=$((mem_mb - LAST_MEM_MB))
          abs_diff=${diff#-} # Absolute difference
        else
          abs_diff=$((MEM_THRESHOLD_MB + 1)) # 强制首次记录
        fi

        # 如果变化超过阈值, 则记录
        if [ "$abs_diff" -gt "$MEM_THRESHOLD_MB" ]; then
          log_safe "💡 当前占用资源: ${mem_mb}MB 内存"
          LAST_MEM_MB=$mem_mb
        fi
      fi
    fi
  fi
}

log_safe "✨ === [monitor] === ✨"
log_safe "🛡️ 监控服务已启动, 检查周期: ${CHECK_INTERVAL} 秒"

PROXY_STATUS="unknown"
LAST_MEM_MB=""
MEM_THRESHOLD_MB=5
LAST_IP=$(get_primary_ip)

# 读取忽略的 SSID 列表
IGNORE_SSID=$(read_setting "IGNORE_SSID" "")
log_safe "🌏 初始网络 IP: ${LAST_IP:-'未连接'}"
[ -n "$IGNORE_SSID" ] && log_safe "🚫 忽略的 SSID: $IGNORE_SSID"

# --- 主循环 ---

while true; do
  sleep "$CHECK_INTERVAL"
  log_resource_usage

  # 1. 获取当前网络环境
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
    LAST_IP=$(get_primary_ip) # 持续更新IP，以便切换网络后能正确识别变化
  else
    # 2. 检查网络状态 (仅在非忽略网络下)
    current_ip=$(get_primary_ip)
    if [ "$current_ip" != "$LAST_IP" ]; then
      log_safe "🛜 网络切换: ${LAST_IP:-'N/A'} -> ${current_ip:-'N/A'}"
      if [ -n "$current_ip" ]; then
        log_safe "🔄 正在更新内网规则..."
        sh "$TPROXY" update_lan >/dev/null 2>&1 || log_safe "❓ 内网规则更新失败"
      else
        log_safe "🔌 网络连接断开, 等待恢复..."
      fi
      LAST_IP=$current_ip
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
      LAST_IP=$(get_primary_ip)
      sleep 2
    fi
  fi

  # 5. 更新模块状态描述
  if [ "$new_status" != "$PROXY_STATUS" ]; then
    case "$new_status" in
    "running") update_desc "✅" ;;
    "paused") update_desc "⏸️" ;;
    "stopped") update_desc "⛔" ;;
    esac
    PROXY_STATUS=$new_status
    log_safe "ℹ️ 模块状态更新为: $PROXY_STATUS"
  fi
done
