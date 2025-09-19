#!/system/bin/sh
# =====================================================================
# 📜 common.sh - 模块通用核心脚本（Magisk/KernelSU 环境）
# ---------------------------------------------------------------------
# 功能：
#   - 定义全局变量（路径、标识符、配置文件等）
#   - 配置读写（并发安全）、日志、安全退出
#   - 网络参数与 IPv6 检测
#   - 权限设置（兼容安装环境/普通环境）
#   - 域名解析（多方案回退）
#   - 后台进程启动（可指定 UID/GID）
# =====================================================================

# --- 模块路径与标识 ---
MODDIR=${MODDIR:-${0%/*}}
MODID=${MODID:-$(basename "$MODDIR")}
PERSIST_DIR=${PERSIST_DIR:-"/data/adb/$MODID"}
SETTING=${SETTING:-"$PERSIST_DIR/settings.conf"}

# --- 并发安全配置读写 ---

# read_setting <key> [default] : 从配置文件读取键值
read_setting() {
  key="$1"; default_val="$2"; f="$SETTING"
  [ -f "$f" ] || { echo "$default_val"; return; }

  val=$(grep -m1 -E "^[[:space:]]*${key}=" "$f" 2>/dev/null | \
        sed -E "s/^[[:space:]]*${key}=[[:space:]]*//" | \
        sed -E 's/[[:space:]]+$//')

  [ -n "$val" ] && echo "$val" || echo "$default_val"
}

# write_setting <key> <value> : 并发安全写入配置
write_setting() {
  key="$1"; val="$2"; f="$SETTING"; lock_dir="${f}.lock"

  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] || echo "# 模块配置文件" > "$f"

  # 使用 lock 目录实现原子操作, 防止并发写入冲突
  while ! mkdir "$lock_dir" 2>/dev/null; do 
    sleep 0.05
  done

  trap 'rmdir "$lock_dir" 2>/dev/null' EXIT

  if grep -q -E "^[[:space:]]*${key}=" "$f"; then
    sed -i -E "s|^[[:space:]]*${key}=.*|${key}=${val}|" "$f"
  else
    echo "${key}=${val}" >> "$f"
  fi

  chmod 600 "$f" 2>/dev/null || true
  rmdir "$lock_dir"
  trap - EXIT
}

# --- 重要文件路径 ---
PROP=${PROP:-"$MODDIR/module.prop"}
SERVICE=${SERVICE:-"$MODDIR/service.sh"}
START_RULES=${START_RULES:-"$MODDIR/start.rules.sh"}
FLAG=${FLAG:-"$MODDIR/service_enabled"}
LOGFILE=${LOGFILE:-"$PERSIST_DIR/$MODID.log"}
PIDFILE=${PIDFILE:-"$PERSIST_DIR/$MODID.pid"}
LOCK_FILE=${LOCK_FILE:-"$PERSIST_DIR/.${MODID}_lock"}

# --- 核心程序配置 ---
BIN_NAME=$(read_setting "BIN_NAME" "sing-box")
BIN_CONFIG=$(read_setting "BIN_CONFIG" "config.json")
CONFIG=${CONFIG:-"$PERSIST_DIR/$BIN_CONFIG"}
BIN_PATH=${BIN_PATH:-"$MODDIR/$BIN_NAME"}
BIN_LOG=${BIN_LOG:-"$PERSIST_DIR/$BIN_NAME.log"}

# --- 网络与 TProxy 参数 ---
AP_LIST=${AP_LIST:-"wlan+ ap+ rndis+ ncm+ eth+ p2p+"}
IGNORE_LIST=${IGNORE_LIST:-""}
INTRANET=${INTRANET:-"10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16"}
INTRANET6=${INTRANET6:-"::1/128 fc00::/7 fe80::/10"}

FAIR4=${FAIR4:-"198.18.0.0/15"}
FAIR6=${FAIR6:-"fc00::/18"}
TPROXY_PORT=${TPROXY_PORT:-"1536"}
TPROXY_USER=${TPROXY_USER:-"root:net_admin"}

# --- 代理模式与用户配置 ---
IPV6_SUPPORT=${IPV6_SUPPORT:-0}
if [ "$(read_setting "IPV6" "0")" = "1" ] && ip -6 route show >/dev/null 2>&1; then
  IPV6_SUPPORT=1
fi
PROXY_MODE=${PROXY_MODE:-"$(read_setting "PROXY_MODE" "blacklist")"}
APP_PACKAGES=${APP_PACKAGES:-$(read_setting "APP_PACKAGES")}

# --- 环境与路径 ---
export PATH="$PATH:/data/adb/magisk:/data/adb/ksu/bin:/data/adb/ap/bin"
if type ui_print >/dev/null 2>&1; then IS_INSTALLER_ENV=1; else IS_INSTALLER_ENV=0; fi

# --- 日志与退出 ---

# log_safe <msg> : 安全地记录日志, 兼容安装环境和普通环境
log_safe() {
  msg="$*"; ts="[$(date +'%T')]"
  
  if [ "$IS_INSTALLER_ENV" = "1" ]; then 
    ui_print "$ts $msg"
  else 
    echo "$ts $msg"
  fi
  
  if [ -n "$LOGFILE" ]; then 
    mkdir -p "$(dirname -- "$LOGFILE")" 2>/dev/null
    printf '%s %s\n' "$ts" "$msg" >> "$LOGFILE"
  fi
}

# abort_safe <msg> : 安全地终止脚本, 兼容安装环境和普通环境
abort_safe() {
  msg="$*"; ts="[$(date +'%T')]"

  if [ "$IS_INSTALLER_ENV" = "1" ] && type abort >/dev/null 2>&1; then
    abort "$ts $msg"
  else
    echo "$ts $msg" >&2
    [ -n "$LOGFILE" ] && printf '%s %s\n' "$ts" "$msg" >> "$LOGFILE"
    exit 1
  fi
}

# --- 模块状态更新 ---

# update_desc [icon] : 更新 module.prop 中的模块描述, 以反映代理状态
update_desc() {
  if [ -n "$1" ]; then 
    icon="$1"
  elif [ -f "$FLAG" ]; then 
    icon="✅"
  else 
    icon="⛔"
  fi

  tmp="$PROP.new.$$"
  awk -v icon="$icon" '
  /^description=/ {
    sub(/^description=/, "", $0)
    desc = $0
    gsub(/^[[:space:]]+/, "", desc)
    if (sub(/\[Proxy Status:[^]]*\]/, "[Proxy Status: " icon "]", desc)) {
      print "description=" desc
    } else {
      print "description=[Proxy Status: " icon "] " desc
    }
    next
  }
  { print }
  ' "$PROP" > "$tmp" && mv -f "$tmp" "$PROP"
}

# --- 权限设置 ---

# set_perm_safe <path> <uid> <gid> <perm> [fileperm] [context] : 安全设置权限, 兼容不同环境
set_perm_safe() {
  path="$1"; owner="$2"; group="$3"; perm="$4"; fileperm="$5"; ctx="$6"
  [ -n "$path" ] || return 1

  if [ "$IS_INSTALLER_ENV" = "1" ]; then
    if [ -n "$fileperm" ]; then
      set_perm_recursive "$path" "$owner" "$group" "$perm" "$fileperm" "$ctx" 2>/dev/null || true
    else
      set_perm "$path" "$owner" "$group" "$perm" "$ctx" 2>/dev/null || true
    fi
    return 0
  fi

  if [ -d "$path" ] && [ -n "$fileperm" ]; then
    chown -R "$owner:$group" "$path" 2>/dev/null || chown -R "$owner.$group" "$path" 2>/dev/null || true
    find "$path" -type d -exec chmod "$perm" {} \; 2>/dev/null || true
    find "$path" -type f -exec chmod "$fileperm" {} \; 2>/dev/null || true
  else
    chown "$owner:$group" "$path" 2>/dev/null || chown "$owner.$group" "$path" 2>/dev/null || true
    chmod "$perm" "$path" 2>/dev/null || true
  fi

  if [ -n "$ctx" ] && command -v chcon >/dev/null 2>&1; then
    chcon -R "$ctx" "$path" 2>/dev/null || true
  fi
}

# --- 提取用户/组ID ---

# 解析 user:group 或 uid:gid, 返回 UID 和 GID
resolve_user_group() {
  input="$1"

  case "$input" in
    *:*) user=${input%%:*} group=${input##*:} ;;
    *) user=$input group="" ;;
  esac

  case "$user" in
    *[!0-9]*) uid=$(id -u "$user" 2>/dev/null) ;;
    *) uid=$user ;;
  esac

  if [ -n "$group" ]; then
    case "$group" in
      *[!0-9]*) gid=$(id -g "$group" 2>/dev/null) ;;
      *) gid=$group ;;
    esac
  fi

  echo "$uid" "$gid"
}

# --- 后台进程管理 ---

# bg_run CMD [ARGS...] : 在后台运行命令, 可指定 UID/GID, 并返回 PID 和 UID
bg_run() {
  [ "$#" -ge 1 ] || { echo "Usage: bg_run CMD [ARGS...]" >&2; return 1; }

  : "${BG_RUN_LOG:=/dev/null}"
  umask 077

  read -r uid_num gid_num <<EOF
    $(resolve_user_group "$TPROXY_USER")
EOF

  # 优先使用 busybox setuidgid, 然后是 su
  if [ -n "$uid_num" ]; then
    if command -v busybox >/dev/null 2>&1 && busybox setuidgid 0 true 2>/dev/null; then
      if [ -n "$gid_num" ]; then
        setuid_cmd="busybox setuidgid ${uid_num}:${gid_num}"
      else
        setuid_cmd="busybox setuidgid ${uid_num}"
      fi
    elif command -v su >/dev/null 2>&1; then
       # su 的实现差异很大, 这是一个通用但可能不完全可靠的回退
       setuid_cmd="su $uid_num"
    fi
  fi

  # 使用 nohup 和 setsid 实现后台守护
  if command -v nohup >/dev/null 2>&1 && command -v setsid >/dev/null 2>&1; then
    nohup setsid ${setuid_cmd:+$setuid_cmd} "$@" </dev/null >"$BG_RUN_LOG" 2>&1 &
  elif command -v nohup >/dev/null 2>&1; then
    nohup ${setuid_cmd:+$setuid_cmd} "$@" </dev/null >"$BG_RUN_LOG" 2>&1 &
  elif command -v setsid >/dev/null 2>&1; then
    setsid ${setuid_cmd:+$setuid_cmd} "$@" </dev/null >"$BG_RUN_LOG" 2>&1 &
  else
    # 最后的兼容手段
    ( trap '' HUP; exec ${setuid_cmd:+$setuid_cmd} "$@" ) </dev/null >"$BG_RUN_LOG" 2>&1 &
  fi

  pid=$!
  # 如果 UID 未知, 尝试从 /proc 获取
  if [ -z "$uid_num" ] && [ -r "/proc/$pid" ]; then
    uid_num=$(stat -c %u "/proc/$pid" 2>/dev/null)
  fi

  echo "$pid $uid_num"
}

# END of common.sh