#!/system/bin/sh
# =====================================================================
# 📜 common.sh - 模块通用核心脚本
# =====================================================================

# --- 模块路径与标识 ---
MODDIR=${MODDIR:-$(dirname "$0")}
MODID=${MODID:-$(basename "$MODDIR")}
PERSIST_DIR=${PERSIST_DIR:-"../../$MODID"}
if [ ! -f "/system/build.prop" ]; then
  PERSIST_DIR=$MODDIR
fi

# --- 并发安全配置读写 ---
MOD_SETTING=${MOD_SETTING:-"$PERSIST_DIR/settings.conf"}

read_setting() {
  f="$MOD_SETTING"
  [ -f "$f" ] || {
    echo "$2"
    return
  }

  val=$(grep -m1 -E "^[[:space:]]*$1=" "$f" 2>/dev/null |
    sed -E "s/^[[:space:]]*$1=[[:space:]]*//" |
    sed -E 's/[[:space:]]+$//')

  [ -n "$val" ] && echo "$val" || echo "$2"
}

write_setting() {
  f="$MOD_SETTING"
  lock_dir="${f}.lock"

  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] || echo "# 模块配置文件" >"$f"

  # 使用 lock 目录实现原子操作, 防止并发写入冲突
  while ! mkdir "$lock_dir" 2>/dev/null; do
    sleep 0.05
  done

  trap 'rmdir "$lock_dir" 2>/dev/null' EXIT

  if grep -q -E "^[[:space:]]*$1=" "$f"; then
    sed -i -E "s|^[[:space:]]*$1=.*|$1=$2|" "$f"
  else
    echo "$1=$2" >>"$f"
  fi

  chmod 600 "$f" 2>/dev/null || true
  rmdir "$lock_dir"
  trap - EXIT
}

# --- 重要文件路径 ---
SERVICE=${SERVICE:-"$MODDIR/service.sh"}
TPROXY=${TPROXY:-"$MODDIR/tproxy.sh"}
MONITOR=${MONITOR:-"$MODDIR/monitor.sh"}
LOGFILE=${LOGFILE:-"$PERSIST_DIR/$MODID.log"}
PIDFILE=${PIDFILE:-"$PERSIST_DIR/$MODID.pid"}
LOCK_FILE=${LOCK_FILE:-"$PERSIST_DIR/$MODID.lock"}

# --- 核心程序配置 ---
BIN_NAME=$(read_setting "BIN_NAME" "sing-box")
BIN_PATH=${BIN_PATH:-"$MODDIR/$BIN_NAME"}
BIN_LOG=${BIN_LOG:-"$PERSIST_DIR/$BIN_NAME.log"}
BIN_CONF=${BIN_CONF:-"$PERSIST_DIR/$(read_setting "BIN_CONFIG" "config.json")"}

# --- 代理用户配置 ---
TPROXY_USER=${TPROXY_USER:-"root:net_admin"}

# --- 环境与路径 ---
export PATH="$PATH:/data/adb/magisk:/data/adb/ksu/bin:/data/adb/ap/bin"
if type ui_print >/dev/null 2>&1; then IS_INSTALLER_ENV=1; else IS_INSTALLER_ENV=0; fi

# --- 日志与退出 ---
log_safe() {
  msg="$*"
  ts="[$(date +'%T')]"

  if [ "$IS_INSTALLER_ENV" = "1" ]; then
    ui_print "$ts $msg"
  else
    echo "$ts $msg"
    if [ -n "$LOGFILE" ]; then
      mkdir -p "$(dirname -- "$LOGFILE")" 2>/dev/null
      printf '%s %s\n' "$ts" "$msg" >>"$LOGFILE"
    fi
  fi
}

abort_safe() {
  msg="$*"
  ts="[$(date +'%T')]"

  if [ "$IS_INSTALLER_ENV" = "1" ] && type abort >/dev/null 2>&1; then
    abort "$ts $msg"
  else
    echo "$ts $msg" >&2
    [ -n "$LOGFILE" ] && printf '%s %s\n' "$ts" "$msg" >>"$LOGFILE"
    exit 1
  fi
}

# --- 模块状态更新 ---
update_desc() {
  icon="${1:-⛔}"
  prop="$MODDIR/module.prop"
  tmp="${prop}.new.$$"

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
  ' "$prop" >"$tmp" && mv -f "$tmp" "$prop"
}

# --- 提取用户/组ID ---
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
bg_run() {
  [ "$#" -ge 1 ] || {
    echo "Usage: bg_run CMD [ARGS...]" >&2
    return 1
  }

  : "${BG_RUN_LOG:=/dev/null}"
  umask 077

  if command -v busybox >/dev/null 2>&1 && busybox setuidgid 0 true 2>/dev/null; then
    setuid_cmd="busybox setuidgid $TPROXY_USER"
  else
    setuid_cmd="su -c"
  fi

  if command -v nohup >/dev/null 2>&1 && command -v setsid >/dev/null 2>&1; then
    nohup setsid ${setuid_cmd:+$setuid_cmd} "$@" </dev/null >"$BG_RUN_LOG" 2>&1 &
  elif command -v nohup >/dev/null 2>&1; then
    nohup ${setuid_cmd:+$setuid_cmd} "$@" </dev/null >"$BG_RUN_LOG" 2>&1 &
  elif command -v setsid >/dev/null 2>&1; then
    setsid ${setuid_cmd:+$setuid_cmd} "$@" </dev/null >"$BG_RUN_LOG" 2>&1 &
  else
    (
      trap '' HUP
      exec ${setuid_cmd:+$setuid_cmd} "$@"
    ) </dev/null >"$BG_RUN_LOG" 2>&1 &
  fi

  echo $!
}

# END of common.sh
