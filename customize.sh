#!/system/bin/sh
# =====================================================================
# 🔧 customize.sh - 安装初始化脚本
# =====================================================================

set -e

# 安装环境下 MODPATH 指向模块解压临时目录
MODPATH=${MODPATH:-$(dirname "$0")}
. "$MODPATH/common.sh"

log_safe "✨ === [customize] ==="
log_safe "📂 模块临时路径: $MODPATH"
log_safe "📂 持久化数据路径: $PERSIST_DIR"

# 1. 停止旧实例
if [ -d "/data/adb/modules/$MODID" ]; then
  if [ -f "$LOGFILE" ]; then
    log_safe "📝 备份旧日志文件..."
    mv -f "$LOGFILE" "$LOGFILE.bak" 2>/dev/null
  fi
  log_safe "🔄 升级中: 停止旧服务..."
  if [ -x "$SERVICE" ]; then
    sh "$SERVICE" stop >/dev/null 2>&1 || log_safe "❓ 代理服务可能未完全停止"
  fi

  # 使用 pkill 终止残留进程, 更可靠
  if command -v pkill >/dev/null 2>&1; then
    log_safe "🔍 终止残留的 '$BIN_NAME' 进程..."
    pkill -9 -f "$BIN_NAME.*$MODID" 2>/dev/null || true
  fi
  sleep 1
else
  log_safe "📦 全新安装模块..."
fi

# 2. 确保持久化目录
if [ ! -d "$PERSIST_DIR" ]; then
  log_safe "📁 创建持久化目录: $PERSIST_DIR"
  mkdir -p "$PERSIST_DIR"
fi

# 3. 迁移用户文件
for f in config.json settings.conf github_token; do
  if [ -f "$MODPATH/$f" ] && [ ! -f "$PERSIST_DIR/$f" ]; then
    log_safe "📄 迁移文件 '$f' 到持久化目录..."
    mv "$MODPATH/$f" "$PERSIST_DIR/"
  fi
done
set_perm_recursive "$PERSIST_DIR" 0 0 0755 0600

# 4. 设置模块文件权限
log_safe "🔒 设置模块文件权限..."
set_perm_recursive "$MODPATH" 0 0 0755 0644

# 5. 设置脚本和核心程序的可执行权限
log_safe "🚀 设置可执行权限..."
for script in "$MODPATH"/*.sh; do
  [ -f "$script" ] && set_perm "$script" 0 0 0755
done
if [ -f "$MODPATH/$BIN_NAME" ]; then
  set_perm "$MODPATH/$BIN_NAME" 0 0 0755
fi

log_safe "✨ 安装完成, 请修改配置并重启设备"
