#!/system/bin/sh
# =====================================================================
# 🔄 update-sub.sh - 订阅更新脚本
# =====================================================================

set -e

MODDIR=$(dirname "$0")
PERSIST_DIR=$(dirname "$0")
. "$MODDIR/common.sh"

log_safe "✨ === [update-sub] === ✨"

# --- Helper Functions ---
get_flag_for_country() {
  # Trim whitespace and convert to lowercase
  input=$(echo "$1" | tr '[:upper:]' '[:lower:]' | xargs)
  case "$input" in
  us | america) echo "🇺🇸" ;;
  hk | hong*) echo "🇭🇰" ;;
  jp | japan) echo "🇯🇵" ;;
  sg | singapore) echo "🇸🇬" ;;
  tw | taiwan) echo "🇹🇼" ;;
  kr | korea) echo "🇰🇷" ;;
  ad) echo "🇦🇩" ;; ae) echo "🇦🇪" ;; af) echo "🇦🇫" ;; ag) echo "🇦🇬" ;; ai) echo "🇦🇮" ;; al) echo "🇦🇱" ;; am) echo "🇦🇲" ;; ao) echo "🇦🇴" ;; aq) echo "🇦🇶" ;; ar) echo "🇦🇷" ;; as) echo "🇦🇸" ;; at) echo "🇦🇹" ;; au) echo "🇦🇺" ;; aw) echo "🇦🇼" ;; ax) echo "🇦🇽" ;; az) echo "🇦🇿" ;; ba) echo "🇧🇦" ;; bb) echo "🇧🇧" ;; bd) echo "🇧🇩" ;; be) echo "🇧🇪" ;; bf) echo "🇧🇫" ;; bg) echo "🇧🇬" ;; bh) echo "🇧🇭" ;; bi) echo "🇧🇮" ;; bj) echo "🇧🇯" ;; bl) echo "🇧🇱" ;; bm) echo "🇧🇲" ;; bn) echo "🇧🇳" ;; bo) echo "🇧🇴" ;; br) echo "🇧🇷" ;; bs) echo "🇧🇸" ;; bt) echo "🇧🇹" ;; bw) echo "🇧🇼" ;; by) echo "🇧🇾" ;; bz) echo "🇧🇿" ;; ca) echo "🇨🇦" ;; cd) echo "🇨🇩" ;; cf) echo "🇨🇫" ;; cg) echo "🇨🇬" ;; ch) echo "🇨🇭" ;; ci) echo "🇨🇮" ;; ck) echo "🇨🇰" ;; cl) echo "🇨🇱" ;; cm) echo "🇨🇲" ;; cn) echo "🇨🇳" ;; co) echo "🇨🇴" ;; cr) echo "🇨🇷" ;; cu) echo "🇨🇺" ;; cv) echo "🇨🇻" ;; cw) echo "🇨🇼" ;; cy) echo "🇨🇾" ;; cz) echo "🇨🇿" ;; de) echo "🇩🇪" ;; dj) echo "🇩🇯" ;; dk) echo "🇩🇰" ;; dm) echo "🇩🇲" ;; do) echo "🇩🇴" ;; dz) echo "🇩🇿" ;; ec) echo "🇪🇨" ;; ee) echo "🇪🇪" ;; eg) echo "🇪🇬" ;; er) echo "🇪🇷" ;; es) echo "🇪🇸" ;; et) echo "🇪🇹" ;; fi) echo "🇫🇮" ;; fj) echo "🇫🇯" ;; fk) echo "🇫🇰" ;; fm) echo "🇫🇲" ;; fo) echo "🇫🇴" ;; fr) echo "🇫🇷" ;; ga) echo "🇬🇦" ;; gb) echo "🇬🇧" ;; gd) echo "🇬🇩" ;; ge) echo "🇬🇪" ;; gf) echo "🇬🇫" ;; gg) echo "🇬🇬" ;; gh) echo "🇬🇭" ;; gi) echo "🇬🇮" ;; gl) echo "🇬🇱" ;; gm) echo "🇬🇲" ;; gn) echo "🇬🇳" ;; gp) echo "🇬🇵" ;; gq) echo "🇬🇶" ;; gr) echo "🇬🇷" ;; gt) echo "🇬🇹" ;; gu) echo "🇬🇺" ;; gw) echo "🇬🇼" ;; gy) echo "🇬🇾" ;; hn) echo "🇭🇳" ;; hr) echo "🇭🇷" ;; ht) echo "🇭🇹" ;; hu) echo "🇭🇺" ;; id) echo "🇮🇩" ;; ie) echo "🇮🇪" ;; il) echo "🇮🇱" ;; im) echo "🇮🇲" ;; in) echo "🇮🇳" ;; io) echo "🇮🇴" ;; iq) echo "🇮🇶" ;; ir) echo "🇮🇷" ;; is) echo "🇮🇸" ;; it) echo "🇮🇹" ;; je) echo "🇯🇪" ;; jm) echo "🇯🇲" ;; jo) echo "🇯🇴" ;; ke) echo "🇰🇪" ;; kg) echo "🇰🇬" ;; kh) echo "🇰🇭" ;; ki) echo "🇰🇮" ;; km) echo "🇰🇲" ;; kn) echo "🇰🇳" ;; kp) echo "🇰🇵" ;; kw) echo "🇰🇼" ;; ky) echo "🇰🇾" ;; kz) echo "🇰🇿" ;; la) echo "🇱🇦" ;; lb) echo "🇱🇧" ;; lc) echo "🇱🇨" ;; li) echo "🇱🇮" ;; lk) echo "🇱🇰" ;; lr) echo "🇱🇷" ;; ls) echo "🇱🇸" ;; lt) echo "🇱🇹" ;; lu) echo "🇱🇺" ;; lv) echo "🇱🇻" ;; ly) echo "🇱🇾" ;; ma) echo "🇲🇦" ;; mc) echo "🇲🇨" ;; md) echo "🇲🇩" ;; me) echo "🇲🇪" ;; mg) echo "🇲🇬" ;; mh) echo "🇲🇭" ;; mk) echo "🇲🇰" ;; ml) echo "🇲🇱" ;; mm) echo "🇲🇲" ;; mn) echo "🇲🇳" ;; mo) echo "🇲🇴" ;; mp) echo "🇲🇵" ;; mq) echo "🇲🇶" ;; mr) echo "🇲🇷" ;; ms) echo "🇲🇸" ;; mt) echo "🇲🇹" ;; mu) echo "🇲🇺" ;; mv) echo "🇲🇻" ;; mw) echo "🇲🇼" ;; mx) echo "🇲🇽" ;; my) echo "🇲🇾" ;; mz) echo "🇲🇿" ;; na) echo "🇳🇦" ;; nc) echo "🇳🇨" ;; ne) echo "🇳🇪" ;; nf) echo "🇳🇫" ;; ng) echo "🇳🇬" ;; ni) echo "🇳🇮" ;; nl) echo "🇳🇱" ;; no) echo "🇳🇴" ;; np) echo "🇳🇵" ;; nr) echo "🇳🇷" ;; nu) echo "🇳🇺" ;; nz) echo "🇳🇿" ;; om) echo "🇴🇲" ;; pa) echo "🇵🇦" ;; pe) echo "🇵🇪" ;; pf) echo "🇵🇫" ;; pg) echo "🇵🇬" ;; ph) echo "🇵🇭" ;; pk) echo "🇵🇰" ;; pl) echo "🇵🇱" ;; pm) echo "🇵🇲" ;; pn) echo "🇵🇳" ;; pr) echo "🇵🇷" ;; ps) echo "🇵🇸" ;; pt) echo "🇵🇹" ;; pw) echo "🇵🇼" ;; py) echo "🇵🇾" ;; qa) echo "🇶🇦" ;; re) echo "🇷🇪" ;; ro) echo "🇷🇴" ;; rs) echo "🇷🇸" ;; ru) echo "🇷🇺" ;; rw) echo "🇷🇼" ;; sa) echo "🇸🇦" ;; sb) echo "🇸🇧" ;; sc) echo "🇸🇨" ;; sd) echo "🇸🇩" ;; se) echo "🇸🇪" ;; sh) echo "🇸🇭" ;; si) echo "🇸🇮" ;; sk) echo "🇸🇰" ;; sl) echo "🇸🇱" ;; sm) echo "🇸🇲" ;; sn) echo "🇸🇳" ;; so) echo "🇸🇴" ;; sr) echo "🇸🇷" ;; ss) echo "🇸🇸" ;; st) echo "🇸🇹" ;; sv) echo "🇸🇻" ;; sx) echo "🇸🇽" ;; sy) echo "🇸🇾" ;; sz) echo "🇸🇿" ;; tc) echo "🇹🇨" ;; td) echo "🇹🇩" ;; tg) echo "🇹🇬" ;; th) echo "🇹🇭" ;; tj) echo "🇹🇯" ;; tk) echo "🇹🇰" ;; tl) echo "🇹🇱" ;; tm) echo "🇹🇲" ;; tn) echo "🇹🇳" ;; to) echo "🇹🇴" ;; tr) echo "🇹🇷" ;; tt) echo "🇹🇹" ;; tv) echo "🇹🇻" ;; tz) echo "🇹🇿" ;; ua) echo "🇺🇦" ;; ug) echo "🇺🇬" ;; uy) echo "🇺🇾" ;; uz) echo "🇺🇿" ;; va) echo "🇻🇦" ;; vc) echo "🇻🇨" ;; ve) echo "🇻🇪" ;; vg) echo "🇻🇬" ;; vi) echo "🇻🇮" ;; vn) echo "🇻🇳" ;; vu) echo "🇻🇺" ;; wf) echo "🇼🇫" ;; ws) echo "🇼🇸" ;; ye) echo "🇾🇪" ;; yt) echo "🇾🇹" ;; za) echo "🇿🇦" ;; zm) echo "🇿🇲" ;; zw) echo "🇿🇼" ;; *) echo "" ;; esac
}

get_country_code_from_api() {
  address=$1
  api_response=$(curl -s --connect-timeout 10 "$SUB_GEO_API/$address")
  curl_exit_code=$?

  if [ $curl_exit_code -ne 0 ]; then
    log_safe "❗ 网络波动, 无法连接到地理位置 API"
    echo "NETWORK_ERROR"
    return
  fi

  # Check if the response is valid JSON with a success status and a country code
  country_code=$(echo "$api_response" | jq -r 'if .status == "success" and .countryCode then .countryCode else empty end')

  if [ -n "$country_code" ]; then
    log_safe "💡 成功获取地理位置: $country_code"
    echo "$country_code"
  else
    log_safe "❗ 地理位置 API 错误: $(echo "$api_response" | jq -c .)"
    echo "API_ERROR"
  fi
}

# Function to URL-decode a string in a POSIX-compliant way
URLDecode() {
  awk '
    BEGIN {
        hextab["0"] = 0; hextab["1"] = 1; hextab["2"] = 2; hextab["3"] = 3;
        hextab["4"] = 4; hextab["5"] = 5; hextab["6"] = 6; hextab["7"] = 7;
        hextab["8"] = 8; hextab["9"] = 9; hextab["a"] = 10; hextab["b"] = 11;
        hextab["c"] = 12; hextab["d"] = 13; hextab["e"] = 14; hextab["f"] = 15;
        hextab["A"] = 10; hextab["B"] = 11; hextab["C"] = 12; hextab["D"] = 13;
        hextab["E"] = 14; hextab["F"] = 15;
    }
    {
        decoded = "";
        for (i = 1; i <= length($0); ++i) {
            if (substr($0, i, 1) == "%" && i + 2 <= length($0)) {
                hex1 = tolower(substr($0, i + 1, 1));
                hex2 = tolower(substr($0, i + 2, 1));
                if (hex1 in hextab && hex2 in hextab) {
                    decoded = decoded sprintf("%c", hextab[hex1] * 16 + hextab[hex2]);
                    i += 2;
                } else {
                    decoded = decoded "%" ; # Invalid hex, pass through
                }
            } else {
                decoded = decoded substr($0, i, 1);
            }
        }
        print decoded;
    }'
}

# --- Main Functions ---

# Helper function to parse common URI components for ss, trojan, vless
# Exports DECODED_TAG, SERVER, PORT, USER_INFO as global variables
parse_standard_uri() {
  link="$1"
  proto="$2"
  # Extract fragment as tag and URL-decode it
  DECODED_TAG=$(echo "$link" | sed -n 's/.*#\(.*\)/\1/p' | URLDecode)
  # Extract server address
  SERVER=$(echo "$link" | sed -n "s/${proto}:\/\/\([^@]*\)@\([^:]*\):.*/\2/p")
  # Extract port
  PORT=$(echo "$link" | sed -n 's/.*:\([0-9]*\).*/\1/p')
  # Extract user info (password, uuid, or encoded ss part)
  USER_INFO=$(echo "$link" | sed -n "s/${proto}:\/\/\([^@]*\)@.*/\1/p")
}

# Function to parse vmess links
parse_vmess() {
  link=$1
  json_str=$(echo "${link#vmess://}" | base64 -d 2>/dev/null || true)

  if [ -z "$json_str" ]; then
    log_safe "❗ Failed to parse Vmess link: Invalid Base64."
    return 1
  fi

  # Extract fields into shell variables
  tag=$(echo "$json_str" | jq -r '.ps')
  server=$(echo "$json_str" | jq -r '.add')
  port=$(echo "$json_str" | jq -r '.port')
  uuid=$(echo "$json_str" | jq -r '.id')
  aid=$(echo "$json_str" | jq -r '.aid')
  security=$(echo "$json_str" | jq -r '.scy // "auto"')
  net=$(echo "$json_str" | jq -r '.net')
  vmess_type=$(echo "$json_str" | jq -r '.type')
  host=$(echo "$json_str" | jq -r '.host')
  path=$(echo "$json_str" | jq -r '.path')
  tls=$(echo "$json_str" | jq -r '.tls')
  sni=$(echo "$json_str" | jq -r '.sni // .host')

  # Filter unsupported transport protocols for sing-box
  if [ "$net" = "kcp" ] || [ "$net" = "mkcp" ] || [ "$net" = "domainsocket" ]; then
    log_safe "❗ 不支持的 vmess 传输协议 '$net', 跳过链接"
    return 1
  fi

  # Construct the JSON output using jq -n
  jq -n \
    --arg tag "$tag" \
    --arg server "$server" \
    --arg port "$port" \
    --arg uuid "$uuid" \
    --arg aid "$aid" \
    --arg security "$security" \
    --arg net "$net" \
    --arg vmess_type "$vmess_type" \
    --arg host "$host" \
    --arg path "$path" \
    --arg tls "$tls" \
    --arg sni "$sni" \
    --arg tfo "$SUB_TFO" \
    --arg udp "$SUB_UDP_FRAGMENT" \
    --arg aead "$SUB_VMESS_AEAD" \
    '
    # Base object
    {
        "tag": $tag,
        "type": "vmess",
        "server": $server,
        "server_port": ($port | tonumber),
        "uuid": $uuid,
        "security": $security,
        "alter_id": (if $aead == "true" then 0 else ($aid | tonumber) end),
        "tcp_fast_open": ($tfo == "true"),
        "udp_fragment": ($udp == "true")
    } |
    # TLS object
    (
        if $tls == "tls" then
            .tls = { "enabled": true, "server_name": $sni }
        else .
        end
    ) |
    # Transport object
    (
        if $net == "ws" then
            .transport = { "type": "ws", "path": $path, "headers": { "Host": $host } }
        elif $net == "h2" or ($net == "tcp" and $vmess_type == "http") then
            .transport = { "type": "http", "path": $path, "host": $host }
        elif $net == "quic" then
            .transport = { "type": "quic" }
        # For raw TCP, transport is null and will be removed by the walk
        else .
        end
    ) |
    # Cleanup
    walk(if type == "object" then with_entries(select(.value != null and .value != "" and .value != {})) else . end)
    '
}

# Function to parse trojan links
parse_trojan() {
  link=$1
  parse_standard_uri "$link" "trojan"
  password=$USER_INFO

  # Extract query parameters
  query=$(echo "$link" | sed -n 's/.*\?//p')
  sni=$(echo "$query" | sed -n 's/.*sni=\([^&]*\).*/\1/p')
  allow_insecure=$(echo "$query" | sed -n 's/.*allowInsecure=\([^&]*\).*/\1/p')
  fp=$(echo "$query" | sed -n 's/.*fp=\([^&]*\).*/\1/p')
  alpn=$(echo "$query" | sed -n 's/.*alpn=\([^&]*\).*/\1/p' | URLDecode)
  type=$(echo "$query" | sed -n 's/.*type=\([^&]*\).*/\1/p')
  host=$(echo "$query" | sed -n 's/.*host=\([^&]*\).*/\1/p')
  path=$(echo "$query" | sed -n 's/.*path=\([^&]*\).*/\1/p' | URLDecode)
  serviceName=$(echo "$query" | sed -n 's/.*serviceName=\([^&]*\).*/\1/p' | URLDecode)

  # Construct the JSON output
  jq -n \
    --arg tag "$DECODED_TAG" \
    --arg server "$SERVER" \
    --arg port "$PORT" \
    --arg password "$password" \
    --arg tfo "$SUB_TFO" \
    --arg udp "$SUB_UDP_FRAGMENT" \
    --arg sni "$sni" \
    --arg allow_insecure "$allow_insecure" \
    --arg fp "$fp" \
    --arg alpn "$alpn" \
    --arg type "$type" \
    --arg host "$host" \
    --arg path "$path" \
    --arg serviceName "$serviceName" \
    '
    # Base object
    {
        "type": "trojan",
        "tag": $tag,
        "server": $server,
        "server_port": ($port | tonumber),
        "password": $password,
        "tcp_fast_open": ($tfo == "true"),
        "udp_fragment": ($udp == "true")
    } |
    # TLS object
    (
        if $sni != "" or ($allow_insecure | test("1|true")) or $fp != "" or $alpn != "" then
            .tls = { "enabled": true } |
            if $sni != "" then .tls.server_name = $sni else . end |
            if $allow_insecure | test("1|true") then .tls.insecure = true else . end |
            if $fp != "" then .tls.utls = { "enabled": true, "fingerprint": $fp } else . end |
            if $alpn != "" then .tls.alpn = ($alpn | split(",")) else . end
        else .
        end
    ) |
    # Transport object
    (
        if $type == "ws" then
            .transport = {
                "type": "ws",
                "path": $path,
                "headers": { "Host": $host }
            }
        elif $type == "grpc" then
            .transport = {
                "type": "grpc",
                "service_name": $serviceName
            }
        else .
        end
    ) |
    # Cleanup
    walk(if type == "object" then with_entries(select(.value != null and .value != "" and .value != {})) else . end)
    '
}

# Function to parse ss links
parse_ss() {
  link=$1
  parse_standard_uri "$link" "ss"

  # Decode the method and password
  decoded_part=$(echo "$USER_INFO" | base64 -d 2>/dev/null || true)
  if [ -z "$decoded_part" ]; then
    log_safe "❗ Failed to parse SS link: Invalid Base64."
    return 1
  fi
  method=$(echo "$decoded_part" | cut -d: -f1)
  password=$(echo "$decoded_part" | cut -d: -f2-)

  # Extract plugin info from query parameters
  query=$(echo "$link" | sed -n 's/.*\?//p')
  plugin_str=$(echo "$query" | sed -n 's/.*plugin=\([^&]*\).*/\1/p' | URLDecode)

  # Parse v2ray-plugin options for WebSocket transport
  # Example: v2ray-plugin;mode=websocket;host=example.com;path=/ws;tls
  transport_type=""
  path=""
  host=""
  tls_enabled="false"

  if echo "$plugin_str" | grep -q "v2ray-plugin" && echo "$plugin_str" | grep -q "mode=websocket"; then
    transport_type="ws"
    path=$(echo "$plugin_str" | sed -n 's/.*path=\([^;]*\).*/\1/p')
    host=$(echo "$plugin_str" | sed -n 's/.*host=\([^;]*\).*/\1/p')
    if echo "$plugin_str" | grep -q "tls"; then
      tls_enabled="true"
    fi
  fi
  # Note: Other plugins/modes like obfs or grpc are not currently supported for SS links.

  # Construct the JSON output
  jq -n \
    --arg tag "$DECODED_TAG" \
    --arg server "$SERVER" \
    --arg port "$PORT" \
    --arg method "$method" \
    --arg password "$password" \
    --arg tfo "$SUB_TFO" \
    --arg udp "$SUB_UDP_FRAGMENT" \
    --arg transport_type "$transport_type" \
    --arg path "$path" \
    --arg host "$host" \
    --arg tls_enabled "$tls_enabled" \
    '
    # Base object
    {
        "type": "shadowsocks",
        "tag": $tag,
        "server": $server,
        "server_port": ($port | tonumber),
        "method": $method,
        "password": $password,
        "tcp_fast_open": ($tfo == "true"),
        "udp_fragment": ($udp == "true")
    } |
    # Transport object
    (
        if $transport_type == "ws" then
            .transport = {
                "type": "ws",
                "path": $path,
                "headers": { "Host": $host }
            }
        else .
        end
    ) |
    # TLS object
    (
        if $tls_enabled == "true" then
            .tls = {
                "enabled": true,
                "server_name": (if $host != "" then $host else $server end)
            }
        else .
        end
    ) |
    # Cleanup
    walk(if type == "object" then with_entries(select(.value != null and .value != "" and .value != {})) else . end)
    '
}

# Function to parse vless links
parse_vless() {
  link=$1
  parse_standard_uri "$link" "vless"
  uuid=$USER_INFO

  # Extract query parameters
  query=$(echo "$link" | sed -n 's/.*\?//p')
  security=$(echo "$query" | sed -n 's/.*security=\([^&]*\).*/\1/p')
  sni=$(echo "$query" | sed -n 's/.*sni=\([^&]*\).*/\1/p')
  fp=$(echo "$query" | sed -n 's/.*fp=\([^&]*\).*/\1/p')
  pbk=$(echo "$query" | sed -n 's/.*pbk=\([^&]*\).*/\1/p')
  sid=$(echo "$query" | sed -n 's/.*sid=\([^&]*\).*/\1/p')
  flow=$(echo "$query" | sed -n 's/.*flow=\([^&]*\).*/\1/p')
  alpn=$(echo "$query" | sed -n 's/.*alpn=\([^&]*\).*/\1/p' | URLDecode)
  type=$(echo "$query" | sed -n 's/.*type=\([^&]*\).*/\1/p')
  host=$(echo "$query" | sed -n 's/.*host=\([^&]*\).*/\1/p')
  path=$(echo "$query" | sed -n 's/.*path=\([^&]*\).*/\1/p' | URLDecode)
  serviceName=$(echo "$query" | sed -n 's/.*serviceName=\([^&]*\).*/\1/p' | URLDecode)

  # Construct the JSON output
  jq -n \
    --arg tag "$DECODED_TAG" \
    --arg server "$SERVER" \
    --arg port "$PORT" \
    --arg uuid "$uuid" \
    --arg tfo "$SUB_TFO" \
    --arg udp "$SUB_UDP_FRAGMENT" \
    --arg security "$security" \
    --arg sni "$sni" \
    --arg fp "$fp" \
    --arg pbk "$pbk" \
    --arg sid "$sid" \
    --arg flow "$flow" \
    --arg alpn "$alpn" \
    --arg type "$type" \
    --arg host "$host" \
    --arg path "$path" \
    --arg serviceName "$serviceName" \
    '
    # Base object
    {
        "type": "vless",
        "tag": $tag,
        "server": $server,
        "server_port": ($port | tonumber),
        "uuid": $uuid,
        "tcp_fast_open": ($tfo == "true"),
        "udp_fragment": ($udp == "true")
    } |
    # Flow
    (if $flow != "" then .flow = $flow else . end) |
    # TLS object
    (
        if $security == "tls" or $security == "reality" then
            .tls = { "enabled": true } |
            if $sni != "" then .tls.server_name = $sni else . end |
            # VLESS over TLS is insecure by default, Reality is secure.
            (if $security == "tls" then .tls.insecure = true else . end) |
            (if $fp != "" then .tls.utls = { "enabled": true, "fingerprint": $fp } else . end) |
            (if $alpn != "" then .tls.alpn = ($alpn | split(",")) else . end) |
            (if $security == "reality" and $pbk != "" then
                .tls.reality = { "enabled": true, "public_key": $pbk } |
                if $sid != "" then .tls.reality.short_id = $sid else . end
            else . end)
        else .
        end
    ) |
    # Transport object
    (
        if $type == "ws" then
            .transport = {
                "type": "ws",
                "path": $path,
                "headers": { "Host": $host }
            }
        elif $type == "grpc" then
            .transport = {
                "type": "grpc",
                "service_name": $serviceName
            }
        else .
        end
    ) |
    # Cleanup
    walk(if type == "object" then with_entries(select(.value != null and .value != "" and .value != {})) else . end)
    '
}

# --- Main Processing Logic ---
process_node() {
  line=$1
  node_json=""
  # tolower for protocol matching
  proto=$(echo "${line%%://*}" | tr '[:upper:]' '[:lower:]')

  case "$proto" in
  vmess) node_json=$(parse_vmess "$line") ;;
  trojan) node_json=$(parse_trojan "$line") ;;
  ss) node_json=$(parse_ss "$line") ;;
  vless) node_json=$(parse_vless "$line") ;;
  *)
    log_safe "🤔 未知协议: ${proto}, 正在跳过"
    return
    ;;
  esac

  # If parsing failed, skip
  [ -z "$node_json" ] && return

  # --- Extract Info & Filter ---
  tag=$(echo "$node_json" | jq -r '.tag')
  server=$(echo "$node_json" | jq -r '.server')
  port=$(echo "$node_json" | jq -r '.server_port')

  # Unified filter for invalid, informational, or local nodes
  if [ -z "$server" ] || [ "$server" = "null" ] || [ -z "$port" ] || [ "$port" = "null" ] ||
    echo "$server" | grep -E -q '^(127\.0\.0\.1|localhost)$' ||
    echo "$tag" | grep -E -q '流量|到期|官网|群组|时间|重置|剩余|应急|过期|禁用|测试'; then
    log_safe "🔄 过滤无效信息节点: $tag"
    return
  fi

  if [ -n "$SUB_FILTER_REGEX" ]; then
    # Loop through each regex pattern (newline-separated)
    while IFS= read -r regex; do
      if [ -n "$regex" ] && echo "$tag" | grep -E "$regex" >/dev/null; then
        log_safe "🔄 根据 $regex 过滤节点: $tag"
        return # Exit process_node function
      fi
    done <<<"$SUB_FILTER_REGEX"
  fi

  log_safe "📌 当前处理: $tag $server $port"

  # --- Deduplication ---
  if [ "$SUB_DEDUPE" = "true" ]; then
    # Create a unique signature and check against a single file
    signature=$(echo "$node_json" | jq -c '{protocol, server, server_port}' | base64)

    is_duplicate=false
    # Use a while-read loop for portability instead of grep -Fx
    if [ -f "$DEDUPE_FILE" ]; then
      while IFS= read -r line; do
        if [ "$line" = "$signature" ]; then
          is_duplicate=true
          break
        fi
      done <"$DEDUPE_FILE"
    fi

    if [ "$is_duplicate" = "true" ]; then
      log_safe "🔄 去重节点: $tag"
      return
    else
      echo "$signature" >>"$DEDUPE_FILE"
    fi
  fi

  # --- Rename with Country Flag ---
  if [ "$SUB_COUNTRY_FLAG" = "true" ] && ! grep -qE '(?:\xF0\x9F\x87[\xA6-\xBF]){2}' <<<"$tag"; then
    country_code_result=""
    if [ -n "$SUB_GEO_API" ] && [ -n "$server" ]; then
      log_safe "🔍 查询节点位置: $server"
      country_code_result=$(get_country_code_from_api "$server")
      case "$country_code_result" in
      API_ERROR)
        log_safe "❌ 无法通过 API 确定节点位置: $tag (将尝试从名称解析)"
        country_code_result="" # Clear the result and fall through
        ;;
      NETWORK_ERROR)
        log_safe "❗ 查询节点位置时网络错误, 将尝试从名称解析: $tag"
        country_code_result=""
        ;; # Fall through
      esac
    fi

    # Fallback to parsing from tag if API fails
    if [ -z "$country_code_result" ]; then
      if echo "$tag" | grep -E "$GROUP_JP" >/dev/null; then
        country_code_result="JP"
      elif echo "$tag" | grep -E "$GROUP_HK" >/dev/null; then
        country_code_result="HK"
      elif echo "$tag" | grep -E "$GROUP_TW" >/dev/null; then
        country_code_result="TW"
      elif echo "$tag" | grep -E "$GROUP_US" >/dev/null; then
        country_code_result="US"
      elif echo "$tag" | grep -E "$GROUP_SG" >/dev/null; then
        country_code_result="SG"
      elif echo "$tag" | grep -E "$GROUP_KR" >/dev/null; then
        country_code_result="KR"
      fi
    fi

    if [ -n "$country_code_result" ]; then
      flag=$(get_flag_for_country "$country_code_result")
      if [ -n "$flag" ]; then
        new_tag="${flag} ${tag}"
        node_json=$(echo "$node_json" | jq --arg new_tag "$new_tag" '.tag = $new_tag')
        tag=$new_tag # Update tag for logging/grouping
        log_safe "🏷️ 节点已重命名为: $new_tag"
      fi
    fi
  fi

  # Append the processed node to the temporary subscription file
  echo "$node_json" >>"$TMP_SUB_FILE"
}

# --- Main Workflow Functions ---
check_dependencies() {
  if ! command -v jq >/dev/null 2>&1; then
    log_safe "❌ 未找到 'jq' 命令, 请确保它在您的 PATH 中"
    exit 1
  fi
  if ! command -v base64 >/dev/null 2>&1; then
    log_safe "❌ 未找到 'base64' 命令, 无法解码"
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    log_safe "❌ 未找到 'curl' 命令, 无法下载"
    exit 1
  fi
}

load_settings() {
  ENABLE_SUBSCRIBE=$(read_setting "ENABLE_SUBSCRIBE" "false")
  SUB_URL=$(read_setting "SUB_URL" "")
  SUB_DEDUPE=$(read_setting "SUB_DEDUPE" "true")
  SUB_TFO=$(read_setting "SUB_TFO" "true")
  SUB_VMESS_AEAD=$(read_setting "SUB_VMESS_AEAD" "true")
  SUB_UDP_FRAGMENT=$(read_setting "SUB_UDP_FRAGMENT" "true")
  SUB_COUNTRY_FLAG=$(read_setting "SUB_COUNTRY_FLAG" "true")
  SUB_FILTER_REGEX=$(read_setting "SUB_FILTER_REGEX" "")
  SUB_GEO_API=$(read_setting "SUB_GEO_API" "")
}

setup_cleanup() {
  TMPDIR=$(mktemp -d "$PERSIST_DIR/.tmp.sub.XXXXXX")
  trap 'log_safe "🧹 清理临时文件"; rm -rf "$TMPDIR";' 0
  trap 'exit 1' 1 2 3 15 # exit on INT, QUIT, TERM, HUP
}

download_subscription() {
  log_safe "📥 正在下载订阅"
  SUB_RAW_PATH="$TMPDIR/sub.raw"
  if ! curl -sSL --connect-timeout 15 -m 30 "$SUB_URL" -o "$SUB_RAW_PATH"; then
    log_safe "❌ 订阅下载失败"
    exit 1
  fi
  log_safe "💡 订阅下载成功"
}

decode_subscription() {
  log_safe "🔗 解码订阅内容"
  SUB_DECODED_PATH="$TMPDIR/sub.decoded"
  # Try to decode base64, if it fails, assume it's plain text
  if ! base64 -d "$SUB_RAW_PATH" >"$SUB_DECODED_PATH" 2>/dev/null; then
    log_safe "❗ Base64 解码失败, 将作为纯文本处理"
    cp "$SUB_RAW_PATH" "$SUB_DECODED_PATH"
  fi

  # --- Parse & Group ---
  log_safe "🔍 解析和分组节点信息"
  GROUP_JP='[Jj][Pp]|[Jj]apan|🇯🇵|日|东京|大阪'
  GROUP_HK='[Hh][Kk]|[Hh]ong|🇭🇰|港'
  GROUP_TW='[Tt][Ww]|[Tt]aiwan|🇹🇼|台'
  GROUP_US='[Uu][Ss]|[Aa]merica|🇺🇸|美'
  GROUP_SG='[Ss][Gg]|[Ss]ingapore|🇸🇬|新'
  GROUP_KR='[Kk][Rr]|[Kk]orea|🇰🇷|韩'
}

initialize_temp_files() {
  log_safe "🔧 初始化临时文件"
  NODES_JSON_PATH="$TMPDIR/nodes.json"
  DEDUPE_FILE="$TMPDIR/seen_signatures.txt"

  echo "[]" >"$NODES_JSON_PATH"
  touch "$DEDUPE_FILE"
}

# Loops through decoded subscription links and processes each one.
process_subscription_links() {
  log_safe "🔨 正在处理订阅链接"
  while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines
    [ -z "$line" ] && continue
    process_node "$line"
  done <"$SUB_DECODED_PATH"
  log_safe "💡 所有链接处理完毕"
}

# Deploys the generated JSON files with validation and backup.
deploy_files() {
  log_safe "🚀 部署更新..."
  nodes_file="$PERSIST_DIR/sub-nodes.json"
  groups_file="$PERSIST_DIR/sub-groups.json"

  # 1. Validate generated JSON files
  if ! jq . "$nodes_file" >/dev/null 2>&1 || ! jq . "$groups_file" >/dev/null 2>&1; then
    log_safe "❌ 生成的 JSON 文件无效！部署中止"
    return 1
  fi
  log_safe "✔️ 生成的 JSON 文件有效"

  # 2. Backup existing config file
  if [ -f "$BIN_CONF" ]; then
    cp "$BIN_CONF" "$BIN_CONF.bak"
    log_safe "🛡️ 已备份现有配置文件 -> $BIN_CONF.bak"
  fi

  # 3. Atomically update the config file with new nodes and groups
  jq --slurpfile new_nodes "$nodes_file" \
    --slurpfile new_regional_groups "$groups_file" \
    '
    # Define variables for clarity
    ( .outbounds | map(select(.protocol)) | map(.tag) ) as $old_node_tags |
    ( $new_nodes[0] ) as $new_nodes_array |
    ( $new_nodes_array | map(.tag) ) as $all_new_node_tags |
    ( $new_regional_groups[0] ) as $new_regional_groups_array |
    ( $new_regional_groups_array | map(.tag) ) as $new_regional_group_tags |

    # Main update logic for the outbounds array
    .outbounds |= (
        # Start with existing groups, removing old nodes from top level
        map(select(.protocol | not)) |

        # Update each group based on its tag
        map(
            if .tag == "Auto" or .tag == "Available" then
                # For Auto/Available, replace outbounds with all new node tags
                .outbounds = $all_new_node_tags
            else
                # For other groups (e.g., Google), clean old subscription tags from their outbounds
                .outbounds |= map(select(. as $t | $old_node_tags | index($t) | not))
            end
        ) |

        # Remove old regional groups from the list; they will be replaced by the new ones
        map(select(.tag as $t | $new_regional_group_tags | index($t) | not))
    ) | 

    # Add the new, updated regional groups and all new nodes
    .outbounds += $new_regional_groups_array + $new_nodes_array
  ' \
    "$BIN_CONF" >"$BIN_CONF.tmp" && mv "$BIN_CONF.tmp" "$BIN_CONF"

  log_safe "🎉 订阅更新成功！新配置已写入 $BIN_CONF"
}

# --- Main Execution ---
main() {
  # The script execution is wrapped in a main function to provide a clear
  # entry point and structure. 'set -e' ensures that the script will exit
  # immediately if a command fails.

  # Load dependencies and settings first
  check_dependencies
  load_settings

  # Exit early if subscription is disabled
  if [ "$ENABLE_SUBSCRIBE" != "true" ] || [ -z "$SUB_URL" ]; then
    log_safe "🚫 订阅更新已禁用或未设置 URL, 正在跳过"
    exit 0
  fi

  # Core workflow
  setup_cleanup
  download_subscription
  decode_subscription
  initialize_temp_files
  process_subscription_links
  deploy_files
}

# --- Run ---
main
