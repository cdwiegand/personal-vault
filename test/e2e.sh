#!/usr/bin/env bash
# End-to-end test of the OAuth discovery -> DCR -> login -> token -> MCP call flow.
# Usage: test/e2e.sh   (builds the project, starts it on a loopback port, drives the full flow)
set -u
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
SP="$(mktemp -d)"
VAULT="$SP/testvault"
PORT=5099
BASE="http://127.0.0.1:$PORT"
ISS="https://localhost:$PORT"          # issuer/audience the tokens are minted with
RURI="https://claude.ai/api/mcp/auth_callback"
PASS="test-pass-123"
KEY="$(openssl rand -base64 32)"

echo "== building =="
dotnet build "$PROJ" -clp:NoSummary >/dev/null || { echo "build failed"; exit 1; }
DLL="$(find "$PROJ/bin" -name PersonalMcpVault.dll | head -1)"

mkdir -p "$VAULT/Daily"
printf '# Roadmap\n\nShip the vault server.\n' > "$VAULT/Roadmap.md"
printf 'Standup notes for today.\n' > "$VAULT/Daily/2026-08-29.md"

echo "== starting server =="
Vault__Root="$VAULT" Vault__AllowDelete=true \
Auth__PublicBaseUrl="$ISS" Auth__Username="chris" Auth__Password="$PASS" \
Auth__JwtSigningKey="$KEY" Auth__StorePath="$SP/oauth-store.db" \
ASPNETCORE_URLS="$BASE" ASPNETCORE_ENVIRONMENT=Production \
dotnet "$DLL" > "$SP/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$SP"' EXIT

curl -s --retry 40 --retry-connrefused --retry-delay 1 --max-time 5 "$BASE/" >/dev/null \
  || { echo "server never came up"; cat "$SP/server.log"; exit 1; }
echo "server up (pid $SRV)"

pass=0; fail=0
check() { if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass=$((pass+1)); else echo "  FAIL: $3 (got '$1' want '$2')"; fail=$((fail+1)); fi; }

echo "== 1. discovery =="
curl -s "$BASE/.well-known/oauth-protected-resource" > "$SP/prm.json"
curl -s "$BASE/.well-known/oauth-protected-resource/mcp" | python3 -c 'import sys,json;json.load(sys.stdin)' && echo "  PRM/mcp ok"
curl -s "$BASE/.well-known/oauth-authorization-server" | python3 -m json.tool >/dev/null && echo "  AS metadata ok"
RES=$(python3 -c 'import json;print(json.load(open("'"$SP"'/prm.json"))["resource"])')
check "$RES" "$ISS/mcp" "PRM.resource == issuer/mcp"

echo "== 2. unauthenticated /mcp must 401 with WWW-Authenticate =="
HDRS=$(curl -s -o /dev/null -D - -X POST "$BASE/mcp" -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}')
check "$(printf '%s' "$HDRS" | head -1 | awk '{print $2}')" "401" "POST /mcp unauthenticated -> 401"
printf '%s' "$HDRS" | grep -qi 'www-authenticate: *bearer.*resource_metadata=' && { echo "  PASS: WWW-Authenticate has resource_metadata"; pass=$((pass+1)); } || { echo "  FAIL: WWW-Authenticate header"; fail=$((fail+1)); }

echo "== 3. dynamic client registration =="
CID=$(curl -s -X POST "$BASE/register" -H 'content-type: application/json' \
  --data '{"client_name":"Claude","redirect_uris":["'"$RURI"'"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}' \
  | tee "$SP/reg.json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["client_id"])')
[ -n "$CID" ] && { echo "  PASS: got client_id $CID"; pass=$((pass+1)); } || { echo "  FAIL: no client_id"; fail=$((fail+1)); }
python3 -c 'import json;d=json.load(open("'"$SP"'/reg.json"));assert "client_secret" not in d;print("  PASS: no client_secret (public client)")' && pass=$((pass+1))

echo "== 4. PKCE + authorize (GET shows login page) =="
VERIFIER=$(openssl rand -base64 60 | tr -d '=+/' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=')
ENC() { python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$1"; }
AUTHQ="response_type=code&client_id=$CID&redirect_uri=$(ENC "$RURI")&code_challenge=$CHALLENGE&code_challenge_method=S256&state=xyz123&scope=vault%20offline_access&resource=$(ENC "$ISS/mcp")"
GET_CODE=$(curl -s -o "$SP/login.html" -w '%{http_code}' "$BASE/authorize?$AUTHQ")
check "$GET_CODE" "200" "GET /authorize -> 200 login page"
grep -qi 'name="password"' "$SP/login.html" && { echo "  PASS: login form rendered"; pass=$((pass+1)); } || { echo "  FAIL: no login form"; fail=$((fail+1)); }

echo "== 5. submit login -> 302 with code =="
LOC=$(curl -s -o /dev/null -D - -X POST "$BASE/authorize" \
  --data-urlencode "username=chris" --data-urlencode "password=$PASS" \
  --data-urlencode "response_type=code" --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=$RURI" --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" --data-urlencode "state=xyz123" \
  --data-urlencode "scope=vault offline_access" --data-urlencode "resource=$ISS/mcp" \
  | grep -i '^location:' | tr -d '\r' | sed 's/[Ll]ocation: //')
CODE_PARAM=$(printf '%s' "$LOC" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
STATE_PARAM=$(printf '%s' "$LOC" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p')
[ -n "$CODE_PARAM" ] && { echo "  PASS: got auth code"; pass=$((pass+1)); } || { echo "  FAIL: no code"; fail=$((fail+1)); }
check "$STATE_PARAM" "xyz123" "state round-trips"

echo "== 5b. wrong password is rejected =="
WCODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/authorize" \
  --data-urlencode "username=chris" --data-urlencode "password=wrong" \
  --data-urlencode "response_type=code" --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=$RURI" --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" --data-urlencode "scope=vault")
check "$WCODE" "401" "wrong password -> 401"

echo "== 6. token exchange (authorization_code + PKCE) =="
curl -s -X POST "$BASE/token" \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$CODE_PARAM" \
  --data-urlencode "redirect_uri=$RURI" --data-urlencode "client_id=$CID" \
  --data-urlencode "code_verifier=$VERIFIER" --data-urlencode "resource=$ISS/mcp" > "$SP/token.json"
ACCESS=$(python3 -c 'import json;print(json.load(open("'"$SP"'/token.json"))["access_token"])' 2>/dev/null)
REFRESH=$(python3 -c 'import json;print(json.load(open("'"$SP"'/token.json")).get("refresh_token") or "")' 2>/dev/null)
[ -n "$ACCESS" ] && { echo "  PASS: got access_token"; pass=$((pass+1)); } || { echo "  FAIL: no access_token"; fail=$((fail+1)); cat "$SP/token.json"; }
[ -n "$REFRESH" ] && { echo "  PASS: got refresh_token"; pass=$((pass+1)); } || { echo "  FAIL: no refresh_token"; fail=$((fail+1)); }

echo "== 6b. reused auth code must fail with invalid_grant =="
REUSE=$(curl -s -X POST "$BASE/token" \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$CODE_PARAM" \
  --data-urlencode "redirect_uri=$RURI" --data-urlencode "client_id=$CID" \
  --data-urlencode "code_verifier=$VERIFIER" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("error",""))')
check "$REUSE" "invalid_grant" "reused code -> invalid_grant"

echo "== 7. authenticated MCP: initialize + tools/list + read_file =="
mcp() { curl -s -X POST "$BASE/mcp" -H "authorization: Bearer $ACCESS" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' --data "$1"; }
I_CODE=$(curl -s -o "$SP/init.out" -w '%{http_code}' -X POST "$BASE/mcp" -H "authorization: Bearer $ACCESS" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}')
check "$I_CODE" "200" "authenticated initialize -> 200"

TL=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
for t in read_file write_file search_content list_allowed_directories; do
  printf '%s' "$TL" | grep -q "\"$t\"" && { echo "  PASS: tool $t listed"; pass=$((pass+1)); } || { echo "  FAIL: tool $t missing"; fail=$((fail+1)); }
done

RF=$(mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"Roadmap.md"}}}')
printf '%s' "$RF" | grep -q 'Ship the vault server' && { echo "  PASS: read_file returned vault content"; pass=$((pass+1)); } || { echo "  FAIL: read_file"; fail=$((fail+1)); }

echo "== 8. path traversal must be blocked =="
ESC=$(mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../../../etc/passwd"}}}')
printf '%s' "$ESC" | grep -qi 'root:.*:0:0' && { echo "  FAIL: traversal LEAKED /etc/passwd"; fail=$((fail+1)); } || { echo "  PASS: traversal blocked"; pass=$((pass+1)); }

echo "== 9. refresh token grant + rotation =="
curl -s -X POST "$BASE/token" --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH" --data-urlencode "client_id=$CID" > "$SP/refresh.json"
NEW_ACCESS=$(python3 -c 'import json;print(json.load(open("'"$SP"'/refresh.json")).get("access_token") or "")' 2>/dev/null)
[ -n "$NEW_ACCESS" ] && { echo "  PASS: refresh produced new access_token"; pass=$((pass+1)); } || { echo "  FAIL: refresh"; fail=$((fail+1)); }
OLD_REUSE=$(curl -s -X POST "$BASE/token" --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("error",""))')
check "$OLD_REUSE" "invalid_grant" "old refresh token invalidated after rotation"

echo ""
echo "==================== RESULT: $pass passed, $fail failed ===================="
exit $fail
