#!/usr/bin/env bash
# heain-access live test 4d: heain-access v2 on heain-sdk v1 with heain-database, against a real
# heain-core node. The AI sidecars are the TEST-ONLY stub (-test-stub-sidecars) so the flow runs
# without model weights; with the real sidecars running on 127.0.0.1:9700-9702, start heain-access
# without the flag (same endpoints, same records).
#  - enrolment keeps templates only, sealed under a per-subject key from core's KMS;
#  - face / fingerprint / ID-card decisions each file a signed reasoning record with a model hash;
#  - ID-card registry and keycard ACL are datasets in heain-database (uses[] db.dataset.lookup);
#  - Stage B-3a: keycard swipes get an advisory anomaly score (Isolation Forest over the card's own
#    history); a flagged swipe goes to an Approver (P5 access.keycard_review) and the ACL still decides;
#  - grants need a fresh, single-use verification and are signed; check / revoke;
#  - removing a subject destroys its key (crypto-shred); retention ends templates; data survives
#    a restart; calls outside the identity lane are refused.
# Needs ~/heain-core, ~/heain-sdk, ~/heain-database. ~2 min.  Run from ~/heain-access:  bash scripts/live_4d.sh
set -uo pipefail
AC=$(cd "$(dirname "$0")/.." && pwd)
DB=${HEAIN_DATABASE_DIR:-$HOME/heain-database}
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
[ -d "$DB" ] || { echo "needs $DB"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/access-4d
URL=https://127.0.0.1:18000
AURL=https://127.0.0.1:19480
DURL=https://127.0.0.1:19460
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
cl() { curl -sk --noproxy '*' --cert "$W/client.pem" --key "$W/client.key" --cacert "$C/ca.pem" "$@"; }
idl() { cl -H 'X-Heain-Lane: identity' "$@"; }      # calls in heain-access's identity lane
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
b64() { printf '%s' "$1" | base64 -w0; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
runapp() { # <instance> <manifest> <port> <state> <binary> [args...]
  local inst=$1 man=$2 port=$3 st=$4; shift 4; mkdir -p "$st"
  HEAIN_MANIFEST=$man HEAIN_INSTANCE=$inst HEAIN_CORE_URL=$URL HEAIN_CORE_ID=G HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
  HEAIN_STATE_DIR=$st HEAIN_ENROLL_TOKEN=$W/$inst.tok HEAIN_ENDPOINT_BASE=https://127.0.0.1:$port HEAIN_LISTEN=127.0.0.1:$port \
    nohup "$@" >> "$W/$inst.log" 2>&1 &
  echo $! > "$P/$inst.pid"; }
pending() { as approver-1 $URL/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='$1')"; }
until_ok() { for i in $(seq 1 ${2:-20}); do eval "$1" && return 0; sleep 1; done; return 1; }
audit() { as admin "$URL/v1/admin/audit?limit=1000&from=${1:-1}"; }
allaudit() { # every record, a page of 1000 at a time, through files (a whole chain is too long for an argument)
  local f=1 n; : > "$W/audit.jsonl"
  while :; do audit $f > "$W/audit.page"; n=$(j "len(d['records'])" < "$W/audit.page")
    [ "${n:-0}" -gt 0 ] || break; cat "$W/audit.page" >> "$W/audit.jsonl"; echo >> "$W/audit.jsonl"; [ "$n" -lt 1000 ] && break; f=$((f+1000)); done
  python3 -c "import json,sys;r=[];[r.extend(json.loads(l)['records']) for l in open(sys.argv[1]) if l.strip()];print(json.dumps({'records':r}))" "$W/audit.jsonl"; }

echo "== 0. core node G; build heain-access and heain-database"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
: > "$L/G.log"
nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
( cd "$AC" && GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/heain-access" ./cmd/heain-access ) && ( cd "$DB" && GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/heain-database" ./cmd/heain-database ) \
  && ok "heain-access and heain-database build" || { bad "build"; exit 1; }
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
as admin -X POST -H 'Content-Type: application/json' -d '{"label":"client.c1"}' $URL/provision/token > "$W/c1.json"
python3 - "$W" <<'PY'
import json,sys; w=sys.argv[1]; d=json.load(open(w+"/c1.json"))
open(w+"/c1.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(w+"/c1.boot.key","w").write(d["bootstrap_key_pem"]); open(w+"/c1.token","w").write(d["token"])
PY
openssl genrsa -out "$W/client.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/client.key" -subj "/CN=client.c1" -out "$W/client.csr" >/dev/null 2>&1
python3 -c "import json;print(json.dumps({'token':open('$W/c1.token').read(),'csr_pem':open('$W/client.csr').read()}))" > "$W/c1.req"
curl -sk --noproxy '*' --cert "$W/c1.boot.pem" --key "$W/c1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/c1.req" $URL/provision/csr \
  | python3 -c "import json,sys;open('$W/client.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"

echo "== 1. heain-database and heain-access start and are admitted"
for i in d1 a1; do as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"heain-$([ $i = d1 ] && echo database || echo access).$i\"}" $URL/provision/token > "$W/$i.tok"; done
runapp d1 "$DB/heain-app.yaml" 19460 "$W/state-d1" "$W/heain-database" -external-dialect sqlite
runapp a1 "$AC/heain-app.yaml" 19480 "$W/state-a1" "$W/heain-access" -test-stub-sidecars
for k in $(seq 1 40); do for a in $(pending app.register); do code approver-1 -X POST $URL/v1/admin/policy/$a/approve >/dev/null; done
  grep -q "heain-database: active" "$W/d1.log" && grep -q "heain-access: active" "$W/a1.log" && break; sleep 1; done
grep -q "heain-access: active" "$W/a1.log" && grep -q "heain-database: active" "$W/d1.log" && ok "both admitted (P5 app.register) and serving" || { bad "start: $(tail -2 "$W/a1.log") $(tail -2 "$W/d1.log")"; $H stop-all >/dev/null 2>&1; exit 1; }
cl -o /dev/null -X POST -d '{"scope_key":"default","records":[{"record_key":"card-0042","value":{"allowed":true}},{"record_key":"card-0666","value":{"allowed":false}}]}' $DURL/v1/datasets/keycards/import
cl -o /dev/null -X POST -d '{"scope_key":"bkk-9","records":[{"record_key":"1100500012345","value":{"eligible":true}},{"record_key":"1100500099999","value":{"eligible":false}}]}' $DURL/v1/datasets/voters/import
ok "keycard ACL and voter registry imported into heain-database"

echo "== 2. face: enrolment keeps a sealed template, matching files reasoning records"
r=$(idl -X POST -d "{\"subject\":\"1100500012345\",\"image_b64\":\"$(b64 face:somchai)\"}" $AURL/v1/enroll/face -w '\n%{http_code}')
[ "$(echo "$r" | tail -1)" = 201 ] && ok "face enrolled (expires $(echo "$r" | head -1 | j "d['expires_at'][:10]"))" || bad "enroll: $r"
[ "$(cl -o /dev/null -w '%{http_code}' -X POST -d "{\"subject\":\"1100500012345\",\"image_b64\":\"$(b64 face:somchai)\"}" $AURL/v1/verify/face)" = 400 ] && ok "a call outside the identity lane is refused (lane_violation)" || bad "lane"
r=$(idl -X POST -d "{\"subject\":\"1100500012345\",\"image_b64\":\"$(b64 face:somchai:at-the-gate)\"}" $AURL/v1/verify/face)
VID=$(echo "$r" | j "d.get('verification_id','')")
[ "$(echo "$r" | j "d['allow']")" = True ] && [ -n "$VID" ] && ok "same person, another photo -> allow (similarity $(echo "$r" | j "d['confidence']"))" || bad "verify same: $r"
r=$(idl -X POST -d "{\"subject\":\"1100500012345\",\"image_b64\":\"$(b64 face:impostor)\"}" $AURL/v1/verify/face)
[ "$(echo "$r" | j "d['allow']")" = False ] && ok "another person -> deny ($(echo "$r" | j "d['reason']"))" || bad "verify other: $r"
[ "$(idl -o /dev/null -w '%{http_code}' -X POST -d "{\"subject\":\"nobody\",\"image_b64\":\"$(b64 face:x)\"}" $AURL/v1/verify/face)" = 404 ] && ok "a subject never enrolled -> 404 not_enrolled" || bad "not enrolled"
[ "$(allaudit | j "sum(1 for x in d['records'] if x['event']['Action']=='ai.reasoning_record' and x['event']['Detail']['record']['capability']['name'] in ('identity.enroll.face','identity.verify.face') and len(x['event']['Detail']['record']['model'].get('artifact_sha256',''))==64)")" = 3 ] \
  && ok "enrol + 2 decisions = 3 signed reasoning records with the model hash (the 404 needs none)" || bad "face records"

echo "== 3. fingerprint, ID card with registry, keycard with ACL"
idl -o /dev/null -X POST -d "{\"subject\":\"emp-77\",\"image_b64\":\"$(b64 finger:emp77)\"}" $AURL/v1/enroll/fingerprint
[ "$(idl -X POST -d "{\"subject\":\"emp-77\",\"image_b64\":\"$(b64 finger:emp77:again)\"}" $AURL/v1/verify/fingerprint | j "d['allow']")" = True ] \
  && [ "$(idl -X POST -d "{\"subject\":\"emp-77\",\"image_b64\":\"$(b64 finger:someone)\"}" $AURL/v1/verify/fingerprint | j "d['allow']")" = False ] && ok "fingerprint: same finger allowed, another refused" || bad "fingerprint"
card() { idl -X POST -d "{\"image_b64\":\"$(b64 "BATR PRACHACHON 1 1005 $1 2")\",\"expected_id_number\":\"$2\",\"registry\":{\"dataset\":\"voters\",\"scope_key\":\"bkk-9\"}}" $AURL/v1/verify/id-card; }
[ "$(card 00123 4 | j "d['allow']")" = False ] && ok "ID card whose number does not match the card -> deny" || bad "idcard mismatch"
r=$(card 00123 1100500123); [ "$(echo "$r" | j "d['reason']")" = "not in the registry" ] && ok "number read but not in the voter registry -> deny" || bad "registry miss: $r"
idc() { idl -X POST -d "{\"image_b64\":\"$(b64 "BATR $1")\",\"expected_id_number\":\"$1\",\"registry\":{\"dataset\":\"voters\",\"scope_key\":\"bkk-9\"}}" $AURL/v1/verify/id-card; }
[ "$(idc 1100500012345 | j "d['allow']")" = True ] && [ "$(idc 1100500099999 | j "d['reason']")" = "listed in the registry as not eligible" ] && ok "registry (heain-database): eligible -> allow, ineligible -> deny" || bad "registry"
kc() { idl -X POST -d "{\"uid\":\"$1\"}" $AURL/v1/verify/keycard | j "d['allow']"; }
[ "$(kc card-0042)" = True ] && [ "$(kc card-0666)" = False ] && [ "$(kc card-9999)" = False ] && ok "keycards checked against the ACL in heain-database (allowed / revoked / unknown)" || bad "keycards"
[ "$(allaudit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Actor'].startswith('heain-database.') and x['event']['Detail'].get('app_actor','').startswith('heain-access.') and x['event']['Detail'].get('capability')=='db.dataset.lookup')")" -ge 5 ] \
  && ok "heain-database audited each lookup as a call from heain-access (uses[] db.dataset.lookup)" || bad "lookup audit"

echo "== 3b. keycard anomaly signal (B-3a): three weeks of history, then a usual and an unusual swipe"
cl -o /dev/null -X POST -d "{\"scope_key\":\"default\",\"records\":[$(for c in 1 2 3 4 5 6; do printf '{"record_key":"kc-0%d","value":{"allowed":true}},' $c; done | sed 's/,$//')]}" $DURL/v1/datasets/keycards/import
swipe() { idl -X POST -d "{\"uid\":\"$1\",\"reader\":\"$2\",\"at\":\"$3\"}" $AURL/v1/verify/keycard; }
MON=$(date -u -d "last monday -21 days" +%Y-%m-%d)
for d in $(seq 0 18); do
  day=$(date -u -d "$MON +$d days" +%Y-%m-%d); [ "$(date -u -d "$day" +%u)" -ge 6 ] && continue
  for c in 1 2 3 4 5 6; do
    swipe kc-0$c lobby "${day}T08:$(printf %02d $(( (c*7+d*3) % 50 + 5 )))":00Z >/dev/null
    swipe kc-0$c garage "${day}T17:$(printf %02d $(( (c*5+d) % 30 + 20 )))":00Z >/dev/null
  done
done
R0=$(allaudit | j "sum(1 for x in d['records'] if x['event']['Action']=='ai.reasoning_record' and x['event']['Detail']['record']['capability']['name']=='identity.verify.keycard' and x['event']['Detail']['record']['model']['name']=='keycard-iforest')")
[ "${R0:-0}" -ge 150 ] && ok "$R0 swipes of 6 cards over three weeks, each with a signed reasoning record (model keycard-iforest)" || bad "history records: $R0"
U=$(swipe kc-01 lobby "$(date -u -d "$MON +21 days" +%Y-%m-%d)T08:41:00Z")
O=$(swipe kc-01 server-room "$(date -u -d "$MON +20 days" +%Y-%m-%d)T03:10:00Z")
[ "$(echo "$U" | j "d['allow'], d['anomaly']['status'], d['anomaly']['flagged']")" = "True scored False" ] && [ "$(echo "$O" | j "d['allow'], d['anomaly']['flagged']")" = "True True" ] \
  && ok "a usual morning swipe scores $(echo "$U" | j "d['anomaly']['score']") (not flagged); the server room at 03:10 on a Sunday scores $(echo "$O" | j "d['anomaly']['score']") -- flagged, yet still allowed: the ACL decides" || bad "anomaly: usual $U unusual $O"
RA=$(echo "$O" | j "d['review_action_id']")
[ -n "$RA" ] && [ "$(as approver-1 $URL/v1/admin/policy/pending | j "[a['Type'] for a in d['actions'] if a['ID']=='$RA'][0]")" = access.keycard_review ] \
  && ok "the flagged swipe went to an Approver (P5 access.keycard_review); heain-access acts on nothing itself" || bad "review: $RA"
X=$(swipe kc-99 server-room "$(date -u -d "$MON +20 days" +%Y-%m-%d)T03:12:00Z")
[ "$(echo "$X" | j "d['allow'], d['anomaly']['status']")" = "False insufficient_history" ] && ok "a card not on the ACL is denied whatever the model says (no history: not scored)" || bad "gate: $X"
! grep -rqaF -e kc-01 -e server-room "$W/state-a1" && ok "swipe history sealed: no card id or reader in heain-access's files" || bad "keycard plaintext at rest"

echo "== 4. grants: fresh single-use verification, signed, check, revoke"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ); LATER=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
r=$(cl -X POST -d "{\"recipient\":\"1100500012345\",\"asset_ref\":\"polling-station-9\",\"valid_from\":\"$NOW\",\"valid_until\":\"$LATER\",\"verification_id\":\"$VID\"}" $AURL/v1/grants -w '\n%{http_code}')
G=$(echo "$r" | head -1 | j "d['id']")
[ "$(echo "$r" | tail -1)" = 201 ] && [ "$(echo "$r" | head -1 | j "len(d['signature_b64'])>0 and d['verification_method']")" = face ] && ok "grant issued against the face verification, signed by heain-access" || bad "grant: $r"
[ "$(cl -o /dev/null -w '%{http_code}' -X POST -d "{\"recipient\":\"x\",\"asset_ref\":\"a\",\"valid_from\":\"$NOW\",\"valid_until\":\"$LATER\",\"verification_id\":\"$VID\"}" $AURL/v1/grants)" = 403 ] && ok "the same verification cannot issue a second grant (403)" || bad "reuse"
[ "$(cl -X POST -d '{"asset_ref":"polling-station-9"}' $AURL/v1/grants/$G/check | j "d['valid']")" = True ] && [ "$(cl -X POST -d '{"asset_ref":"polling-station-8"}' $AURL/v1/grants/$G/check | j "d['valid']")" = False ] && ok "check: valid for its asset, not for another" || bad "check"
cl -o /dev/null -X DELETE $AURL/v1/grants/$G
[ "$(cl -X POST -d '{"asset_ref":"polling-station-9"}' $AURL/v1/grants/$G/check | j "d['reason']")" = revoked ] && ok "revoked grant -> invalid (revoked)" || bad "revoke"
[ "$(cl -o /dev/null -w '%{http_code}' -X POST -d '{"evidence":{}}' $AURL/v1/plugins/dcp-key/kdm)" = 501 ] && ok "dcp-key plugin not enabled -> 501 (industry plugin is optional)" || bad "plugin"

echo "== 5. no images or ids at rest; restart; removal is crypto-shred; retention"
! grep -rqaF -e 1100500012345 -e emp-77 -e "face:somchai" -e "finger:emp77" -e Bangrak "$W/state-a1" && ok "heain-access's files hold no subject id or image (templates sealed, ids blinded)" || bad "plaintext at rest"
! audit | grep -q -e 1100500012345 -e emp-77 && ok "no subject id in core's audit" || bad "id in audit"
kill -TERM "$(cat "$P/a1.pid")"; sleep 2; runapp a1 "$AC/heain-app.yaml" 19480 "$W/state-a1" "$W/heain-access" -test-stub-sidecars
until_ok '[ "$(grep -c "heain-access: active" "$W/a1.log")" -ge 2 ]' 30
[ "$(idl -X POST -d "{\"subject\":\"emp-77\",\"image_b64\":\"$(b64 finger:emp77)\"}" $AURL/v1/verify/fingerprint | j "d['allow']")" = True ] && ok "after a restart enrolled templates still match (keys from core)" || bad "restart"
[ "$(idl -X DELETE $AURL/v1/subjects/1100500012345 | j "d['removed']")" = True ] && [ "$(idl -o /dev/null -w '%{http_code}' -X POST -d "{\"subject\":\"1100500012345\",\"image_b64\":\"$(b64 face:somchai)\"}" $AURL/v1/verify/face)" = 404 ] \
  && [ "$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.key_destroyed' and x['event']['Detail']['key_id'].startswith('subj-'))")" = 1 ] && ok "subject removed: its key destroyed in core (crypto-shred), no longer matches" || bad "remove"
kill -TERM "$(cat "$P/a1.pid")"; sleep 2; runapp a1 "$AC/heain-app.yaml" 19480 "$W/state-a1" "$W/heain-access" -test-stub-sidecars -retention 3s
until_ok '[ "$(grep -c "heain-access: active" "$W/a1.log")" -ge 3 ]' 30
idl -o /dev/null -X POST -d "{\"subject\":\"short-lived\",\"image_b64\":\"$(b64 face:temp)\"}" $AURL/v1/enroll/face; sleep 4
[ "$(idl -o /dev/null -w '%{http_code}' -X POST -d "{\"subject\":\"short-lived\",\"image_b64\":\"$(b64 face:temp)\"}" $AURL/v1/verify/face)" = 404 ] && ok "a template past its retention is not used (404)" || bad "retention"
[ "$(as admin "$URL/v1/admin/audit/verify" | j "d['ok']")" = True ] && ok "core audit chain verifies" || bad "audit verify"

echo "== cleanup"
for i in a1 d1; do kill -TERM "$(cat "$P/$i.pid")" 2>/dev/null; done; sleep 2
$H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"
