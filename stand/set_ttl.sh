#!/bin/sh
# Срок аренды роли для испытаний: sh stand/set_ttl.sh <роль> <срок, например 120s>
set -eu
ROLE=$1
TTL=$2
NS=${NAMESPACE:-credshield}
K="kubectl --context ${KUBE_CONTEXT:-kind-vkr} -n $NS"
BT=$($K get secret bao-root -o jsonpath='{.data.token}' | base64 -d)
$K exec -i deploy/openbao -c openbao -- env BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$BT" ROLE="$ROLE" TTL="$TTL" sh -s <<'EOS'
bao write database/roles/$ROLE db_name=orders \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE orders TO \"{{name}}\"; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP OWNED BY \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl=$TTL max_ttl=1h >/dev/null
EOS
