#!/bin/sh
# Настройка хранилища: выполняется внутри пода openbao (kubectl exec -i ... -- env ... sh -s < bootstrap.sh).
# Ожидает переменные: BAO_TOKEN, PG_PASSWORD, ROLES (через пробел), NAMESPACE.
# token_ttl больше срока аренды (1 ч): при истечении токена сессии хранилище отзывает все выданные им аренды.
set -eu
export BAO_ADDR=http://127.0.0.1:8200

bao auth enable kubernetes >/dev/null
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc >/dev/null
bao secrets enable database >/dev/null

ALLOWED=$(echo "$ROLES" | tr ' ' ',')
bao write database/config/orders plugin_name=postgresql-database-plugin \
  allowed_roles="$ALLOWED" \
  connection_url="postgresql://{{username}}:{{password}}@postgres:5432/orders?sslmode=disable" \
  max_open_connections=20 max_idle_connections=20 \
  username=postgres password="$PG_PASSWORD" >/dev/null

for r in $ROLES; do
  bao write database/roles/$r db_name=orders \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE orders TO \"{{name}}\"; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP OWNED BY \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
    default_ttl=1h max_ttl=24h >/dev/null
  printf 'path "database/creds/%s" { capabilities = ["read"] }\n' "$r" | bao policy write "$r" - >/dev/null
  bao write auth/kubernetes/role/$r bound_service_account_names="$r" \
    bound_service_account_namespaces="$NAMESPACE" audience=openbao token_policies="$r" token_ttl=65m >/dev/null
done

printf 'path "sys/leases/revoke-prefix/database/creds/*" { capabilities = ["update", "sudo"] }\n' | bao policy write responder - >/dev/null
bao token create -policy=responder -period=24h -field=token
