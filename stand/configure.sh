#!/bin/sh
# Настройка хранилища с рабочего места: bootstrap.sh внутри пода, затем токен сервиса реагирования в Secret.
# Повторный запуск нужен после каждого перезапуска пода openbao (режим разработки хранит данные в памяти).
set -eu
NS=${NAMESPACE:-credshield}
CTX=${KUBE_CONTEXT:-kind-vkr}
K="kubectl --context $CTX -n $NS"
HERE=$(dirname "$0")
BT=$($K get secret bao-root -o jsonpath='{.data.token}' | base64 -d)
PG=$($K get secret postgres-admin -o jsonpath='{.data.password}' | base64 -d)
TOK=$($K exec -i deploy/openbao -c openbao -- env BAO_TOKEN="$BT" PG_PASSWORD="$PG" ROLES="${ROLES:-orders billing bench}" NAMESPACE="$NS" sh -s < "$HERE/bootstrap.sh")
$K delete secret responder-token --ignore-not-found >/dev/null
$K create secret generic responder-token --from-literal=token="$TOK"
