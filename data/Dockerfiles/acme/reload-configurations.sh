#!/bin/bash

# Direct caller identity is retained: curl executes in this service cgroup.
mailcow_control_curl() {
  if [[ "${MAILCOW_NATIVE_CONTROL:-0}" == "1" ]]; then
    curl --unix-socket /run/mailcow-control.sock "$@"
  else
    curl "$@"
  fi
}
if [[ "${MAILCOW_NATIVE_CONTROL:-0}" == "1" ]]; then
  MAILCOW_CONTROL_URL=http://localhost
else
  MAILCOW_CONTROL_URL="https://dockerapi.${COMPOSE_PROJECT_NAME}_mailcow-network"
fi

# Reading container IDs
# Wrapping as array to ensure trimmed content when calling $NGINX etc.
NGINX=($(mailcow_control_curl --silent --insecure ${MAILCOW_CONTROL_URL}/containers/json | jq -r ".[] | {name: .Config.Labels[\"com.docker.compose.service\"], project: .Config.Labels[\"com.docker.compose.project\"], id: .Id}" | jq -rc "select( .name | tostring | contains(\"nginx-mailcow\")) | select( .project | tostring | contains(\"${COMPOSE_PROJECT_NAME,,}\")) | .id" | tr "\n" " "))
DOVECOT=($(mailcow_control_curl --silent --insecure ${MAILCOW_CONTROL_URL}/containers/json | jq -r ".[] | {name: .Config.Labels[\"com.docker.compose.service\"], project: .Config.Labels[\"com.docker.compose.project\"], id: .Id}" | jq -rc "select( .name | tostring | contains(\"dovecot-mailcow\")) | select( .project | tostring | contains(\"${COMPOSE_PROJECT_NAME,,}\")) | .id" | tr "\n" " "))
POSTFIX=($(mailcow_control_curl --silent --insecure ${MAILCOW_CONTROL_URL}/containers/json | jq -r ".[] | {name: .Config.Labels[\"com.docker.compose.service\"], project: .Config.Labels[\"com.docker.compose.project\"], id: .Id}" | jq -rc "select( .name | tostring | contains(\"postfix-mailcow\")) | select( .project | tostring | contains(\"${COMPOSE_PROJECT_NAME,,}\")) | .id" | tr "\n" " "))

reload_nginx(){
  echo "Reloading Nginx..."
  NGINX_RELOAD_RET=$(mailcow_control_curl -X POST --insecure ${MAILCOW_CONTROL_URL}/containers/${NGINX}/exec -d '{"cmd":"reload", "task":"nginx"}' --silent -H 'Content-type: application/json' | jq -r .type)
  [[ ${NGINX_RELOAD_RET} != 'success' ]] && { echo "Could not reload Nginx, restarting container..."; restart_container ${NGINX} ; }
}

reload_dovecot(){
  echo "Reloading Dovecot..."
  DOVECOT_RELOAD_RET=$(mailcow_control_curl -X POST --insecure ${MAILCOW_CONTROL_URL}/containers/${DOVECOT}/exec -d '{"cmd":"reload", "task":"dovecot"}' --silent -H 'Content-type: application/json' | jq -r .type)
  [[ ${DOVECOT_RELOAD_RET} != 'success' ]] && { echo "Could not reload Dovecot, restarting container..."; restart_container ${DOVECOT} ; }
}

reload_postfix(){
  echo "Reloading Postfix..."
  POSTFIX_RELOAD_RET=$(mailcow_control_curl -X POST --insecure ${MAILCOW_CONTROL_URL}/containers/${POSTFIX}/exec -d '{"cmd":"reload", "task":"postfix"}' --silent -H 'Content-type: application/json' | jq -r .type)
  [[ ${POSTFIX_RELOAD_RET} != 'success' ]] && { echo "Could not reload Postfix, restarting container..."; restart_container ${POSTFIX} ; }
}

restart_container(){
  for container in $*; do
    echo "Restarting ${container}..."
    C_REST_OUT=$(mailcow_control_curl -X POST --insecure ${MAILCOW_CONTROL_URL}/containers/${container}/restart --silent | jq -r '.msg')
    echo "${C_REST_OUT}"
  done
}

if [[ "${CERT_AMOUNT_CHANGED}" == "1" ]]; then
  restart_container ${NGINX}
  restart_container ${DOVECOT}
  restart_container ${POSTFIX}
else
  reload_nginx
  #reload_dovecot
  restart_container ${DOVECOT}
  #reload_postfix
  restart_container ${POSTFIX}
fi
