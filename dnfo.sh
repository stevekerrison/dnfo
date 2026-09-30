#!/usr/bin/env bash
#
# Docker Netfilter Firewall Operator
#
# Monitors Docker events and installs nftables rules inside the network
# namespaces of containers configured through DNFO labels.
#
# Required commands:
#   docker
#   jq
#   nft
#   nsenter
#   ip
#   flock
#   mktemp
#
# This program must run as root.
#

set -Eeuo pipefail
IFS=$'\n\t'

readonly PROGRAM_NAME="${0##*/}"
readonly DEFAULT_TABLE_NAME="dnfo_firewall_table"
readonly LOCK_DIR="/run/dnfo"
readonly LOCK_FILE="${LOCK_DIR}/operator.lock"

EVENT_RETRY_ATTEMPTS="${DNFO_EVENT_RETRY_ATTEMPTS:-10}"
EVENT_RETRY_DELAY="${DNFO_EVENT_RETRY_DELAY:-0.25}"
DOCKER_RECONNECT_DELAY="${DNFO_DOCKER_RECONNECT_DELAY:-2}"


###############################################################################
# Logging and validation
###############################################################################

log()
{
    local level="$1"
    shift

    printf '%s [%s] %s\n' \
        "$(date --iso-8601=seconds)" \
        "$level" \
        "$*" >&2
}

die()
{
    log "ERROR" "$*"
    exit 1
}

require_root()
{
    if [[ "$EUID" -ne 0 ]]; then
        die "This program must run as root"
    fi
}

require_commands()
{
    local command_name

    for command_name in \
        docker \
        jq \
        nft \
        nsenter \
        ip \
        flock \
        mktemp \
        sed \
        grep \
        sort \
        tr
    do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            die "Required command not found: ${command_name}"
        fi
    done
}

validate_boolean()
{
    case "${1,,}" in
        true|false)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

validate_policy()
{
    case "${1,,}" in
        accept|drop)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

validate_table_name()
{
    local table_name="$1"

    [[ "$table_name" =~ ^[A-Za-z_][A-Za-z0-9_]{0,63}$ ]]
}


###############################################################################
# Docker inspection helpers
###############################################################################

label_from_json()
{
    local inspect_json="$1"
    local label_name="$2"

    jq -r \
        --arg label "$label_name" \
        '.[0].Config.Labels[$label] // empty' \
        <<<"$inspect_json"
}

container_pid_from_json()
{
    local inspect_json="$1"

    jq -r '.[0].State.Pid // 0' <<<"$inspect_json"
}

container_running_from_json()
{
    local inspect_json="$1"

    jq -r '.[0].State.Running // false' <<<"$inspect_json"
}

container_name_from_json()
{
    local inspect_json="$1"

    jq -r \
        '.[0].Name // empty | ltrimstr("/")' \
        <<<"$inspect_json"
}

container_id_from_json()
{
    local inspect_json="$1"

    jq -r '.[0].Id // empty' <<<"$inspect_json"
}


###############################################################################
# Docker network handling
###############################################################################

split_network_list()
{
    #
    # Accept comma-separated, whitespace-separated, or multiline values.
    #
    tr ',\r\t ' '\n\n\n\n' |
        sed '/^[[:space:]]*$/d' |
        sort -u
}

network_is_listed()
{
    local network_name="$1"
    local network_list="$2"

    [[ -n "$network_list" ]] &&
        grep -Fxq -- "$network_name" <<<"$network_list"
}

resolve_interface_for_network()
{
    local inspect_json="$1"
    local network_name="$2"
    local pid="$3"

    local endpoint_mac
    local interface_name

    endpoint_mac="$(
        jq -r \
            --arg network "$network_name" \
            '.[0].NetworkSettings.Networks[$network].MacAddress // empty' \
            <<<"$inspect_json"
    )"

    if [[ -z "$endpoint_mac" ]]; then
        log "WARN" \
            "Network '${network_name}' has no endpoint MAC address"
        return 1
    fi

    interface_name="$(
	nsenter --target "$pid" --net ip -j link show |
	jq -r \
		--arg mac "${endpoint_mac,,}" '
		.[]
		| select((.address // "") | ascii_downcase == $mac)
		| .ifname
		' |
	head -n1
    )"

    if [[ -z "$interface_name" ]]; then
        log "WARN" \
            "Could not resolve interface for Docker network '${network_name}'"
        return 1
    fi

    printf '%s\n' "$interface_name"
}

build_input_network_rules()
{
    local inspect_json="$1"
    local pid="$2"
    local include_value="$3"
    local ignore_value="$4"

    local include_networks
    local ignore_networks
    local network_name
    local interface_name
    local should_accept

    include_networks="$(split_network_list <<<"$include_value")"
    ignore_networks="$(split_network_list <<<"$ignore_value")"

    while IFS= read -r network_name; do
        [[ -n "$network_name" ]] || continue

        should_accept="false"

        #
        # Interpretation:
        #
        # dnfo.input.ignore:
        #   Networks ignored by the input firewall receive an iifname accept
        #   rule.
        #
        # dnfo.input.include:
        #   When non-empty, only listed networks remain subject to the input
        #   firewall. All networks not listed receive an accept rule.
        #
        # Include takes precedence if a network appears in both lists.
        #
        if [[ -n "$include_networks" ]]; then
            if ! network_is_listed \
                "$network_name" \
                "$include_networks"; then

                should_accept="true"
            fi
        elif network_is_listed \
            "$network_name" \
            "$ignore_networks"; then

            should_accept="true"
        fi

        [[ "$should_accept" == "true" ]] || continue

        if interface_name="$(
            resolve_interface_for_network \
                "$inspect_json" \
                "$network_name" \
                "$pid"
        )"; then
            printf \
                '        iifname "%s" accept comment "dnfo ignored network %s"\n' \
                "$interface_name" \
                "$network_name"
        fi
    done < <(
        jq -r \
            '.[0].NetworkSettings.Networks | keys[]?' \
            <<<"$inspect_json"
    )
}


###############################################################################
# nftables ruleset generation
###############################################################################

indent_rules()
{
    local rules="$1"
    local rule

    [[ -n "$rules" ]] || return 0

    while IFS= read -r rule; do
        [[ -n "$rule" ]] || continue
        printf '        %s\n' "$rule"
    done <<<"$rules"
}

emit_table_deletion()
{
    local table_name="$1"

    #
    # This replaces:
    #
    #     destroy table inet TABLE
    #
    # for compatibility with nftables versions that do not support destroy.
    #
    # "add table" does not fail if the table already exists. It ensures that
    # the following delete command always has a table to delete.
    #
    printf 'add table inet %s\n' "$table_name"
    printf 'delete table inet %s\n' "$table_name"
}

emit_managed_table_cleanup()
{
    local table_name="$1"

    #
    # Always delete the default table. This cleans up stale state when a
    # container changes from the default table name to a custom table name.
    #
    emit_table_deletion "$DEFAULT_TABLE_NAME"

    #
    # Delete the configured table when it differs from the default.
    #
    if [[ "$table_name" != "$DEFAULT_TABLE_NAME" ]]; then
        printf '\n'
        emit_table_deletion "$table_name"
    fi
}

generate_standard_ruleset()
{
    local inspect_json="$1"
    local pid="$2"
    local table_name="$3"
    local defaults_enabled="$4"
    local input_policy="$5"
    local forward_policy="$6"
    local output_policy="$7"
    local input_ignore="$8"
    local input_include="$9"
    local input_rules="${10}"
    local forward_rules="${11}"
    local output_rules="${12}"

    emit_managed_table_cleanup "$table_name"
    printf '\n\n'

    printf 'create table inet %s {\n' "$table_name"

    printf '    chain input {\n'
    printf \
        '        type filter hook input priority filter; policy %s;\n' \
        "$input_policy"

    if [[ "$defaults_enabled" == "true" ]]; then
        printf '%s\n' \
            '        ct state invalid drop' \
            '        ct state established,related accept' \
            '        iifname "lo" accept'
    fi

    build_input_network_rules \
        "$inspect_json" \
        "$pid" \
        "$input_include" \
        "$input_ignore"

    indent_rules "$input_rules"

    printf '    }\n\n'

    printf '    chain forward {\n'
    printf \
        '        type filter hook forward priority filter; policy %s;\n' \
        "$forward_policy"

    if [[ "$defaults_enabled" == "true" ]]; then
        printf '%s\n' \
            '        ct state invalid drop' \
            '        ct state established,related accept'
    fi

    indent_rules "$forward_rules"

    printf '    }\n\n'

    printf '    chain output {\n'
    printf \
        '        type filter hook output priority filter; policy %s;\n' \
        "$output_policy"

    if [[ "$defaults_enabled" == "true" ]]; then
        printf '%s\n' \
            '        ct state invalid drop' \
            '        ct state established,related accept'
    fi

    indent_rules "$output_rules"

    printf '    }\n'
    printf '}\n'
}

generate_custom_chains_ruleset()
{
    local table_name="$1"
    local custom_chains="$2"
    local line

    emit_managed_table_cleanup "$table_name"
    printf '\n\n'

    printf 'create table inet %s {\n' "$table_name"

    while IFS= read -r line; do
        printf '    %s\n' "$line"
    done <<<"$custom_chains"

    printf '}\n'
}

generate_remove_ruleset()
{
    local table_name="$1"

    emit_managed_table_cleanup "$table_name"
}


###############################################################################
# nftables transaction handling
###############################################################################

apply_nft_file()
{
    local pid="$1"
    local rules_file="$2"
    local container_description="$3"

    #
    # Validate the complete transaction without committing it.
    #
    if ! nsenter --target "$pid" --net \
        nft --check --file "$rules_file"; then

        log "ERROR" \
            "nft transaction validation failed for ${container_description}"
        return 1
    fi

    #
    # All commands in this file are submitted by one nft invocation and
    # committed as one nftables transaction.
    #
    if ! nsenter --target "$pid" --net \
        nft --file "$rules_file"; then

        log "ERROR" \
            "nft transaction failed for ${container_description}"
        return 1
    fi
}

remove_managed_tables()
{
    local pid="$1"
    local table_name="$2"
    local container_description="$3"

    local rules_file

    if ! validate_table_name "$table_name"; then
        log "ERROR" \
            "Refusing invalid nftables table name: ${table_name}"
        return 1
    fi

    rules_file="$(
        mktemp --tmpdir="$LOCK_DIR" dnfo-remove.XXXXXX
    )"

    chmod 0600 "$rules_file"

    generate_remove_ruleset "$table_name" >"$rules_file"

    if ! apply_nft_file \
        "$pid" \
        "$rules_file" \
        "$container_description"; then

        rm -f -- "$rules_file"
        return 1
    fi

    rm -f -- "$rules_file"

    log "INFO" \
        "Atomically removed DNFO-managed tables from ${container_description}"
}


###############################################################################
# Container reconciliation
###############################################################################

reconcile_container()
{
    local container_reference="$1"

    local inspect_json
    local container_id
    local container_name
    local container_description
    local running
    local pid

    local enabled
    local defaults_enabled
    local input_policy
    local forward_policy
    local output_policy
    local input_ignore
    local input_include
    local input_rules
    local forward_rules
    local output_rules
    local custom_chains
    local custom_nftables
    local table_name

    local rules_file

    if ! inspect_json="$(
        docker inspect "$container_reference" 2>/dev/null
    )"; then
        log "DEBUG" \
            "Container no longer exists: ${container_reference}"
        return 0
    fi

    container_id="$(container_id_from_json "$inspect_json")"
    container_name="$(container_name_from_json "$inspect_json")"

    container_description="$(
        printf '%s (%s)' \
            "${container_name:-unknown}" \
            "${container_id:0:12}"
    )"

    running="$(container_running_from_json "$inspect_json")"
    pid="$(container_pid_from_json "$inspect_json")"

    if [[ ! -e "/proc/${pid}/ns/net" ]]; then
        log "DEBUG" \
            "Network namespace disappeared for ${container_description}"
        return 0
    fi

    enabled="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.enable"
    )"

    enabled="${enabled:-false}"
    enabled="${enabled,,}"

    table_name="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.table.name"
    )"

    table_name="${table_name:-$DEFAULT_TABLE_NAME}"

    if ! validate_table_name "$table_name"; then
        log "ERROR" \
            "Invalid dnfo.table.name '${table_name}' on ${container_description}"
        return 1
    fi

    if ! validate_boolean "$enabled"; then
        log "ERROR" \
            "Invalid dnfo.enable '${enabled}' on ${container_description}"
        return 1
    fi

    if [[ "$enabled" != "true" ]]; then
        remove_managed_tables \
            "$pid" \
            "$table_name" \
            "$container_description" || true

        log "DEBUG" \
            "DNFO disabled for ${container_description}"
        return 0
    fi

    defaults_enabled="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.defaults"
    )"

    defaults_enabled="${defaults_enabled:-true}"
    defaults_enabled="${defaults_enabled,,}"

    input_policy="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.input.default"
    )"

    input_policy="${input_policy:-drop}"
    input_policy="${input_policy,,}"

    forward_policy="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.forward.default"
    )"

    forward_policy="${forward_policy:-drop}"
    forward_policy="${forward_policy,,}"

    output_policy="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.output.default"
    )"

    output_policy="${output_policy:-accept}"
    output_policy="${output_policy,,}"

    if ! validate_boolean "$defaults_enabled"; then
        log "ERROR" \
            "Invalid dnfo.defaults '${defaults_enabled}' on ${container_description}"
        return 1
    fi

    if ! validate_policy "$input_policy"; then
        log "ERROR" \
            "Invalid dnfo.input.default '${input_policy}' on ${container_description}"
        return 1
    fi

    if ! validate_policy "$forward_policy"; then
        log "ERROR" \
            "Invalid dnfo.forward.default '${forward_policy}' on ${container_description}"
        return 1
    fi

    if ! validate_policy "$output_policy"; then
        log "ERROR" \
            "Invalid dnfo.output.default '${output_policy}' on ${container_description}"
        return 1
    fi

    input_ignore="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.input.ignore"
    )"

    input_include="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.input.include"
    )"

    input_rules="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.input.rules"
    )"

    forward_rules="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.forward.rules"
    )"

    output_rules="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.output.rules"
    )"

    custom_chains="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.custom.chains"
    )"

    custom_nftables="$(
        label_from_json \
            "$inspect_json" \
            "dnfo.custom.nftables"
    )"

    rules_file="$(
        mktemp --tmpdir="$LOCK_DIR" dnfo-rules.XXXXXX
    )"

    chmod 0600 "$rules_file"

    #
    # Complete nftables override.
    #
    # DNFO must not add, delete, flush, create, or otherwise manipulate
    # any table in this mode. The supplied configuration is submitted
    # exactly as provided.
    #
    if [[ -n "$custom_nftables" ]]; then
        printf '%s\n' "$custom_nftables" >"$rules_file"

        if ! apply_nft_file \
            "$pid" \
            "$rules_file" \
            "$container_description"; then

            rm -f -- "$rules_file"

            log "ERROR" \
                "Custom nftables transaction failed for ${container_description}"
            return 1
        fi

        rm -f -- "$rules_file"

        log "INFO" \
            "Applied dnfo.custom.nftables unchanged to ${container_description}"
        return 0
    fi

    if [[ -n "$custom_chains" ]]; then
        generate_custom_chains_ruleset \
            "$table_name" \
            "$custom_chains" \
            >"$rules_file"
    else
        generate_standard_ruleset \
            "$inspect_json" \
            "$pid" \
            "$table_name" \
            "$defaults_enabled" \
            "$input_policy" \
            "$forward_policy" \
            "$output_policy" \
            "$input_ignore" \
            "$input_include" \
            "$input_rules" \
            "$forward_rules" \
            "$output_rules" \
            >"$rules_file"
    fi

    if ! apply_nft_file \
        "$pid" \
        "$rules_file" \
        "$container_description"; then

        rm -f -- "$rules_file"

        log "ERROR" \
            "Atomic firewall replacement failed for ${container_description}; previous rules remain active"
        return 1
    fi

    rm -f -- "$rules_file"

    log "INFO" \
        "Atomically replaced table inet ${table_name} on ${container_description}"
}

reconcile_with_retry()
{
    local container_reference="$1"
    local attempt

    for ((
        attempt = 1;
        attempt <= EVENT_RETRY_ATTEMPTS;
        attempt++
    )); do
        if reconcile_container "$container_reference"; then
            return 0
        fi

        if (( attempt < EVENT_RETRY_ATTEMPTS )); then
            sleep "$EVENT_RETRY_DELAY"
        fi
    done

    log "ERROR" \
        "Reconciliation failed after ${EVENT_RETRY_ATTEMPTS} attempts: ${container_reference}"

    return 1
}

reconcile_running_containers()
{
    local container_id

    log "INFO" "Reconciling running containers"

    while IFS= read -r container_id; do
        [[ -n "$container_id" ]] || continue

        reconcile_with_retry "$container_id" || true
    done < <(
        docker container ls \
            --quiet \
            --no-trunc
    )
}


###############################################################################
# Docker event handling
###############################################################################

handle_event()
{
    local event_json="$1"

    local event_type
    local event_action
    local actor_id
    local container_id

    event_type="$(
        jq -r '.Type // empty' <<<"$event_json"
    )"

    event_action="$(
        jq -r '.Action // empty' <<<"$event_json"
    )"

    actor_id="$(
        jq -r '.Actor.ID // empty' <<<"$event_json"
    )"

    case "${event_type}:${event_action}" in
        container:start|container:restart|container:unpause)
            if [[ -n "$actor_id" ]]; then
                reconcile_with_retry "$actor_id" || true
            fi
            ;;

        network:connect|network:disconnect)
            container_id="$(
                jq -r \
                    '.Actor.Attributes.container // empty' \
                    <<<"$event_json"
            )"

            if [[ -n "$container_id" ]]; then
                reconcile_with_retry "$container_id" || true
            fi
            ;;

        *)
            ;;
    esac
}

watch_events()
{
    local event_json

    while true; do
        log "INFO" "Starting Docker event stream"

        while IFS= read -r event_json; do
            [[ -n "$event_json" ]] || continue

            if ! jq -e . >/dev/null 2>&1 <<<"$event_json"; then
                log "WARN" "Discarding malformed Docker event"
                continue
            fi

            handle_event "$event_json"
        done < <(
            docker events \
                --filter type=container \
                --filter type=network \
                --format '{{json .}}'
        )

        log "WARN" \
            "Docker event stream ended; reconnecting in ${DOCKER_RECONNECT_DELAY} seconds"

        sleep "$DOCKER_RECONNECT_DELAY"

        #
        # Reconcile all running containers after reconnecting because events
        # may have been missed while the event stream was unavailable.
        #
        if docker info >/dev/null 2>&1; then
            reconcile_running_containers
        fi
    done
}


###############################################################################
# Main
###############################################################################

main()
{
    require_root
    require_commands

    install -d \
        -m 0755 \
        "$LOCK_DIR"

    exec 9>"$LOCK_FILE"

    if ! flock --nonblock 9; then
        die "Another DNFO instance is already running"
    fi

    if ! docker info >/dev/null 2>&1; then
        die "Cannot communicate with the Docker daemon"
    fi

    log "INFO" \
        "Starting ${PROGRAM_NAME}"

    reconcile_running_containers
    watch_events
}

main "$@"
