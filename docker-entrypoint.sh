#!/bin/bash
set -eu

# allow the container to be started with `--user`
if [[ "$1" == rabbitmq* ]] && [ "$(id -u)" = '0' ]; then
	if [ "$1" = 'rabbitmq-server' ]; then
		chown -R rabbitmq /var/lib/rabbitmq
	fi
	exec gosu rabbitmq "$BASH_SOURCE" "$@"
fi

# backwards compatibility for old environment variables
: "${RABBITMQ_SSL_CERTFILE:=${RABBITMQ_SSL_CERT_FILE:-}}"
: "${RABBITMQ_SSL_KEYFILE:=${RABBITMQ_SSL_KEY_FILE:-}}"
: "${RABBITMQ_SSL_CACERTFILE:=${RABBITMQ_SSL_CA_FILE:-}}"

# "management" SSL config should default to using the same certs
: "${RABBITMQ_MANAGEMENT_SSL_CACERTFILE:=$RABBITMQ_SSL_CACERTFILE}"
: "${RABBITMQ_MANAGEMENT_SSL_CERTFILE:=$RABBITMQ_SSL_CERTFILE}"
: "${RABBITMQ_MANAGEMENT_SSL_KEYFILE:=$RABBITMQ_SSL_KEYFILE}"

: "${RABBITMQ_MANAGEMENT_LOAD_DEFINITIONS:=}"

# https://www.rabbitmq.com/configure.html
sslConfigKeys=(
	cacertfile
	certfile
	fail_if_no_peer_cert
	keyfile
	verify
)
managementConfigKeys=(
	"${sslConfigKeys[@]/#/ssl_}"
	load_definitions
)
rabbitConfigKeys=(
	default_pass
	default_user
	default_vhost
	hipe_compile
	vm_memory_high_watermark
	cluster_partition_handling
	delegate_count
	fhc_read_buffering
	fhc_write_buffering
	queue_index_embed_msgs_below
	queue_index_max_journal_entries
)
fileConfigKeys=(
	management_ssl_cacertfile
	management_ssl_certfile
	management_ssl_keyfile
	management_load_definitions
	ssl_cacertfile
	ssl_certfile
	ssl_keyfile
)
allConfigKeys=(
	"${managementConfigKeys[@]/#/management_}"
	"${rabbitConfigKeys[@]}"
	"${sslConfigKeys[@]/#/ssl_}"
)

declare -A configDefaults=(
	[management_ssl_fail_if_no_peer_cert]='false'
	[management_ssl_verify]='verify_none'

	[ssl_fail_if_no_peer_cert]='true'
	[ssl_verify]='verify_peer'
)

haveConfig=
haveSslConfig=
haveManagementSslConfig=
valManagementLoadDefinitions=
for conf in "${allConfigKeys[@]}"; do
	var="RABBITMQ_${conf^^}"
	val="${!var:-}"
	if [ "$val" ]; then
		haveConfig=1
		case "$conf" in
			ssl_*) haveSslConfig=1 ;;
			management_ssl_*) haveManagementSslConfig=1 ;;
			management_load_definitions) valManagementLoadDefinitions="$val" ;;
		esac
	fi
done
if [ "$haveSslConfig" ]; then
	missing=()
	for sslConf in cacertfile certfile keyfile; do
		var="RABBITMQ_SSL_${sslConf^^}"
		val="${!var}"
		if [ -z "$val" ]; then
			missing+=( "$var" )
		fi
	done
	if [ "${#missing[@]}" -gt 0 ]; then
		{
			echo
			echo 'error: SSL requested, but missing required configuration'
			for miss in "${missing[@]}"; do
				echo "  - $miss"
			done
			echo
		} >&2
		exit 1
	fi
fi
missingFiles=()
for conf in "${fileConfigKeys[@]}"; do
	var="RABBITMQ_${conf^^}"
	val="${!var}"
	if [ "$val" ] && [ ! -f "$val" ]; then
		missingFiles+=( "$val ($var)" )
	fi
done
if [ "${#missingFiles[@]}" -gt 0 ]; then
	{
		echo
		echo 'error: files specified, but missing'
		for miss in "${missingFiles[@]}"; do
			echo "  - $miss"
		done
		echo
	} >&2
	exit 1
fi

# set defaults for missing values (but only after we're done with all our checking so we don't throw any of that off)
for conf in "${!configDefaults[@]}"; do
	default="${configDefaults[$conf]}"
	var="RABBITMQ_${conf^^}"
	[ -z "${!var:-}" ] || continue
	eval "export $var=\"\$default\""
done

# If long & short hostnames are not the same, use long hostnames
if [ "$(hostname)" != "$(hostname -s)" ]; then
	: "${RABBITMQ_USE_LONGNAME:=true}"
fi

if [ "${RABBITMQ_ERLANG_COOKIE:-}" ]; then
	cookieFile='/var/lib/rabbitmq/.erlang.cookie'
	if [ -e "$cookieFile" ]; then
		if [ "$(cat "$cookieFile" 2>/dev/null)" != "$RABBITMQ_ERLANG_COOKIE" ]; then
			echo >&2
			echo >&2 "warning: $cookieFile contents do not match RABBITMQ_ERLANG_COOKIE"
			echo >&2
		fi
	else
		echo "$RABBITMQ_ERLANG_COOKIE" > "$cookieFile"
		chmod 600 "$cookieFile"
	fi
fi

# prints "$2$1$3$1...$N"
join() {
	local sep="$1"; shift
	local out; printf -v out "${sep//%/%%}%s" "$@"
	echo "${out#$sep}"
}
indent() {
	if [ "$#" -gt 0 ]; then
		echo "$@"
	else
		cat
	fi | sed 's/^/\t/g'
}
rabbit_array() {
	echo -n '['
	case "$#" in
		0) echo -n ' ' ;;
		1) echo -n " $1 " ;;
		*)
			local vals="$(join $',\n' "$@")"
			echo
			indent "$vals"
	esac
	echo -n ']'
}
rabbit_env_config() {
	local prefix="$1"; shift

	local ret=()
	local conf
	for conf; do
		local var="rabbitmq${prefix:+_$prefix}_$conf"
		var="${var^^}"

		local val="${!var:-}"

		local rawVal=
		case "$conf" in
			verify|fail_if_no_peer_cert|cluster_partition_handling|delegate_count|fhc_read_buffering|fhc_write_buffering|queue_index_embed_msgs_below|queue_index_max_journal_entries)
				[ "$val" ] || continue
				rawVal="$val"
				;;

			hipe_compile)
				[ "$val" ] && rawVal='true' || rawVal='false'
				;;

			cacertfile|certfile|keyfile)
				[ "$val" ] || continue
				rawVal='"'"$val"'"'
				;;

			vm_memory_high_watermark)
				node_mem=$(free -b | grep Mem | awk '{ print $2 }')
				# if cgroup is not enabled, use absolute ram
				if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
					cgroup_mem=$(< /sys/fs/cgroup/memory/memory.limit_in_bytes)
				else
					cgroup_mem=$node_mem
				fi
				# set default
				if [ -z "$val" ]; then
					# assume cgroup limit is set if cgroup is smaller than absolute RAM
				if [ $cgroup_mem -lt $node_mem ]; then
						val=0.85
					else
						val=0.4
					fi
				fi
				# numeric values have additional calculations/checks
				if [[ $val =~ ^[+-]?[0-9]+\.?[0-9]*$ ]]; then
					mem_available=$([ $cgroup_mem -le $node_mem ] && echo "$cgroup_mem" || echo "$node_mem")

					if [[ $val =~ ^[+-]?[0-9]+\.[0-9]*$ ]]; then
						# float, calculate limit
						mem_hwm=$(awk "BEGIN {printf \"%0.0f\", $mem_available * $val}")
					else
						mem_hwm=$val
					fi
					# mem hwm cannot be higher than available memory (cgroup or absolute mem)
					mem_hwm=$([ $mem_hwm -le $mem_available ] && echo "$mem_hwm" || echo "$mem_available")
					# mem hwm must be at least 128MB
					mem_hwm=$([ $mem_hwm -le 134217728 ] && echo "134217728" || echo "$mem_hwm")
				else
					mem_hwm='"'"$val"'"'
				fi

                                rawVal="{ absolute, $mem_hwm }"
				;;

			*)
				[ "$val" ] || continue
				rawVal='<<"'"$val"'">>'
				;;
		esac
		[ "$rawVal" ] || continue

		ret+=( "{ $conf, $rawVal }" )
	done

	join $'\n' "${ret[@]}"
}

if [ "$1" = 'rabbitmq-server' ] && [ "$haveConfig" ]; then
	fullConfig=()

	rabbitConfig=(
		"{ loopback_users, $(rabbit_array) }"
	)

	if [ "$haveSslConfig" ]; then
		IFS=$'\n'
		rabbitSslOptions=( $(rabbit_env_config 'ssl' "${sslConfigKeys[@]}") )
		unset IFS

		rabbitConfig+=(
			"{ tcp_listeners, $(rabbit_array) }"
			"{ ssl_listeners, $(rabbit_array 5671) }"
			"{ ssl_options, $(rabbit_array "${rabbitSslOptions[@]}") }"
		)
	else
		rabbitConfig+=(
			"{ tcp_listeners, $(rabbit_array 5672) }"
			"{ ssl_listeners, $(rabbit_array) }"
		)
	fi

	IFS=$'\n'
	rabbitConfig+=( $(rabbit_env_config '' "${rabbitConfigKeys[@]}") )
	unset IFS

	fullConfig+=( "{ rabbit, $(rabbit_array "${rabbitConfig[@]}") }" )

	# If management plugin is installed, then generate config consider this
	if [ "$(rabbitmq-plugins list -m -e rabbitmq_management)" ]; then
		if [ "$haveManagementSslConfig" ]; then
			IFS=$'\n'
			rabbitManagementSslOptions=( $(rabbit_env_config 'management_ssl' "${sslConfigKeys[@]}") )
			unset IFS

			rabbitManagementListenerConfig+=(
				'{ port, 15671 }'
				'{ ssl, true }'
				"{ ssl_opts, $(rabbit_array "${rabbitManagementSslOptions[@]}") }"
			)
		else
			rabbitManagementListenerConfig+=(
				'{ port, 15672 }'
				'{ ssl, false }'
			)
		fi

		rabbitManagementConfig+=(
			"{ listener, $(rabbit_array "${rabbitManagementListenerConfig[@]}") }"
		)

		if [ -n "$valManagementLoadDefinitions" ]; then
			# Expand all instance of $VAR or ${VAR} to their environment values
			# Regex source: http://stackoverflow.com/questions/2914220/bash-templating-how-to-build-configuration-files-from-templates-with-bash/25019138#25019138
			perl -pe 's;(\\*)(\$([a-zA-Z_][a-zA-Z_0-9]*)|\$\{([a-zA-Z_][a-zA-Z_0-9]*)\})?;substr($1,0,int(length($1)/2)).($2&&length($1)%2?$2:$ENV{$3||$4});eg' \
				$valManagementLoadDefinitions > /etc/rabbitmq/definitions.json

			rabbitManagementConfig+=(
				'{ load_definitions, "/etc/rabbitmq/definitions.json" }'
			)
		fi

		fullConfig+=(
			"{ rabbitmq_management, $(rabbit_array "${rabbitManagementConfig[@]}") }"
		)
	fi

	echo "$(rabbit_array "${fullConfig[@]}")." > /etc/rabbitmq/rabbitmq.config
fi

combinedSsl='/tmp/combined.pem'
if [ "$haveSslConfig" ] && [[ "$1" == rabbitmq* ]] && [ ! -f "$combinedSsl" ]; then
	# Create combined cert
	cat "$RABBITMQ_SSL_CERTFILE" "$RABBITMQ_SSL_KEYFILE" > "$combinedSsl"
	chmod 0400 "$combinedSsl"
fi
if [ "$haveSslConfig" ] && [ -f "$combinedSsl" ]; then
	# More ENV vars for make clustering happiness
	# we don't handle clustering in this script, but these args should ensure
	# clustered SSL-enabled members will talk nicely
	export ERL_SSL_PATH="$(erl -eval 'io:format("~p", [code:lib_dir(ssl, ebin)]),halt().' -noshell)"
	export RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS="-pa $ERL_SSL_PATH -proto_dist inet_tls -ssl_dist_opt server_certfile $combinedSsl -ssl_dist_opt server_secure_renegotiate true client_secure_renegotiate true"
	export RABBITMQ_CTL_ERL_ARGS="$RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS"
fi

export RABBITMQ_NODENAME="rabbit@${HOSTNAME}${K8S_HOSTNAME_SUFFIX:-}"

exec "$@"
