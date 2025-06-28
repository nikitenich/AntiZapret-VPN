#!/bin/bash
#
# Добавление/удаление клиента
#
# chmod +x client.sh && ./client.sh [1-8] [имя_клиента] [срок_действия]
#
# Срок действия в днях - только для OpenVPN
#
set -e

handle_error() {
	echo
	echo "$(lsb_release -ds) $(uname -r) $(date --iso-8601=seconds)"
	echo
	echo -e "\e[1;31mError occurred at line $1 while executing: $2\e[0m"
	exit 1
}
trap 'handle_error $LINENO "$BASH_COMMAND"' ERR

export LC_ALL=C

askClientName(){
	if ! [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
		echo
		echo 'Enter client name: 1–32 alphanumeric characters (a-z, A-Z, 0-9) with underscore (_) or dash (-)'
		until [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; do
			read -rp 'Client name: ' -e CLIENT_NAME
		done
	fi
}

askClientCertExpire(){
	if ! [[ "$CLIENT_CERT_EXPIRE" =~ ^[0-9]+$ ]] || (( CLIENT_CERT_EXPIRE <= 0 )) || (( CLIENT_CERT_EXPIRE > 3650 )); then
		echo
		echo 'Enter client certificate expiration days (1-3650):'
		until [[ "$CLIENT_CERT_EXPIRE" =~ ^[0-9]+$ ]] && (( CLIENT_CERT_EXPIRE > 0 )) && (( CLIENT_CERT_EXPIRE <= 3650 )); do
			read -rp 'Certificate expiration days: ' -e -i 3650 CLIENT_CERT_EXPIRE
		done
	fi
}

setServerHost_FileName(){
	if [[ -z "$1" ]]; then
		SERVER_HOST="$SERVER_IP"
	else
		SERVER_HOST="$1"
	fi

	FILE_NAME="${CLIENT_NAME#antizapret-}"
	FILE_NAME="${FILE_NAME#vpn-}"
	FILE_NAME="${FILE_NAME}-(${SERVER_HOST})"
}

setServerIP(){
	SERVER_IP="$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
	if [[ -z "$SERVER_IP" ]]; then
		echo 'Default IP address not found!'
		exit 2
	fi
}

render() {
	local IFS=''
	while read -r line; do
		while [[ "$line" =~ (\$\{[a-zA-Z_][a-zA-Z_0-9]*\}) ]]; do
			local LHS="${BASH_REMATCH[1]}"
			local RHS="$(eval echo "\"$LHS\"")"
			line="${line//$LHS/$RHS}"
		done
		echo "$line"
	done < "$1"
}

initOpenVPN(){
	mkdir -p /etc/openvpn/easyrsa3
	cd /etc/openvpn/easyrsa3

	if [[ ! -f ./pki/ca.crt ]] || \
	   [[ ! -f ./pki/issued/antizapret-server.crt ]] || \
	   [[ ! -f ./pki/private/antizapret-server.key ]]; then
		rm -rf ./pki
		rm -rf /etc/openvpn/server/keys
		rm -rf /etc/openvpn/client/keys
		/usr/share/easy-rsa/easyrsa init-pki
		EASYRSA_CA_EXPIRE=3650 /usr/share/easy-rsa/easyrsa --batch --req-cn="AntiZapret CA" build-ca nopass
		EASYRSA_CERT_EXPIRE=3650 /usr/share/easy-rsa/easyrsa --batch build-server-full "antizapret-server" nopass
	fi

	mkdir -p /etc/openvpn/server/keys
	mkdir -p /etc/openvpn/client/keys

	if [[ ! -f /etc/openvpn/server/keys/ca.crt ]] || \
	   [[ ! -f /etc/openvpn/server/keys/antizapret-server.crt ]] || \
	   [[ ! -f /etc/openvpn/server/keys/antizapret-server.key ]]; then
		cp ./pki/ca.crt /etc/openvpn/server/keys/ca.crt
		cp ./pki/issued/antizapret-server.crt /etc/openvpn/server/keys/antizapret-server.crt
		cp ./pki/private/antizapret-server.key /etc/openvpn/server/keys/antizapret-server.key
	fi

	if [[ ! -f /etc/openvpn/server/keys/crl.pem ]]; then
		EASYRSA_CRL_DAYS=3650 /usr/share/easy-rsa/easyrsa gen-crl
		chmod 644 ./pki/crl.pem
		cp ./pki/crl.pem /etc/openvpn/server/keys/crl.pem
	fi
}

addOpenVPN(){
	setServerHost_FileName "$OPENVPN_HOST"
	cd /etc/openvpn/easyrsa3

	if [[ ! -f ./pki/issued/$CLIENT_NAME.crt ]] || \
	   [[ ! -f ./pki/private/$CLIENT_NAME.key ]]; then
		askClientCertExpire
		echo
		EASYRSA_CERT_EXPIRE=$CLIENT_CERT_EXPIRE /usr/share/easy-rsa/easyrsa --batch build-client-full $CLIENT_NAME nopass
	else
		echo
		echo 'Client with that name already exists! Please enter different name for new client'
		echo
		if [[ "$CLIENT_CERT_EXPIRE" != "0" ]]; then
			echo 'Current client certificate expiration period:'
			openssl x509 -in ./pki/issued/$CLIENT_NAME.crt -noout -dates
			echo
			echo "Attention! Certificate renewal is NOT possible after 'notAfter' date"
			askClientCertExpire
			echo
			rm -f ./pki/issued/$CLIENT_NAME.crt
			/usr/share/easy-rsa/easyrsa --batch --days=$CLIENT_CERT_EXPIRE sign client $CLIENT_NAME
			rm -f /etc/openvpn/client/keys/$CLIENT_NAME.crt
		fi
	fi

	if [[ ! -f /etc/openvpn/client/keys/$CLIENT_NAME.crt ]] || \
	   [[ ! -f /etc/openvpn/client/keys/$CLIENT_NAME.key ]]; then
		cp ./pki/issued/$CLIENT_NAME.crt /etc/openvpn/client/keys/$CLIENT_NAME.crt
		cp ./pki/private/$CLIENT_NAME.key /etc/openvpn/client/keys/$CLIENT_NAME.key
	fi

	CA_CERT="$(grep -A 999 'BEGIN CERTIFICATE' -- "/etc/openvpn/server/keys/ca.crt")"
	CLIENT_CERT="$(grep -A 999 'BEGIN CERTIFICATE' -- "/etc/openvpn/client/keys/$CLIENT_NAME.crt")"
	CLIENT_KEY="$(cat -- "/etc/openvpn/client/keys/$CLIENT_NAME.key")"
	if [[ ! "$CA_CERT" ]] || [[ ! "$CLIENT_CERT" ]] || [[ ! "$CLIENT_KEY" ]]; then
		echo 'Cannot load client keys!'
		exit 11
	fi

	render "/etc/openvpn/client/templates/antizapret-udp.conf" > "/root/antizapret/client/openvpn/antizapret-udp/antizapret-$FILE_NAME-udp.ovpn"
	render "/etc/openvpn/client/templates/antizapret-tcp.conf" > "/root/antizapret/client/openvpn/antizapret-tcp/antizapret-$FILE_NAME-tcp.ovpn"
	render "/etc/openvpn/client/templates/antizapret.conf" > "/root/antizapret/client/openvpn/antizapret/antizapret-$FILE_NAME.ovpn"
	render "/etc/openvpn/client/templates/vpn-udp.conf" > "/root/antizapret/client/openvpn/vpn-udp/vpn-$FILE_NAME-udp.ovpn"
	render "/etc/openvpn/client/templates/vpn-tcp.conf" > "/root/antizapret/client/openvpn/vpn-tcp/vpn-$FILE_NAME-tcp.ovpn"
	render "/etc/openvpn/client/templates/vpn.conf" > "/root/antizapret/client/openvpn/vpn/vpn-$FILE_NAME.ovpn"

	echo "OpenVPN profile files (re)created for client '$CLIENT_NAME' at /root/antizapret/client/openvpn"
}

deleteOpenVPN(){
	setServerHost_FileName "$OPENVPN_HOST"
	echo
	cd /etc/openvpn/easyrsa3

	/usr/share/easy-rsa/easyrsa --batch revoke $CLIENT_NAME
	EASYRSA_CRL_DAYS=3650 /usr/share/easy-rsa/easyrsa gen-crl
	chmod 644 ./pki/crl.pem
	cp ./pki/crl.pem /etc/openvpn/server/keys/crl.pem

	rm -f /root/antizapret/client/openvpn/antizapret/antizapret-$FILE_NAME.ovpn
	rm -f /root/antizapret/client/openvpn/antizapret-udp/antizapret-$FILE_NAME-udp.ovpn
	rm -f /root/antizapret/client/openvpn/antizapret-tcp/antizapret-$FILE_NAME-tcp.ovpn
	rm -f /root/antizapret/client/openvpn/vpn/vpn-$FILE_NAME.ovpn
	rm -f /root/antizapret/client/openvpn/vpn-udp/vpn-$FILE_NAME-udp.ovpn
	rm -f /root/antizapret/client/openvpn/vpn-tcp/vpn-$FILE_NAME-tcp.ovpn
	rm -f /etc/openvpn/client/keys/$CLIENT_NAME.crt
	rm -f /etc/openvpn/client/keys/$CLIENT_NAME.key

	echo "OpenVPN client '$CLIENT_NAME' successfully deleted"
}

listOpenVPN(){
	[[ -n "$CLIENT_NAME" ]] && return
	echo
	echo 'OpenVPN client names:'
	ls /etc/openvpn/easyrsa3/pki/issued | sed 's/\.crt$//' | grep -v "^antizapret-server$" | sort
}

recreate(){
	echo

	find /root/antizapret/client -type f -delete

	# OpenVPN
	if [[ -d "/etc/openvpn/easyrsa3/pki/issued" ]]; then
		initOpenVPN
		CLIENT_CERT_EXPIRE=0
		ls /etc/openvpn/easyrsa3/pki/issued | sed 's/\.crt$//' | grep -v "^antizapret-server$" | sort | while read -r CLIENT_NAME; do
			if [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
				addOpenVPN >/dev/null
				echo "OpenVPN profile files recreated for client '$CLIENT_NAME'"
			else
				echo "OpenVPN client name '$CLIENT_NAME' is invalid! No profile files recreated"
			fi
		done
	else
		CLIENT_NAME="antizapret-client"
		CLIENT_CERT_EXPIRE=3650
		echo "Creating OpenVPN server keys and first OpenVPN client: '$CLIENT_NAME'"
		initOpenVPN
		addOpenVPN >/dev/null
	fi
}

backup(){
	echo

	rm -rf /root/antizapret/backup

	cp -r /etc/openvpn/easyrsa3 /root/antizapret/backup
	cp -r /root/antizapret/config /root/antizapret/backup

	BACKUP_FILE="/root/antizapret/backup-$SERVER_IP.tar.gz"
	tar -czf "$BACKUP_FILE" -C /root/antizapret/backup easyrsa3 config
	tar -tzf "$BACKUP_FILE" > /dev/null

	rm -rf /root/antizapret/backup

	echo "Clients and config backup (re)created at $BACKUP_FILE"
}

source /root/antizapret/setup
umask 022
setServerIP

OPTION=$1
CLIENT_NAME=$2
CLIENT_CERT_EXPIRE=$3

if ! [[ "$OPTION" =~ ^[1-8]$ ]]; then
	echo
	echo 'Please choose option:'
	echo '    1) OpenVPN - Add client/Renew client certificate'
	echo '    2) OpenVPN - Delete client'
	echo '    3) OpenVPN - List clients'
	echo '    4) (Re)create clients profile files'
	echo '    5) (Re)create clients and config backup'
	until [[ "$OPTION" =~ ^[1-8]$ ]]; do
		read -rp 'Option choice [1-8]: ' -e OPTION
	done
fi

case "$OPTION" in
	1)
		echo "OpenVPN - Add client/Renew client certificate $CLIENT_NAME $CLIENT_CERT_EXPIRE"
		askClientName
		initOpenVPN
		addOpenVPN
		;;
	2)
		echo "OpenVPN - Delete client $CLIENT_NAME"
		listOpenVPN
		askClientName
		deleteOpenVPN
		;;
	3)
		echo 'OpenVPN - List clients'
		listOpenVPN
		;;
	4)
		echo '(Re)create clients profile files'
		recreate
		;;
	5)
		echo '(Re)create clients and config backup'
		backup
		;;
esac