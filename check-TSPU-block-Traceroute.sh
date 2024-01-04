#!/bin/bash
while [ "$#" -gt 0 ] ; do
  case "${1}" in
    (--packet)  packet="${2}" ; shift ;;
    (--ip)  ip="${2}" ; shift ;;
    (--port)  port="${2}" ; shift ;;
    (--packet=?*)  packet="${1#--packet=}" ;;
    (--port=?*)  port="${1#--port=}" ;;
    (--ip=?*)  ip="${1#--ip=}" ;;
  esac
  shift
done
if [[ ! $packet ]]; then
	read -r -p "Input hex packet(Paste TLS Client Hello, TCP payload): " packet
fi
if [[ ! $packet ]]; then
	echo "ERROR: Empty packet!"
	exit 1
fi
if [[ ! $ip ]]; then
	read -r -p "Input IP: " ip
fi
if [[ ! $ip ]]; then
	echo "ERROR: Empty IP!"
	exit 1
fi
if [[ ! $port ]]; then
	read -r -p "Input port(Default HTTPS port 443): " port
fi
if [[ ! $port ]]; then
	port="443"
fi
sourcePort=$(shuf -i 1024-65535 -n 1)
ack=$(shuf -i 1024-1000000 -n 1)
seq=$(shuf -i 1024-1000000 -n 1)
iptables -I OUTPUT -p tcp --tcp-flags FIN FIN -d $ip -j DROP
iptables -I OUTPUT -p tcp --tcp-flags RST RST -d $ip -j DROP
nping --tcp-connect --seq $seq --ack $ack -g $sourcePort -p $port $ip -c 1
nping --tcp --seq $(( $seq + 2 )) --ack $(( $ack + 2 )) -g $sourcePort --flags PSH,ACK --data "$packet" --tr -p $port $ip
iptables -D OUTPUT -p tcp --tcp-flags FIN FIN -d $ip -j DROP
iptables -D OUTPUT -p tcp --tcp-flags RST RST -d $ip -j DROP
