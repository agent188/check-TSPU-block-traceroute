#!/bin/bash
read -r -p "Input hex packet(Paste TLS Client Hello, TCP payload): " packet
if [[ ! $packet ]]; then
	echo "ERROR: Empty packet!"
	exit 1
fi
read -r -p "Input IP: " ip
if [[ ! $ip ]]; then
	echo "ERROR: Empty IP!"
	exit 1
fi
read -r -p "Input port(Default HTTPS port 443): " port
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
