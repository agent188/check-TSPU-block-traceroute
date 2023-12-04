#!/bin/bash
function GenerateTlsClientHello() {
	echo -n "160301029001"
	echo -n "$lengthTLS"
	echo -n "030339d8b9a158482bf07aa4d536525d2aee4201149ba97db31bf5ca4372540d8f7320936b24c51d659080fa9e73a9fb588270b2b3c7620b883b564b1558ca1e2bba2d0022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f00350100"
	echo -n "$extensionsLength"
	echo -n "0000001200"
	echo -n "$sniLength"
	echo -n "0000"
	echo -n "$lengthDomain"
	echo -n "$domain"
	echo -n "00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d0020785f5d1eaf738ea9ecbd0323dc72c9f63800996152e61f8ac806aad079e21742001700410425b40ce142fcacb20d84ae21de491eb1c863ff0afa095461d7b1cdb2117373000851813e533cbe0e54200ea8d7597f523dad180d55589f303b442b8be925b8df002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001fe0d011900000100010c00202d0dea938aae09a9dd7c6566fad1ae0f6f7ded2bc1a3f9295080fe93628e4da700ef703feacdb2b43a8dea0c3ef1cf88f51184108acc9f3d92a6d073d4b380468f21c2fc2235c83f805c3ad36790fa6aba13580b634f39b1a01e0c1d43ab48e178e7dfe55b6ff6e693267017f8390f8b761ef2da3f287e2c5d3941a292953f36ea45665bd1f00530d56d16734d081ab3ceabf4968ca1cb557946b38678aebaad6bf16daa0086ebbc441c465b736eac85f3f64697a67a8632ba1531ec2d9641827851c7cce96d3a87ffb4870706bbddef4cfc83150e4663436d6ccb7dcd6bbc138ad2834a1397fb19cc08b8dd00f1e2a423f6a03e8276bb40c7361733639f255710bfa66bce8444fc31f3dc669a8da7217b"
}
read -r -p "Input domain(SNI in TLS Client Hello): " domain
if [[ ! $domain ]]; then
	echo "ERROR: Empty domain!"
	exit 1
fi
lengthDomain=$(echo -n "$domain" | wc -c)
sniLength=$(( $lengthDomain + 3 ))
lengthTLS=$(( 636 + $sniLength ))
extensionsLength=$(( 529 + $sniLength ))
sniLength=$(printf '%02x' $sniLength)
lengthDomain=$(printf '%02x' $lengthDomain)
lengthTLS=$(printf '%06x' $lengthTLS)
extensionsLength=$(printf '%04x' $extensionsLength)
domain=$(echo -n "$domain" | xxd -p)
data=$(GenerateTlsClientHello)
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
nping --tcp --seq $(( $seq + 2 )) --ack $(( $ack + 2 )) -g $sourcePort --flags PSH,ACK --data "$data" --tr -p $port $ip
iptables -D OUTPUT -p tcp --tcp-flags FIN FIN -d $ip -j DROP
iptables -D OUTPUT -p tcp --tcp-flags RST RST -d $ip -j DROP
