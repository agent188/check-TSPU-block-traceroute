# check-TSPU-block-traceroute
Util checks by traceroute whether the site is blocked on the territory of the Russian Federation. This util can traceroute established TCP connection. This tool can also work with other DPI systems.

# Dependencies
- iptables
- nmap

# Example run
`./check-TSPU-block-Traceroute.sh --packet "16030300c2010000be03036596960a89cdf09a0eadd847dd3ae4cd6ec4c1a1b778ecc0a5023da8b5d85a8c00002ac02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a0100006b00000012001000000d7275747261636b65722e6f7267000500050100000000000a00080006001d00170018000b00020100000d001a0018080408050806040105010201040305030203020206010603002300000010000b000908687474702f312e3100170000ff01000100" --ip 172.67.182.196 --port 443`
