#!/bin/bash


ACTION=$1
shift
IPSET=$@
IPTABLES="/sbin/iptables"


function print_usage() {
    echo "Usage: ./block_test.sh [add|remove] ip1 ip2 ..."
}


if [ "$ACTION" != "add" -a "$ACTION" != "remove" ]; then
    print_usage
    exit 1
fi


for ip in $IPSET
do
    case $ACTION in
        add)
            $IPTABLES -t filter -A OUTPUT -d $ip -j DROP
            $IPTABLES -t filter -A FORWARD -d $ip -j DROP
            ;;
        remove)
            oid=$($IPTABLES -L OUTPUT -n --line-numbers | grep $ip | awk '{print $1}')
            fid=$($IPTABLES -L FORWARD -n --line-numbers | grep $ip | awk '{print $1}')
            $IPTABLES -t filter -D OUTPUT $oid
            $IPTABLES -t filter -D FORWARD $fid
            ;;
    esac
done


$IPTABLES -t filter -L OUTPUT -n
$IPTABLES -t filter -L FORWARD -n
