#!/bin/sh

if [ "$1" != "${1#*[0-9].[0-9]}" ]; then
	/usr/sbin/ipset add sshotp $1
elif [ "$1" != "${1#*:[0-9a-fA-F]}" ]; then
	/usr/sbin/ipset add sshotpv6 $1
fi
