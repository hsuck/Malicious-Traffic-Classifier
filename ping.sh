#!/bin/bash

for i in {1..30000}
do
    ip=$(shuf -i 1-254 -n 4 | tr '\n' '.' | sed 's/[.]*$//g')
	ping -c 1 -w 1 -W 1 $ip | grep -q "ttl=" && echo "$ip [yes]" || echo "$ip [no]" &
done
