#!/bin/bash

dropping="false"

while sleep 5; do
	timestamp=$(date)
	if [ $dopping -e "false" ]; then
		echo "starting dropping at $timestamp"
		trafficshape drop 90%
	else
		echo "stopping dropping at $timestamp"
		trafficshape stop
	fi
done
