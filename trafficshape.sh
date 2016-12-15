#!/bin/bash
TC=/sbin/tc

#interface
IF=$1

# drop rate
RATE=$3

drop() {
	# start dropping packets
	$TC qdisc add dev $IF root netem loss $RATE
}

stop() {
	# Stop dropping packets
	$TC qdisc del dev $IF root
}

case "$2" in

	drop)

		echo -n "Starting packet dropping: "
		drop
		echo "done"
		;;

	stop)

		echo -n "Stopping packet dropping: "
		stop
		echo "done"
		;;

	*)

		pwd=$(pwd)
		echo "Usage: tc.bash {drop|stop}"
		;;

	esac

exit 0
