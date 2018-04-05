
while [ true ]; do
	echo ""
	echo ""
	echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	echo "Starting jpnevulator.py"
	./jpnevulator.py --timing-print --tty /dev/ttyUSB0:CMD --tty /dev/ttyUSB1:RSP --read --baudrate 115200 --width 32 --timing-delta 5000 -f tempFw/packet.list
	echo ""
	echo "stopping jpnevulator.py"
	sleep 1
	# clear
done
