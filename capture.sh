if [ -n "$1" ]; then
    INTERFACE="$1"
fi

if [ -z "${INTERFACE}" ]; then
    echo "Undefined Interface."
    exit 1
fi

if [ -f "./capture.pcapng" ]; then
    rm ./capture.pcapng
fi

echo "Starting nr-gnb .."
./build/nr-gnb -c open5gs-gnb.yaml > /dev/null 2>&1 &
pid_gnb=$!
sleep 1s

echo "TShark capturing .."
tshark -i ${INTERFACE} -F pcapng -w ./capture.pcapng > /dev/null 2>&1 &
pid_tshark=$!
sleep 1s

echo "Starting nr-ue .."
sudo bash -c './build/nr-ue -c open5gs-ue.yaml > /dev/null 2>&1 &'
sleep 1s

sudo kill $(ps aux | grep nr-ue | awk '{print $2}')
sleep 2s
kill ${pid_gnb}
kill ${pid_tshark}