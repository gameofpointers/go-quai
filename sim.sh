#!/bin/bash

# Set the threshold for the line count
THRESHOLD=101
MINING_START_THRESHOLD=1
NUMBER_OF_SIMULATIONS=100
NUMBER_OF_MACHINES_RUNNING=37
SLEEP_BEFORE_MINING=20
TIME_BETWEEN_TESTS=30
CHECK_INTERVAL=0.1
GOQUAI_PATH=~/go-quai
MINER_PATH=~/quai-cpu-miner

# Function to call the first API and get the block number
getBlockNumber() {
    RESPONSE=$(curl -s --location 'http://localhost:8610/' \
    --header 'Content-Type: application/json' \
    --data '{
        "jsonrpc": "2.0",
        "method": "quai_blockNumber",
        "params": [],
        "id": 1
    }')
    echo $RESPONSE | jq -r '.result'
}

getBlockByNumber() {
    BLOCK_NUMBER=$1
    RESPONSE=$(curl -s --location 'http://localhost:8610/' \
    --header 'Content-Type: application/json' \
    --data "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"quai_getBlockByNumber\",
        \"params\": [\"$BLOCK_NUMBER\", true],
        \"id\": 1
	}")
    echo $RESPONSE | jq -r '.result'
}

# Clean the database and nodelogs before starting the Simulation
# clean the db and nodelogs
echo "Removing the Database and the nodelogs"
pkill -9 quai
rm -rf $GOQUAI_PATH/nodelogs

# create the static files
cp -r quai ~/.quai

# start go-quai
make run

sleep $SLEEP_BEFORE_MINING

cd $MINER_PATH && make run-mine-background region=0 zone=0
cd $GOQUAI_PATH

start=1
end=$NUMBER_OF_SIMULATIONS
# Main loop to run the experiment 100 times
for i in $(seq $start $end); do
    > simulations/$i.csv
    while true; do
        blockNumber=$(($(getBlockNumber)))
        # Check if the count has reached the threshold
        if [ "$blockNumber" -ge "$THRESHOLD" ]; then
            # Call the APIs and store the block number
            echo "Simulation, $i, Num of Nodes, $NUMBER_OF_MACHINES_RUNNING" >> simulations/$i.csv
	        echo "Block Height, Block Hash, Time Stamp, Received Time Stamp, Extra Bits"  >> simulations/$i.csv

            start=1
            end=$THRESHOLD
	        for j in $(seq $start $end); do 
                index_hex=$(printf "0x%x" $j)
                block_j=$(getBlockByNumber "$index_hex")
                timestamp=$(($(echo $block_j | jq -r '.timestamp')))
                hash=$(echo $block_j | jq -r '.hash')
                entropy=$(echo $block_j | jq -r '.extraBits')
                receivedtime=$(cat nodelogs/zone-0-0.log | grep 'Appended' | grep $hash | awk '{print $21}' | awk -F= '{print $2}')
                echo $j, $hash, $timestamp, $receivedtime, $entropy >> simulations/$i.csv
	        done

            ###### Stop, clear data, and restart the process #####
	        
	        echo "Stop the Miner"
	        # stop the miner
	        cd $MINER_PATH && make stop
	        echo "Miner stopped"

	        sleep 5

	        # stop the node
	        echo "Stop the Node"
	        cd $GOQUAI_PATH 
	        make stop
	        echo "Node stopped"

	        # clean the db and nodelogs
	        echo "Removing the Database and the nodelogs"
            rm -rf ~/.quai $GOQUAI_PATH/nodelogs

            # create the static files
            cp -r quai ~/.quai

	        echo "Sleep for $TIME_BETWEEN_TESTS"
	        # SLEEP BEFORE NEXT TEST
            sleep $TIME_BETWEEN_TESTS

	        echo "Start Node"
            make run

            sleep $SLEEP_BEFORE_MINING

	        echo "Starting the Miner on 0-0"
	        cd $MINER_PATH && make run-mine-background region=0 zone=0
	        
	        echo "Going back to go-quai"
	        cd $GOQUAI_PATH
	        break
        else
            sleep $CHECK_INTERVAL
        fi
    done
done

