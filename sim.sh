#!/bin/bash

# Set the threshold for the line count
THRESHOLD=100
NUMBER_OF_SIMULATIONS=100
NUMBER_OF_MACHINES_RUNNING=50
EXPECTED_PEERS="0x26"
SLEEP_BEFORE_MINING=10
TIME_BETWEEN_TESTS=60
CHECK_INTERVAL=0.2
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

# Function to call the second API with the block number from the first API
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
    # echo $RESPONSE | grep -o '"totalEntropy":.*' | awk -F'"' '{print $4}'
    echo $RESPONSE | jq -r '.result.totalEntropy'
}

# Clean the database and nodelogs before starting the Simulation
# clean the db and nodelogs
echo "Removing the Database and the nodelogs"
pkill -9 quai
rm -rf ~/.quai $GOQUAI_PATH/nodelogs

# start go-quai
make run
sleep $SLEEP_BEFORE_MINING

cd $MINER_PATH && make run-mine-background region=0 zone=0
cd $GOQUAI_PATH

# Main loop to run the experiment 100 times
for i in {1..$NUMBER_OF_SIMULATIONS}; do
    while true; do
        # Count the number of "Appended" lines in the log file
        COUNT=$(cat nodelogs/zone-0-0.log | grep Appended | wc -l)

        # Check if the count has reached the threshold
        if [ "$COUNT" -ge "$THRESHOLD" ]; then
            # Call the APIs and store the block number
            BLOCK_NUMBER=$(getBlockNumber)
	        TOTAL_ENTROPY=$(getBlockByNumber $BLOCK_NUMBER)

	        echo "Simulation Iteration :$i, Block Height: $BLOCK_NUMBER, Total Entropy: $TOTAL_ENTROPY" 

	        # TODO: need to store this information

            ###### Stop, clear data, and restart the process #####
	        
	        echo "Stop the Miner"
	        # stop the miner
	        cd $MINER_PATH && make stop
	        echo "Miner stopped"
	        # stop the node
	        echo "Stop the Node"
	        cd $GOQUAI_PATH 
	        make stop
	        echo "Node stopped"

	        # clean the db and nodelogs
	        echo "Removing the Database and the nodelogs"
            rm -rf ~/.quai $GOQUAI_PATH/nodelogs

	        echo "Sleep for $TIME_BETWEEN_TESTS"
	        # SLEEP BEFORE NEXT TEST
            sleep $TIME_BETWEEN_TESTS

	        echo "Start Node"
                make run

	        echo "Sleep for $SLEEP_BEFORE_MINING before starting the miner"
	        # Take a break before mining
            sleep $SLEEP_BEFORE_MINING

            # Retry until we get enough peers before starting to mine
            while true; do
                # Send the request and capture the response
                response=$(curl --silent --location 'http://localhost:8610/' \
                --header 'Content-Type: application/json' \
                --data '{
                  "jsonrpc": "2.0",
                  "method": "net_peerCount",
                  "params": [],
                  "id": 1
                }' | jq -r '.result')

                # Check if the response is "12"
                if [[ "$response" == $EXPECTED_PEERS ]]; then
                    echo "Got expected number of peers"
                    break
                else
                    sleep 1 # Wait for 1 second before retrying
                fi
            done

	        echo "Starting the Miner on 0-0"
	        cd $MINER_PATH && make run-mine-background region=0 zone=0
	        
	        echo "Going back to go-quai"
	        cd $GOQUAI_PATH
        else
            sleep $CHECK_INTERVAL
        fi
    done
done

