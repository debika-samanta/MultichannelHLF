./network.sh down
./network.sh up createChannel -c channel1 -s couchdb
./network.sh deployCC -c channel1 -ccn basic1 -ccp ../asset-transfer-basic/chaincode-go -ccl go
./monitordocker.sh