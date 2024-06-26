./network.sh up createChannel -c channel2
cd addOrg3
./addOrg3.sh up -c channel2
../../bin/cryptogen generate --config=org3-crypto.yaml --output="../organizations"
../../bin/configtxgen -printOrg Org3MSP > ../organizations/peerOrganizations/org3.example.com/org3.json
docker-compose -f compose/compose-org3.yaml -f compose/docker/docker-compose-org3.yaml up -d
cd ..
source ./envG.sh
peer channel fetch config channel-artifacts/config_block.pb -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com -c channel2 --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

cd channel-artifacts
configtxlator proto_decode --input config_block.pb --type common.Block --output config_block.json
jq ".data.data[0].payload.data.config" config_block.json > config.json
jq -s '.[0] * {"channel_group":{"groups":{"Application":{"groups": {"Org3MSP":.[1]}}}}}' config.json ../organizations/peerOrganizations/org3.example.com/org3.json > modified_config.json
configtxlator proto_encode --input config.json --type common.Config --output config.pb
configtxlator proto_encode --input modified_config.json --type common.Config --output modified_config.pb
configtxlator compute_update --channel_id channel2 --original config.pb --updated modified_config.pb --output org3_update.pb
configtxlator proto_decode --input org3_update.pb --type common.ConfigUpdate --output org3_update.json
echo '{"payload":{"header":{"channel_header":{"channel_id":"'channel2'", "type":2}},"data":{"config_update":'$(cat org3_update.json)'}}}' | jq . > org3_update_in_envelope.json
cd ..

peer channel signconfigtx -f channel-artifacts/org3_update_in_envelope.pb
source ./envB.sh
peer channel update -f channel-artifacts/org3_update_in_envelope.pb -c channel2 -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

source ./envD.sh
peer channel fetch 0 channel-artifacts/channel2.block -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com -c channel2 --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
peer channel join -b channel-artifacts/channel2.block

CORE_PEER_GOSSIP_USELEADERELECTION=true
CORE_PEER_GOSSIP_ORGLEADER=false
./network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-go/ -ccl go -c channel2
source ./envD.sh
peer lifecycle chaincode package basic.tar.gz --path ../asset-transfer-basic/chaincode-go/ --lang golang --label basic_1
PACKAGE_ID=$(peer lifecycle chaincode calculatepackageid basic.tar.gz)
export CC_PACKAGE_ID=${PACKAGE_ID}
peer lifecycle chaincode install basic.tar.gz


peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" --channelID channel2 --name basic --version 1.0 --package-id $CC_PACKAGE_ID --sequence 1
source ./envB.sh
cd channel-artifacts
peer channel fetch config config_block.pb -o localhost:7050 -c channel2 --tls --cafile ${PWD}/../organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
jq .data.data[0].payload.data.config config_block.json > config.json
jq 'del(.channel_group.groups.Application.groups.Org2MSP)' config.json > modified_config.json
configtxlator proto_encode --input config.json --type common.Config --output config.pb
configtxlator proto_encode --input modified_config.json --type common.Config --output modified_config.pb
configtxlator compute_update --channel_id channel2 --original config.pb --updated modified_config.pb --output config_update.pb
configtxlator proto_decode --input config_update.pb --type common.ConfigUpdate --output config_update.json
echo '{"payload":{"header":{"channel_header":{"channel_id":"'channel2'", "type":2}},"data":{"config_update":'$(cat config_update.json)'}}}' | jq . > config_update_in_envelope.json
configtxlator proto_encode --input config_update_in_envelope.json --type common.Envelope --output config_update_in_envelope.pb
peer channel signconfigtx -f config_update_in_envelope.pb
peer channel update -f config_update_in_envelope.pb -c channel2 -o localhost:7050 --tls --cafile ${PWD}/../organizations/ordererOrganizations/example.com/msp/tlscacerts/tlsca.example.com-cert.pem
cd ..
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C channel2 -n basic --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" --peerAddresses localhost:11051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt" -c '{"function":"InitLedger","Args":[]}'
source ./envG.sh
cd channel-artifacts
peer channel update -f config_update_in_envelope.pb -c channel2 -o localhost:7050 --tls --cafile ${PWD}/../organizations/ordererOrganizations/example.com/msp/tlscacerts/tlsca.example.com-cert.pem






