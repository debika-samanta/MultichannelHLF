export PATH=$PATH:$(pwd)/../../../bin
export export FABRIC_CFG_PATH=$(pwd)/../../../config/

export ORDERER_CA=$(pwd)/../../organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
export PEER0_ORG1_CA=$(pwd)/../../organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem
export PEER0_ORG2_CA=$(pwd)/../../organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem

export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org2MSP
export CORE_PEER_MSPCONFIGPATH=$(pwd)/../../organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=$(pwd)/../../organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_ADDRESS=localhost:9051

go run wallet.go