package chaincode

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing an OwnershipRecords
type SmartContract struct {
	contractapi.Contract
}

const tokenPrefix = "token"

type OwnershipRecord struct {
	BlockchainID         string           `json:"BlockchainID"`
	OwnershipRecordID    string           `json:"OwnershipRecordID"`
	OwnerAddress         string           `json:"OwnerAddress"`
	DestinedOwnerAddress string           `json:"DestinedOwnerAddress"`
	TokenType            string           `json:"TokenType"`
	TokenAddress         string           `json:"TokenAddress"`
	TokenValue           int              `json:"TokenValue"`
	TokenKey             map[string]Token `json:"TokenKey"`
	Data                 string           `json:"Data"`
	TransactionState     int              `json:"TransactionState"`
	DigitalAssetID       string           `json:"DigitalAssetID"`
	TokenValidityHash    string           `json:"TokenValidityHash"`
}

type Token struct {
	Name          string `json:"name"`
	Symbol        string `json:"symbol"`
	Decimals      int    `json:"decimals"`
	TotalSupply   int    `json:"totalSupply"`
	MinterAddress string `json:"minterAddress"`
}

type TokenBalance struct {
	TokenKey map[string]Token `json:"TokenKey"`
	Balance  int              `json:"balance"`
}

// InitLedger adds a base set of OwnershipRecord to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	records := []OwnershipRecord{
		{BlockchainID: "1", OwnershipRecordID: "1", OwnerAddress: "0x123", DestinedOwnerAddress: "0x456", TokenType: "ERC20", TokenAddress: "0x789", TokenKey: nil, TokenValue: 50, Data: "data", TransactionState: 1, DigitalAssetID: "1", TokenValidityHash: "0x123"},
	}

	for _, records := range records {
		var err error
		recordJSON, err := json.Marshal(records)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(records.OwnershipRecordID, recordJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world TransactionState. %v", err)
		}
	}

	return nil
}

// SmartContract to read ownership record from the world state
func (s *SmartContract) ReadOwnershipRecord(ctx contractapi.TransactionContextInterface, ownershipRecordID string) (*OwnershipRecord, error) {
	recordJSON, err := ctx.GetStub().GetState(ownershipRecordID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world TransactionState: %v", err)
	}
	if recordJSON == nil {
		return nil, fmt.Errorf("the ownership record %s does not exist", ownershipRecordID)
	}

	var record OwnershipRecord
	err = json.Unmarshal(recordJSON, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

func encrypt(plainText, keyString string) (string, error) {
	// Convert the key string to a byte array
	key := []byte(keyString)

	// Generate a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Generate a new Galois Counter Mode (GCM) cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Encrypt the plaintext using the GCM cipher
	ciphertext := gcm.Seal(nonce, nonce, []byte(plainText), nil)

	// Return the ciphertext as a base64-encoded string
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext, keyString string) (string, error) {
	// Convert the key string to a byte array
	key := []byte(keyString)

	// Decode the ciphertext from base64 string
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Generate a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Generate a new Galois Counter Mode (GCM) cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Get the nonce size from the GCM cipher
	nonceSize := gcm.NonceSize()

	// Extract the nonce and ciphertext from the ciphertext bytes
	nonce, ciphertextBytes := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]

	// Decrypt the ciphertext using the GCM cipher
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	// Return the plaintext as a string
	return string(plaintext), nil
}

func (s *SmartContract) HTLCLocking(ctx contractapi.TransactionContextInterface, ownershipRecordID string, destinedOwnerAddress string, secret string) (string, error) {
	Exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}
	if !Exists {
		return " ", fmt.Errorf("the record %s does not exist", ownershipRecordID)
	}

	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}

	var Txid = ctx.GetStub().GetTxID()
	fmt.Println("Txid is ", Txid)

	tokenadd := record.TokenAddress
	encryptedTokenAddress, err := encrypt(tokenadd, secret)
	if err != nil {
		return " ", err
	}

	record.TransactionState = 0
	record.DestinedOwnerAddress = destinedOwnerAddress
	record.TokenAddress = encryptedTokenAddress

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return " ", err
	}

	err = ctx.GetStub().PutState(ownershipRecordID, recordJSON)
	if err != nil {
		return " ", err
	}

	return Txid, nil
}

func (s *SmartContract) HTLCWithdraw(ctx contractapi.TransactionContextInterface, ownershipRecordID string, newOwnerAddress string, secret string, TransactionState int) (string, error) {
	Exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}
	if !Exists {
		return " ", fmt.Errorf("the record %s does not exist", ownershipRecordID)
	}

	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}

	var Txid = ctx.GetStub().GetTxID()
	fmt.Println("Txid is ", Txid)

	tokenadd := record.TokenAddress
	decryptedTokenAddress, err := decrypt(tokenadd, secret)
	if err != nil {
		return " ", err
	}

	record.TransactionState = 0
	record.DestinedOwnerAddress = newOwnerAddress
	record.TokenAddress = decryptedTokenAddress

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return " ", err
	}

	err = ctx.GetStub().PutState(ownershipRecordID, recordJSON)
	if err != nil {
		return " ", err
	}

	return Txid, nil
}

func (s *SmartContract) HTLCReturn(ctx contractapi.TransactionContextInterface, ownershipRecordID string, secret string) (string, error) {
	Exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}
	if !Exists {
		return " ", fmt.Errorf("the record %s does not exist", ownershipRecordID)
	}

	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}

	var Txid = ctx.GetStub().GetTxID()
	fmt.Println("Txid is ", Txid)

	tokenadd := record.TokenAddress
	decryptedTokenAddress, err := decrypt(tokenadd, secret)
	if err != nil {
		return " ", err
	}

	AssetOwnerAddress := record.OwnerAddress
	record.TransactionState = -1
	record.DestinedOwnerAddress = AssetOwnerAddress
	record.TokenAddress = decryptedTokenAddress

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return " ", err
	}

	err = ctx.GetStub().PutState(ownershipRecordID, recordJSON)
	if err != nil {
		return " ", err
	}

	return Txid, nil
}

func (s *SmartContract) CreateTokenOwnershipRecord(ctx contractapi.TransactionContextInterface, ownershipRecordID string, blockchainId string, tokenType string, OwnerAddress string, value int, data string, digitalassetId string, tokenAddress string, tokenvalidityhash string) (string, error) {
	Exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}
	if !Exists {
		return " ", fmt.Errorf("the record %s does not exist", ownershipRecordID)
	}

	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}

	var Txid = ctx.GetStub().GetTxID()
	fmt.Println("Txid is ", Txid)

	// Fill the record details.

	record.BlockchainID = blockchainId
	record.OwnerAddress = OwnerAddress
	record.TokenValue = value
	record.Data = data
	record.TokenAddress = tokenAddress
	record.DigitalAssetID = digitalassetId
	record.TokenValidityHash = tokenvalidityhash

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return " ", err
	}

	err = ctx.GetStub().PutState(ownershipRecordID, recordJSON)
	if err != nil {
		return " ", err
	}

	return Txid, nil
}

// SmartContract to delete an OwnershipRecord from the worldState.
func (s *SmartContract) DeleteOwnershipRecord(ctx contractapi.TransactionContextInterface, ownershipRecordID string) error {
	exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the record %s does not exist", ownershipRecordID)
	}

	return ctx.GetStub().DelState(ownershipRecordID)
}

// AssetExists returns true when asset with given ID exists in worldState
func (s *SmartContract) OwnershipRecordExists(ctx contractapi.TransactionContextInterface, ownershipRecordID string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(ownershipRecordID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world TransactionState: %v", err)
	}

	return assetJSON != nil, nil
}

// SmartContract to transfer ownership of a token to a destined owner address if ownership accepted by the destined owner
func (s *SmartContract) TransferOwnership(ctx contractapi.TransactionContextInterface, ownershipRecordID string) (string, error) {

	Exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return "", err
	}
	if !Exists {
		return "", fmt.Errorf("the record %s does not exist", ownershipRecordID)
	}

	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return "", err
	}

	oldOwnerAddress := record.OwnerAddress
	record.OwnerAddress = record.DestinedOwnerAddress
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return "", err
	}

	err = ctx.GetStub().PutState(ownershipRecordID, recordJSON)
	if err != nil {
		return "", err
	}

	return oldOwnerAddress, nil
}

// SmartContract to rollback ownership of a token to a previous owner address if ownership rejected by the destined owner
func (s *SmartContract) RollbackOwnership(ctx contractapi.TransactionContextInterface, ownershipRecordID string, oldOwnerAddress string) (string, error) {

	Exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return "", err
	}
	if !Exists {
		return "", fmt.Errorf("the record %s does not exist", ownershipRecordID)
	}

	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return "", err
	}

	record.DestinedOwnerAddress = oldOwnerAddress
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return "", err
	}

	err = ctx.GetStub().PutState(ownershipRecordID, recordJSON)
	if err != nil {
		return "", err
	}

	return oldOwnerAddress, nil
}

// SmartContract to get all ownership records of a particular account address
func (s *SmartContract) GetAllOwnershipRecords(ctx contractapi.TransactionContextInterface, accountAddress string) ([]*OwnershipRecord, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all assets in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var records []*OwnershipRecord
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var record OwnershipRecord
		err = json.Unmarshal(queryResponse.Value, &record)
		if err != nil {
			return nil, err
		}

		if record.OwnerAddress == accountAddress {
			records = append(records, &record)
		}
	}

	return records, nil
}

func (s *SmartContract) ReadOwnershipData(ctx contractapi.TransactionContextInterface, ownershipRecordID string) (string, error) {
	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return "", err
	}

	return record.Data, nil
}

// ## modified in the smart contract (also need to modify for Eth2Fab)
// SmartContract to update the TransactionState of the ownership record in the worldState as per the input destination owner
func (s *SmartContract) UpdateOwnershipRecord(ctx contractapi.TransactionContextInterface, ownershipRecordID string, transactionState int, destinationOwnerAddress string) (string, error) {
	Exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}
	if !Exists {
		return " ", fmt.Errorf("the record %s does not exist", ownershipRecordID)
	}

	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}

	var Txid = ctx.GetStub().GetTxID()
	fmt.Println("Txid is ", Txid)

	// update the TransactionState of the ownership record in the worldState as per the input by Bob  (modified in the smart contract -->instead of y/n --give 1/0/-1)
	record.TransactionState = transactionState
	record.DestinedOwnerAddress = destinationOwnerAddress

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return " ", err
	}

	err = ctx.GetStub().PutState(ownershipRecordID, recordJSON)
	if err != nil {
		return " ", err
	}
	//## doubt here -- Is "data" feild is txid of tokenMint or tokenTransfer
	return Txid, nil
}

// SmartContract to put the signature of the owner in the worldState of the ownership record
func (s *SmartContract) GenerateSignature(ctx contractapi.TransactionContextInterface, signature string, ownershipRecordID string) (string, error) {

	exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}
	if !exists {
		return " ", fmt.Errorf("the record %s does not exists", ownershipRecordID)
	}

	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return "", err
	}

	data := record.Data
	if signature != "" {
		record.Data = data + " @del " + signature
	}

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return "", err
	}

	err = ctx.GetStub().PutState(ownershipRecordID, recordJSON)
	if err != nil {
		return "", err
	}

	return signature, nil
}

// Smart Contract to remove the signature of the owner from the worldState of the ownership record
func (s *SmartContract) RemoveSignature(ctx contractapi.TransactionContextInterface, ownershipRecordID string) (string, error) {
	exists, err := s.OwnershipRecordExists(ctx, ownershipRecordID)
	if err != nil {
		return " ", err
	}
	if !exists {
		return " ", fmt.Errorf("the record %s does not exists", ownershipRecordID)
	}

	record, err := s.ReadOwnershipRecord(ctx, ownershipRecordID)
	if err != nil {
		return "", err
	}

	data := record.Data
	record.Data = strings.Split(data, " @del ")[0]

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return "", err
	}

	err = ctx.GetStub().PutState(ownershipRecordID, recordJSON)
	if err != nil {
		return "", err
	}

	return " ", nil
}

// token minting smart contracts   //

// smart contract to create a new token
func (s *SmartContract) MintToken(ctx contractapi.TransactionContextInterface, name string, symbol string, decimals int, totalSupply int, minterAddress string) (string, error) {
	// check if the token already exists
	tokenKey, err := ctx.GetStub().CreateCompositeKey(tokenPrefix, []string{name, symbol})
	if err != nil {
		return "", fmt.Errorf("failed to create composite key: %v", err)
	}

	Exists, err := s.TokenExists(ctx, tokenKey)
	if err != nil {
		return "", err
	}
	if Exists {
		return "", fmt.Errorf("the token %s already exists", name)
	}

	//check authorization of the user , Org2MSP is the only one authorized to create a new token
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("failed getting MSPID: %v", err)
	}
	if clientMSPID != "Org2MSP" {
		return "", fmt.Errorf("the client is not authorized to mint new tokens")
	}

	//get client address from the wallet
	MinterAddress := minterAddress
	if MinterAddress == "" {
		return "", fmt.Errorf("the client address can not be empty")
	}

	if totalSupply <= 0 {
		return "", fmt.Errorf("total supply must be positive")
	}

	token := Token{
		Name:          name,
		Symbol:        symbol,
		Decimals:      decimals,
		TotalSupply:   totalSupply,
		MinterAddress: minterAddress,
	}

	//map token key to token struct
	tokenKeyMap := make(map[string]Token)
	tokenKeyMap[tokenKey] = token

	//get token balance from the world state
	amount := token.TotalSupply

	//get tnx id
	OwnershipRecordID := ctx.GetStub().GetTxID()

	record := OwnershipRecord{
		OwnershipRecordID:    OwnershipRecordID,
		BlockchainID:         "1",
		OwnerAddress:         minterAddress,
		DestinedOwnerAddress: "",
		TokenType:            "erc20",
		TokenAddress:         string(rand.Intn(200)),
		TokenValue:           amount,
		TokenKey:             tokenKeyMap,
		DigitalAssetID:       "",
		Data:                 OwnershipRecordID,
		TransactionState:     1,
		TokenValidityHash:    "abcd",
	}

	OwnershipRecordJSON, err := json.Marshal(record)
	if err != nil {
		return "", err
	}

	err = ctx.GetStub().PutState(OwnershipRecordID, OwnershipRecordJSON)
	if err != nil {
		return "", err
	}

	return OwnershipRecordID, nil
}

// smart contract to getBalance of a token
func (s *SmartContract) GetBalance(ctx contractapi.TransactionContextInterface, OwnerAddress string) ([]*TokenBalance, error) {
	//get all the tokens from the world state whose owner is the same as the owner address
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var tokenBalances []*TokenBalance

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var record OwnershipRecord
		err = json.Unmarshal(queryResponse.Value, &record)
		if err != nil {
			return nil, err
		}

		if record.OwnerAddress == OwnerAddress {
			tokenBalances = append(tokenBalances, &TokenBalance{TokenKey: record.TokenKey, Balance: record.TokenValue})
		}
	}

	return tokenBalances, nil
}

// smart contract to check if the token exists or not
func (s *SmartContract) TokenExists(ctx contractapi.TransactionContextInterface, tokenKey string) (bool, error) {
	// Check if the token already exists
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return true, err
	}
	defer resultsIterator.Close()

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return true, err
		}

		var record OwnershipRecord
		err = json.Unmarshal(queryResponse.Value, &record)
		if err != nil {
			return true, err
		}

		//compare key with token key
		recordTokenKey := record.TokenKey
		for key := range recordTokenKey {
			if key == tokenKey {
				return true, nil
			}
		}
	}
	return false, nil
}
