package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto"
	//need to install go get github.com/ethereum/go-ethereum/crypto
)

// main func
func main() {
	err := createWallet()
	if err != nil {
		return
	}
}

// Wallet struct
type Wallet struct {
	Account_Address string
	Balance         float64
	// PrivateKey string
	// PublicKey string
	Cert string
}

type EcdsaKey struct {
	PubKey  *ecdsa.PublicKey
	PrivKey *ecdsa.PrivateKey
}

func (k *EcdsaKey) ImportPrivKeyFromFile(file string) (err error) {

	keyFile := []byte(file)
	keyBlock, _ := pem.Decode(keyFile)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return
	}

	k.PrivKey = key.(*ecdsa.PrivateKey)
	k.PubKey = &k.PrivKey.PublicKey

	// fmt.Println("Private key: ", k.PrivKey)
	// fmt.Println("Public key: ", k.PubKey)

	return
}

// AddressFromPrivateKey returns the address of the given private key.
func AddressFromPrivateKey(privateKey string) string {
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return ""
	}
	privateKeyECDSA, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return ""
	}
	publicKey := privateKeyECDSA.Public()
	// fmt.Println("public key :",publicKey)
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return ""
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	return address
}

// create path /organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
func createWallet() (err error) {
	fmt.Println("Creating wallet.json file")
	w := &Wallet{}
	key := &EcdsaKey{}
	credPath := filepath.Join(
		"..",
		"..",
		"organizations",
		"peerOrganizations",
		"org2.example.com",
		"users",
		"Admin@org2.example.com",
		"msp",
	)

	// fmt.Println(credPath)
	//fetch priv_key from directory
	keyfile, err := os.ReadDir(filepath.Join(credPath, "keystore"))
	if err != nil {
		return err
	}
	keyPath := path.Join(credPath, "keystore")
	privkey, err := os.ReadFile(path.Join(keyPath, keyfile[0].Name()))
	if err != nil {
		return err
	}
	// fmt.Println(string(privkey))
	//convert key to string
	keyString := string(privkey)

	err1 := key.ImportPrivKeyFromFile(keyString)
	if err != nil {
		fmt.Println(err1)
		return err1
	}
	// w.PrivateKey = hex.EncodeToString(key.PrivKey.D.Bytes())
	// fmt.Println("privet key :",w.PrivateKey)

	//convert public key to string
	// w.PublicKey = hex.EncodeToString(key.PubKey.X.Bytes())
	// fmt.Println("public key :",w.PublicKey)
	//fetch cert from directory
	certfile, err := os.ReadDir(filepath.Join(credPath, "signcerts"))
	if err != nil {
		return err
	}
	certPath := path.Join(credPath, "signcerts")
	cert, err := os.ReadFile(path.Join(certPath, certfile[0].Name()))
	if err != nil {
		return err
	}
	w.Cert = string(cert)
	// fmt.Println(w.Cert)
	w.Balance = 0.0

	//generate address from private key using web3
	Address := AddressFromPrivateKey(hex.EncodeToString(key.PrivKey.D.Bytes()))
	w.Account_Address = Address
	// fmt.Println("Address: ", w.Address)

	//convert struct into json format and write to file
	walletJSON, err := json.Marshal(w)
	if err != nil {
		return err
	}

	err = os.WriteFile("wallet.json", walletJSON, 0644)
	if err != nil {
		return err
	}
	fmt.Println("wallet.json file created")
	return nil
}