package tools

import (
	"crypto/x509"
	"sync"

	"github.com/miekg/pkcs11"
)

// Object handles from srb-id-pkcs11 source (srb-id-pkcs11/src/consts.zig)
const (
	HandleSigningCert = 0x80000030
	HandleSigningKey  = 0x80000020
	HandlePublicKey   = 0x80000008
)

// DigestInfo ASN.1 prefixes for PKCS#1 v1.5 used to identify the hash algorithm
var digestInfoPrefixes = map[string][]byte{
	"SHA-1":   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	"SHA-256": {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	"SHA-384": {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	"SHA-512": {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// Expected hash lengths per algorithm
var hashLengths = map[string]int{
	"SHA-1":   20,
	"SHA-256": 32,
	"SHA-384": 48,
	"SHA-512": 64,
}

type CardStatus struct {
	ReaderConnected bool   `json:"readerConnected"`
	CardPresent     bool   `json:"cardPresent"`
	TokenLabel      string `json:"tokenLabel,omitempty"`
}

type CardManager struct {
	modulePath string
	ctx        *pkcs11.Ctx
	mu         sync.Mutex
}

func InitializeCardManager(modulePath string) (*CardManager, error) {
	return &CardManager{modulePath: modulePath}, nil
}

func (cm *CardManager) Close() error {
	return nil
}

func (cm *CardManager) FindSlot() (uint, error) {}

func (cm *CardManager) GetStatus() (CardStatus, error) {}

func (cm *CardManager) GetSigningCertificate() ([]byte, *x509.Certificate, error) {}

func (cm *CardManager) Sign(pin string, hash []byte, algorithm string) ([]byte, error) {}

func digestInfoWrap(hash []byte, algorithm string) ([]byte, error) {}

func mapPKCS11Error(err error) (httpStatus int, code string, message string) {}
