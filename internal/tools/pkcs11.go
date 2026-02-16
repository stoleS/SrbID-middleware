package tools

import (
	"crypto/x509"
	"fmt"
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
	// Load the srb-id-pkcs11.dylib
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", modulePath)
	}

	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("PKCS#11 initialize failed: %w", err)
	}

	return &CardManager{
		modulePath: modulePath,
		ctx:        ctx,
	}, nil
}

func (cm *CardManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.ctx != nil {
		// Release the memory and unload the srb-id-pkcs11.dylib
		err := cm.ctx.Finalize()
		cm.ctx.Destroy()
		return err
	}
	return nil
}

// GetSlots true -> Only slots WITH a token inserted, false -> ALL slots
func (cm *CardManager) GetSlots(withToken bool) ([]uint, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	slots, err := cm.ctx.GetSlotList(withToken)
	if err != nil {
		return []uint{}, err
	}

	if len(slots) == 0 {
		return []uint{}, fmt.Errorf("No card present")
	}

	return slots, nil
}

// GetStatus Go through the available slots and check if any are available and have the card inserted
func (cm *CardManager) GetStatus() (CardStatus, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	status := CardStatus{}

	allSlots, err := cm.GetSlots(false)
	if err != nil {
		return status, fmt.Errorf("GetSlotList failed: %w", err)
	}
	status.ReaderConnected = len(allSlots) > 0

	tokenSlots, err := cm.GetSlots(true)
	if err != nil {
		return status, nil
	}
	status.CardPresent = len(tokenSlots) > 0

	if status.CardPresent {
		tokenInfo, err := cm.ctx.GetTokenInfo(tokenSlots[0])
		if err == nil {
			status.TokenLabel = tokenInfo.Label
		}
	}

	return status, nil

}

func (cm *CardManager) GetSigningCertificate() ([]byte, *x509.Certificate, error) {}

func (cm *CardManager) Sign(pin string, hash []byte, algorithm string) ([]byte, error) {}

func digestInfoWrap(hash []byte, algorithm string) ([]byte, error) {}

func mapPKCS11Error(err error) (httpStatus int, code string, message string) {}
