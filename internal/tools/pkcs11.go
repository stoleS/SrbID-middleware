package tools

import (
	"crypto/x509"
	"errors"
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
		return []uint{}, fmt.Errorf("no card present")
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

	if len(allSlots) == 0 {
		return status, fmt.Errorf("no slots present")
	}

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

// GetSigningCertificate Get the first slot with card inserted -> Open card session -> Find the signing cert by its object handle -> Parse it -> Close session
func (cm *CardManager) GetSigningCertificate() ([]byte, *x509.Certificate, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	slotID, err := cm.GetSlots(true)

	if err != nil {
		return nil, nil, err
	}

	session, err := cm.ctx.OpenSession(slotID[0], pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		cm.ctx.Destroy()
		return nil, nil, fmt.Errorf("OpenSession failed: %w", err)
	}
	defer cm.ctx.CloseSession(session)

	attrs, err := cm.ctx.GetAttributeValue(session, pkcs11.ObjectHandle(HandleSigningCert), []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("GetAttributeValue failed: %w", err)
	}

	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, nil, fmt.Errorf("certificate not found on card")
	}

	derBytes := attrs[0].Value

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return derBytes, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return derBytes, cert, nil
}

// Sign Prepare the hash for signing -> Find slot with card -> Open session -> Login -> Sign -> Logout -> Close session -> Return signed hash
func (cm *CardManager) Sign(pin string, hash []byte, algorithm string) ([]byte, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.ctx == nil {
		return nil, fmt.Errorf("card manager not initialized")
	}

	if pin == "" {
		return nil, fmt.Errorf("PIN cannot be empty")
	}

	if len(hash) == 0 {
		return nil, fmt.Errorf("hash cannot be empty")
	}

	digestInfo, err := digestInfoWrap(hash, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap digest: %w", err)
	}

	slotID, err := cm.GetSlots(true)
	if err != nil {
		return nil, fmt.Errorf("GetSlotList failed: %w", err)
	}

	session, err := cm.ctx.OpenSession(slotID[0], pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		cm.ctx.Destroy()
		return nil, fmt.Errorf("OpenSession failed: %w", err)
	}
	defer cm.ctx.CloseSession(session)

	if err := cm.ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		cm.ctx.Destroy()
		return nil, fmt.Errorf("login failed: %w", err)
	}
	defer cm.ctx.Logout(session)

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	if err := cm.ctx.SignInit(session, mechanism, pkcs11.ObjectHandle(HandleSigningKey)); err != nil {
		return nil, fmt.Errorf("failed to initialize signing: %w", err)
	}

	signature, err := cm.ctx.Sign(session, digestInfo)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signature, nil
}

// digestInfoWrap Raw hash cannot be used for signing so we need to prepare it as ASN.1 DigestInfo structure
func digestInfoWrap(hash []byte, algorithm string) ([]byte, error) {
	prefix, ok := digestInfoPrefixes[algorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	expectedLen, ok := hashLengths[algorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if len(hash) != expectedLen {
		return nil, fmt.Errorf("invalid hash length for %s: got %d, expected %d",
			algorithm, len(hash), expectedLen)
	}

	result := make([]byte, len(prefix)+len(hash))
	copy(result, prefix)
	copy(result[len(prefix):], hash)
	return result, nil
}

// MapPKCS11Error If something in pkcs#11 fails that is not handled before by our error checking, provide it to the user in a nice way
func MapPKCS11Error(err error) (httpStatus int, code string, message string) {
	if err == nil {
		return 200, "", ""
	}

	var pkcsErr pkcs11.Error
	ok := errors.As(err, &pkcsErr)
	if !ok {
		return 500, "internal_error", err.Error()
	}

	switch pkcsErr {
	case pkcs11.CKR_PIN_INCORRECT:
		return 401, "pin_incorrect", "Incorrect PIN"
	case pkcs11.CKR_PIN_LOCKED:
		return 403, "pin_locked", "PIN is locked (too many failed attempts)"
	case pkcs11.CKR_PIN_LEN_RANGE:
		return 400, "pin_invalid", "PIN must be 4-8 characters"
	case pkcs11.CKR_TOKEN_NOT_PRESENT:
		return 503, "card_not_present", "Smart card not inserted"
	case pkcs11.CKR_DEVICE_REMOVED:
		return 503, "card_removed", "Smart card was removed"
	case pkcs11.CKR_SLOT_ID_INVALID:
		return 503, "no_reader", "No card reader found"
	default:
		return 500, "pkcs11_error", fmt.Sprintf("PKCS#11 error: %v", pkcsErr)
	}
}
