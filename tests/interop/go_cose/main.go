// go-cose is a test-only COSE_Sign1 oracle for wolfCOSE interoperability.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const (
	maxMessageSize = 2048
	p256DERBase64  = "MHcCAQEEIAMc7GQ5oxpE/Jrk2S+fxT6IzdQIVBb7f+wh1i6ief93oAoGCCqGSM49AwEHoUQDQgAEhw4Ot5NqlZzyjFDnvmqHuTN0VBBy4ishX5BHf8i5xiC3b9tvdsQWHhXuHaHAG7QJXLf+TmhWSrFKoXYhOMYjAA=="
	psaProfile     = "tag:psacertified.org,2023:psa#tfm"
	psaSign1Hex    = "d28443a10126a0590100a819010058210102020202020202020202020202" +
		"0202020202020202020202020202020202020219095c5820000000000000" +
		"00000000000000000000000000000000000000000000000000000a582001" +
		"010101010101010101010101010101010101010101010101010101010101" +
		"0119095a1a7fffffff19095b19300019010978217461673a707361636572" +
		"7469666965642e6f72672c323032333a7073612374666d19010c48000000" +
		"000000000019095f81a30558200404040404040404040404040404040404" +
		"040404040404040404040404040404025820030303030303030303030303" +
		"0303030303030303030303030303030303030303016450526f545840786e" +
		"937a4c42667af3847399319ca95c7e7dbabdc9b50fdb8de3f6bff4ab82ff" +
		"80c42140e2a488000219e3e10663193da69c75f52b798ea10b2f7041a90e" +
		"8e5a"
)

var payload = []byte("wolfCOSE<->go-cose COSE_Sign1 interoperability")

var psaSign1X = []byte{
	0x4e, 0x5e, 0x22, 0x09, 0x9e, 0x3b, 0xce, 0xb4,
	0x5b, 0x44, 0x6d, 0x13, 0x55, 0xfd, 0x1d, 0xc3,
	0xb5, 0x45, 0x94, 0x7b, 0x6f, 0xd7, 0xc1, 0xc8,
	0x9d, 0x88, 0x67, 0x98, 0xc3, 0x72, 0x6e, 0x8f,
}

var psaSign1Y = []byte{
	0x80, 0xd7, 0x0b, 0x84, 0x0b, 0x25, 0x6a, 0xac,
	0x34, 0xa6, 0x2e, 0xde, 0x10, 0x43, 0x36, 0x4f,
	0x04, 0x40, 0x95, 0xf0, 0x03, 0x47, 0x4b, 0x91,
	0xe0, 0x18, 0x20, 0x92, 0xaf, 0xb1, 0x3f, 0x2e,
}

func signingKey() (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(p256DERBase64)
	if err != nil {
		return nil, fmt.Errorf("decode fixed P-256 key: %w", err)
	}

	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse fixed P-256 key: %w", err)
	}

	return key, nil
}

func sign() error {
	key, err := signingKey()
	if err != nil {
		return err
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		return fmt.Errorf("create ES256 signer: %w", err)
	}

	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
		},
	}
	encoded, err := cose.Sign1(rand.Reader, signer, headers, payload, nil)
	if err != nil {
		return fmt.Errorf("sign COSE_Sign1: %w", err)
	}

	written, err := os.Stdout.Write(encoded)
	if err != nil {
		return fmt.Errorf("write COSE_Sign1: %w", err)
	}
	if written != len(encoded) {
		return fmt.Errorf("write COSE_Sign1: wrote %d of %d bytes", written,
			len(encoded))
	}

	return nil
}

func verify(encoded []byte) error {
	key, err := signingKey()
	if err != nil {
		return err
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &key.PublicKey)
	if err != nil {
		return fmt.Errorf("create ES256 verifier: %w", err)
	}

	var message cose.Sign1Message
	if err = message.UnmarshalCBOR(encoded); err != nil {
		return fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	if err = message.Verify(nil, verifier); err != nil {
		return fmt.Errorf("verify COSE_Sign1: %w", err)
	}
	if !bytes.Equal(message.Payload, payload) {
		return fmt.Errorf("verify COSE_Sign1: payload mismatch")
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 0x01
	var invalid cose.Sign1Message
	if err = invalid.UnmarshalCBOR(tampered); err == nil {
		if err = invalid.Verify(nil, verifier); err == nil {
			return fmt.Errorf("verify COSE_Sign1: accepted a tampered signature")
		}
	}

	return nil
}

func runVerify() error {
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin, maxMessageSize+1))
	if err != nil {
		return fmt.Errorf("read COSE_Sign1: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maxMessageSize {
		return fmt.Errorf("read COSE_Sign1: invalid message length %d", len(encoded))
	}

	return verify(encoded)
}

func verifyPSAAttestation() error {
	encoded, err := hex.DecodeString(psaSign1Hex)
	if err != nil {
		return fmt.Errorf("decode RFC 9783 token: %w", err)
	}

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(psaSign1X),
		Y:     new(big.Int).SetBytes(psaSign1Y),
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
	if err != nil {
		return fmt.Errorf("create PSA ES256 verifier: %w", err)
	}

	var message cose.Sign1Message
	if err = message.UnmarshalCBOR(encoded); err != nil {
		return fmt.Errorf("decode RFC 9783 COSE_Sign1: %w", err)
	}
	if err = message.Verify(nil, verifier); err != nil {
		return fmt.Errorf("verify RFC 9783 COSE_Sign1: %w", err)
	}

	var claims map[int64]interface{}
	if err = cbor.Unmarshal(message.Payload, &claims); err != nil {
		return fmt.Errorf("decode RFC 9783 EAT claims: %w", err)
	}

	expectedUEID := append([]byte{0x01}, bytes.Repeat([]byte{0x02}, 32)...)
	ueid, ok := claims[256].([]byte)
	if !ok || !bytes.Equal(ueid, expectedUEID) {
		return fmt.Errorf("decode RFC 9783 EAT claims: UEID mismatch")
	}

	nonce, ok := claims[10].([]byte)
	if !ok || !bytes.Equal(nonce, bytes.Repeat([]byte{0x01}, 32)) {
		return fmt.Errorf("decode RFC 9783 EAT claims: nonce mismatch")
	}

	profile, ok := claims[265].(string)
	if !ok || profile != psaProfile {
		return fmt.Errorf("decode RFC 9783 EAT claims: profile mismatch")
	}

	bootSeed, ok := claims[268].([]byte)
	if !ok || !bytes.Equal(bootSeed, make([]byte, 8)) {
		return fmt.Errorf("decode RFC 9783 EAT claims: boot seed mismatch")
	}

	return nil
}

func main() {
	var err error

	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go_cose_oracle sign|verify|psa")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "sign":
		err = sign()
	case "verify":
		err = runVerify()
	case "psa":
		err = verifyPSAAttestation()
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "go-cose interop:", err)
		os.Exit(1)
	}
}
