package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/tdx"
	"github.com/google/gce-tcb-verifier/testing/fakeovmf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const upstreamSyntheticMRTD = "6e540be4917f24f74cc3292b59803d06dc7c38eb4a3c1fd6be9c735ba74bb7a23e25f98da94779d17508b243e4fb582b"

type syntheticEndorsement struct {
	firmware []byte
	golden   *epb.VMGoldenMeasurement
	signer   *rsa.PrivateKey
	roots    *x509.CertPool
	now      time.Time
}

func synthetic(t *testing.T) syntheticEndorsement {
	t.Helper()
	now := time.Date(2026, time.September, 27, 0, 0, 0, 0, time.UTC)
	firmware := fakeovmf.CleanExample(t, 2*1024*1024)
	mrtd, err := tdx.MRTD(tdx.LaunchOptionsDefault(""), firmware)
	if err != nil {
		t.Fatal(err)
	}
	// This value is Google's synthetic CleanTdxExampleMeasurement from the
	// pinned verify/verifytest package. It detects an unexpected recipe change,
	// but is not an independent MRTD implementation or production firmware.
	if got := hex.EncodeToString(mrtd[:]); got != upstreamSyntheticMRTD {
		t.Fatalf("pinned upstream synthetic MRTD changed: %s", got)
	}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	signerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic test signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signer, rootCert, &signerKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	digest := sha512.Sum384(firmware)
	return syntheticEndorsement{
		firmware: firmware, signer: signerKey, roots: roots, now: now,
		golden: &epb.VMGoldenMeasurement{
			Timestamp: timestamppb.New(now), Commit: []byte("synthetic-commit"),
			Cert: signerDER, Digest: digest[:],
			Tdx: &epb.VMTdx{Svn: 42, Measurements: []*epb.VMTdx_Measurement{{Mrtd: mrtd[:]}}},
		},
	}
}

func (s syntheticEndorsement) signed(t *testing.T) []byte {
	t.Helper()
	payload, err := proto.Marshal(s.golden)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	signature, err := rsa.SignPSS(rand.Reader, s.signer, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(&epb.VMLaunchEndorsement{
		SerializedUefiGolden: payload, Signature: signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEmbeddedGoogleRootHasReviewedHash(t *testing.T) {
	if _, err := trustedRoot(); err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticSignedGenericReferenceIsDiagnosticOnly(t *testing.T) {
	s := synthetic(t)
	result, err := inspect(s.signed(t), s.firmware, s.roots, s.now)
	if err != nil {
		t.Fatal(err)
	}
	if result.MRTD != upstreamSyntheticMRTD || result.PrivateModeApproved || result.MeasurementProfile != "google_current_generic" {
		t.Fatalf("wrong diagnostic result: %+v", result)
	}
}

func TestRejectsBadSignatureRootFirmwareAndExpiry(t *testing.T) {
	s := synthetic(t)
	good := s.signed(t)
	wrongFirmware := append([]byte(nil), s.firmware...)
	wrongFirmware[0x800] ^= 1
	if _, err := inspect(good, wrongFirmware, s.roots, s.now); err == nil {
		t.Fatal("changed firmware accepted")
	}
	wrongRoots := x509.NewCertPool()
	if _, err := inspect(good, s.firmware, wrongRoots, s.now); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	if _, err := inspect(good, s.firmware, s.roots, s.now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired signing certificate accepted")
	}
	badSignature := new(epb.VMLaunchEndorsement)
	if err := proto.Unmarshal(good, badSignature); err != nil {
		t.Fatal(err)
	}
	badSignature.Signature[0] ^= 1
	mutated, err := proto.Marshal(badSignature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspect(mutated, s.firmware, s.roots, s.now); err == nil {
		t.Fatal("changed signature accepted")
	}
}

func TestRejectsWrongOrAmbiguousSignedTDXMeasurement(t *testing.T) {
	s := synthetic(t)
	s.golden.Tdx.Measurements[0].Mrtd[0] ^= 1
	if _, err := inspect(s.signed(t), s.firmware, s.roots, s.now); err == nil {
		t.Fatal("wrong signed MRTD accepted")
	}
	s.golden.Tdx.Measurements[0].Mrtd[0] ^= 1
	s.golden.Tdx.Measurements = append(s.golden.Tdx.Measurements,
		&epb.VMTdx_Measurement{Mrtd: append([]byte(nil), s.golden.Tdx.Measurements[0].Mrtd...)})
	if _, err := inspect(s.signed(t), s.firmware, s.roots, s.now); err == nil {
		t.Fatal("ambiguous generic measurement accepted")
	}
	s.golden.Tdx.Measurements[1].RamGib = 16
	if _, err := inspect(s.signed(t), s.firmware, s.roots, s.now); err != nil {
		t.Fatalf("unselected legacy measurement should not invalidate generic reference: %v", err)
	}
	s.golden.Tdx.Measurements[0].RamGib = 32
	if _, err := inspect(s.signed(t), s.firmware, s.roots, s.now); err == nil {
		t.Fatal("missing generic measurement accepted")
	}
	s.golden.Tdx = nil
	if _, err := inspect(s.signed(t), s.firmware, s.roots, s.now); err == nil {
		t.Fatal("non-TDX endorsement accepted")
	}
}
