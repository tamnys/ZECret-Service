// gcp-endorsement reconstructs a candidate Google TDX firmware reference.
// It is an offline release-review tool, not a native-client trust decision.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/tdx"
	"github.com/google/gce-tcb-verifier/verify"
	"google.golang.org/protobuf/proto"
)

// This certificate is the DER file published at
// https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt . Its hash is a
// reviewed, immutable input. Root rotation requires a new reviewed tool.
//
//go:embed roots/GCE-cc-tcb-root_1.crt
var googleRootDER []byte

const (
	googleRootSHA256   = "e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c"
	googleSourceCommit = "022f7554a942ea49f1085256104df1de9c8b3e98"
)

type report struct {
	SchemaVersion               int    `json:"schema_version"`
	Status                      string `json:"status"`
	EndorsementSHA256           string `json:"endorsement_sha256"`
	FirmwareSHA384              string `json:"firmware_sha384"`
	GoogleRootCertificateSHA256 string `json:"google_root_certificate_sha256"`
	GoogleVerifierCommit        string `json:"google_verifier_commit"`
	MeasurementProfile          string `json:"measurement_profile"`
	TDXFirmwareSVN              uint32 `json:"tdx_firmware_svn"`
	MRTD                        string `json:"mrtd"`
	PrivateModeApproved         bool   `json:"private_mode_approved"`
}

func trustedRoot() (*x509.CertPool, error) {
	digest := sha256.Sum256(googleRootDER)
	if hex.EncodeToString(digest[:]) != googleRootSHA256 {
		return nil, errors.New("embedded Google root certificate hash mismatch")
	}
	cert, err := x509.ParseCertificate(googleRootDER)
	if err != nil {
		return nil, fmt.Errorf("parse embedded Google root certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return roots, nil
}

func inspect(endorsementBytes, firmware []byte, roots *x509.CertPool, now time.Time) (report, error) {
	var result report
	if len(endorsementBytes) == 0 || len(firmware) == 0 {
		return result, errors.New("endorsement and firmware must be nonempty")
	}
	endorsement := new(epb.VMLaunchEndorsement)
	if err := proto.Unmarshal(endorsementBytes, endorsement); err != nil {
		return result, fmt.Errorf("decode launch endorsement: %w", err)
	}
	firmwareDigest := sha512.Sum384(firmware)
	if err := verify.EndorsementProto(endorsement, &verify.Options{
		RootsOfTrust:       roots,
		ExpectedUefiSha384: firmwareDigest[:],
		Now:                now,
		// Getter remains nil. This tool cannot fetch a root or endorsement.
	}); err != nil {
		return result, fmt.Errorf("authenticate Google endorsement and firmware digest: %w", err)
	}
	golden := new(epb.VMGoldenMeasurement)
	if err := proto.Unmarshal(endorsement.GetSerializedUefiGolden(), golden); err != nil {
		return result, fmt.Errorf("decode signed golden measurement: %w", err)
	}
	if golden.GetTdx() == nil {
		return result, errors.New("signed endorsement has no TDX measurements")
	}
	// Google's current generic launch profile is independent of the older
	// machine-shape/early-accept compatibility variants. It cannot authorize
	// those variants; a real quote must later match a separately reviewed policy.
	computed, err := tdx.MRTD(tdx.LaunchOptionsDefault(""), firmware)
	if err != nil {
		return result, fmt.Errorf("reconstruct TDX MRTD from firmware: %w", err)
	}
	var generic *epb.VMTdx_Measurement
	for _, m := range golden.GetTdx().GetMeasurements() {
		if m == nil || len(m.GetMrtd()) != len(computed) {
			return result, errors.New("signed TDX measurement has invalid length")
		}
		if m.GetRamGib() == 0 && !m.GetEarlyAccept() {
			if generic != nil {
				return result, errors.New("signed endorsement has ambiguous generic TDX measurements")
			}
			generic = m
		}
	}
	if generic == nil {
		return result, errors.New("signed endorsement has no generic TDX measurement")
	}
	if !bytes.Equal(generic.GetMrtd(), computed[:]) {
		return result, errors.New("reconstructed MRTD differs from signed generic TDX measurement")
	}
	endorsementDigest := sha256.Sum256(endorsementBytes)
	result = report{
		SchemaVersion:               1,
		Status:                      "signed_firmware_reference_reconstructed_unapproved",
		EndorsementSHA256:           hex.EncodeToString(endorsementDigest[:]),
		FirmwareSHA384:              hex.EncodeToString(firmwareDigest[:]),
		GoogleRootCertificateSHA256: googleRootSHA256,
		GoogleVerifierCommit:        googleSourceCommit,
		MeasurementProfile:          "google_current_generic",
		TDXFirmwareSVN:              golden.GetTdx().GetSvn(),
		MRTD:                        hex.EncodeToString(computed[:]),
		PrivateModeApproved:         false,
	}
	return result, nil
}

func run(args []string) error {
	flags := flag.NewFlagSet("gcp-endorsement", flag.ContinueOnError)
	endorsementPath := flags.String("endorsement", "", "local signed VMLaunchEndorsement binarypb")
	firmwarePath := flags.String("firmware", "", "local Google OVMF firmware binary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *endorsementPath == "" || *firmwarePath == "" {
		return errors.New("require --endorsement FILE and --firmware FILE; no positional arguments")
	}
	roots, err := trustedRoot()
	if err != nil {
		return err
	}
	endorsementBytes, err := os.ReadFile(*endorsementPath)
	if err != nil {
		return fmt.Errorf("read local endorsement: %w", err)
	}
	firmware, err := os.ReadFile(*firmwarePath)
	if err != nil {
		return fmt.Errorf("read local firmware: %w", err)
	}
	result, err := inspect(endorsementBytes, firmware, roots, time.Now().UTC())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
