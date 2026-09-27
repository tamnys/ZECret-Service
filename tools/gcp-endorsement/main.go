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
	MachineType                 string `json:"machine_type,omitempty"`
	RamGiB                      uint32 `json:"ram_gib,omitempty"`
	EarlyAccept                 *bool  `json:"early_accept,omitempty"`
	TDXFirmwareSVN              uint32 `json:"tdx_firmware_svn"`
	MRTD                        string `json:"mrtd"`
	PrivateModeApproved         bool   `json:"private_mode_approved"`
}

// These are the exact C3 shapes in the pinned Google TDX measurement code.
// Legacy launch variants are distinct from the current generic profile; do
// not infer a shape from an endorsement filename or a received quote.
var legacyC3RamGiB = map[string]uint32{
	"c3-standard-4":   16,
	"c3-standard-8":   32,
	"c3-standard-22":  88,
	"c3-standard-44":  176,
	"c3-standard-88":  352,
	"c3-standard-176": 704,
}

type launchSelection struct {
	legacyMachineType string
	earlyAccept       bool
	legacy            bool
}

func parseLaunchSelection(machineType, earlyAccept string) (launchSelection, error) {
	if machineType == "" && earlyAccept == "" {
		return launchSelection{}, nil
	}
	if machineType == "" || (earlyAccept != "true" && earlyAccept != "false") {
		return launchSelection{}, errors.New("legacy launch requires --legacy-machine-type and --legacy-early-accept=true|false")
	}
	if _, ok := legacyC3RamGiB[machineType]; !ok {
		return launchSelection{}, fmt.Errorf("unsupported legacy C3 machine type: %s", machineType)
	}
	return launchSelection{legacyMachineType: machineType, earlyAccept: earlyAccept == "true", legacy: true}, nil
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
	return inspectSelected(endorsementBytes, firmware, roots, now, launchSelection{})
}

func inspectSelected(endorsementBytes, firmware []byte, roots *x509.CertPool, now time.Time, selection launchSelection) (report, error) {
	var result report
	if len(endorsementBytes) == 0 || len(firmware) == 0 {
		return result, errors.New("endorsement and firmware must be nonempty")
	}
	if selection.legacy {
		if _, ok := legacyC3RamGiB[selection.legacyMachineType]; !ok {
			return result, errors.New("unsupported legacy C3 machine type")
		}
	} else if selection.legacyMachineType != "" || selection.earlyAccept {
		return result, errors.New("inconsistent launch selection")
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
	options := tdx.LaunchOptionsDefault("")
	profile := "google_current_generic"
	var ramGiB uint32
	if selection.legacy {
		// The pinned Google endorsement generator uses this exact historical
		// TDHOB measurement recipe for named C3 shapes.
		options = tdx.LaunchOptionsDefaultTDHOBBug(selection.legacyMachineType)
		options.DisableUnacceptedMemory = selection.earlyAccept
		ramGiB = legacyC3RamGiB[selection.legacyMachineType]
		profile = "google_legacy_c3_tdhob_bug"
	}
	computed, err := tdx.MRTD(options, firmware)
	if err != nil {
		return result, fmt.Errorf("reconstruct TDX MRTD from firmware: %w", err)
	}
	var selected *epb.VMTdx_Measurement
	for _, m := range golden.GetTdx().GetMeasurements() {
		if m == nil || len(m.GetMrtd()) != len(computed) {
			return result, errors.New("signed TDX measurement has invalid length")
		}
		if m.GetRamGib() == ramGiB && m.GetEarlyAccept() == selection.earlyAccept {
			if selected != nil {
				return result, errors.New("signed endorsement has ambiguous selected TDX measurements")
			}
			selected = m
		}
	}
	if selected == nil {
		return result, errors.New("signed endorsement has no selected TDX measurement")
	}
	if !bytes.Equal(selected.GetMrtd(), computed[:]) {
		return result, errors.New("reconstructed MRTD differs from signed selected TDX measurement")
	}
	endorsementDigest := sha256.Sum256(endorsementBytes)
	var earlyAccept *bool
	if selection.legacy {
		earlyAccept = &selection.earlyAccept
	}
	result = report{
		SchemaVersion:               1,
		Status:                      "signed_firmware_reference_reconstructed_unapproved",
		EndorsementSHA256:           hex.EncodeToString(endorsementDigest[:]),
		FirmwareSHA384:              hex.EncodeToString(firmwareDigest[:]),
		GoogleRootCertificateSHA256: googleRootSHA256,
		GoogleVerifierCommit:        googleSourceCommit,
		MeasurementProfile:          profile,
		MachineType:                 selection.legacyMachineType,
		RamGiB:                      ramGiB,
		EarlyAccept:                 earlyAccept,
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
	legacyMachineType := flags.String("legacy-machine-type", "", "explicit historical C3 shape (requires --legacy-early-accept)")
	legacyEarlyAccept := flags.String("legacy-early-accept", "", "explicit true|false for historical C3 measurement")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *endorsementPath == "" || *firmwarePath == "" {
		return errors.New("require --endorsement FILE and --firmware FILE; no positional arguments")
	}
	selection, err := parseLaunchSelection(*legacyMachineType, *legacyEarlyAccept)
	if err != nil {
		return err
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
	result, err := inspectSelected(endorsementBytes, firmware, roots, time.Now().UTC(), selection)
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
