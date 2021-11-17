package mdm

import (
	macospkg "github.com/korylprince/go-macos-pkg"
)

// MDM is an interface for running the InstallEnterpriseApplication command on an mdm
type MDM interface {
	// InstallEnterpriseApplication runs the InstallEnterpriseApplication command with the given udid and manifest
	InstallEnterpriseApplication(udid string, manifest *macospkg.Manifest) error
	// Transform returns the UDID for the given serial. If the serial is not found, attest.ErrInvalidIdentifier is returned
	Transform(serial string) (udid string, err error)
}
