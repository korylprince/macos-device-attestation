package mdm

import macospkg "github.com/korylprince/go-macos-pkg"

// MDM is an interface for running the InstallEnterpriseApplication command on an mdm
type MDM interface {
	// InstallEnterpriseApplication runs the InstallEnterpriseApplication command with the given serial and manifest
	InstallEnterpriseApplication(serial string, manifest *macospkg.Manifest) error
}
