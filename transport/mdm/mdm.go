package mdm

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"text/template"

	// embed install.sh
	_ "embed"

	macospkg "github.com/korylprince/go-macos-pkg"
	"github.com/korylprince/macos-device-attestation/filestore"
	"github.com/korylprince/macos-device-attestation/mdm"
)

//go:embed install.sh
var installScript string
var tmplPostinstall = template.Must(template.New("install.sh").Parse(installScript))

// Transport implements a Transport which uses an MDM to install a signed pkg to place a secure token on the filesystem
type Transport struct {
	mdm.MDM
	prefix string
	filestore.FileStore
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// New returns a new Transport with the given parameters.
// cert should be an "Apple Developer ID Installer" certificate
func New(m mdm.MDM, urlPrefix string, fs filestore.FileStore, cert *x509.Certificate, key *rsa.PrivateKey) *Transport {
	return &Transport{MDM: m, prefix: urlPrefix, FileStore: fs, cert: cert, key: key}
}

// Place places the token at path on the device with udid
func (m *Transport) Place(token, udid, path string) error {
	postinstall := new(bytes.Buffer)
	if err := tmplPostinstall.Execute(postinstall, struct {
		Token string
		Path  string
	}{token, path}); err != nil {
		return fmt.Errorf("could not create postinstall script: %w", err)
	}

	pkg, err := macospkg.GeneratePkg("com.github.korylprince.macos-device-attestation", "1.0.0", postinstall.Bytes())
	if err != nil {
		return fmt.Errorf("could not create payload pkg: %w", err)
	}

	signedPkg, err := macospkg.SignPkg(pkg, m.cert, m.key)
	if err != nil {
		return fmt.Errorf("could not sign payload pkg: %w", err)
	}

	fsPath, err := m.Put("payload.pkg", signedPkg)
	if err != nil {
		return fmt.Errorf("could not store payload pkg: %w", err)
	}

	manifest := macospkg.NewManifest(signedPkg, fmt.Sprintf("%s/%s", m.prefix, fsPath), macospkg.ManifestHashSHA256)

	if err = m.InstallEnterpriseApplication(udid, manifest); err != nil {
		return fmt.Errorf("could not execute install command: %w", err)
	}

	return nil
}
