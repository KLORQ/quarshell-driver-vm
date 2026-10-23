//go:build darwin || linux

package vm

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

const guestProxyCADir = "/usr/local/share/ca-certificates/quarshell-proxy-ca"

// guestProxyCABundle reads the validated operator CA bundle for delivery to
// the authenticated guest control agent. This is public trust material,
// never a credential.
func guestProxyCABundle(proxyEnv []string) (string, error) {
	var path string
	for _, entry := range proxyEnv {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == "QUARSHELL_PROXY_CA_BUNDLE" {
			path = strings.TrimSpace(value)
		}
	}
	if path == "" {
		return "", nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 1<<20 {
		return "", fmt.Errorf("VM proxy CA bundle must be a regular file no larger than 1 MiB")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read VM proxy CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return "", fmt.Errorf("VM proxy CA bundle contains no valid certificates")
	}
	return string(pem), nil
}
