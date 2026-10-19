package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The release script and the embedded verification key must agree. This
// signs with a throwaway key through scripts/sign.sh and checks the Go side.
func TestSignScriptProducesVerifiableSignatures(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	pem := filepath.Join(dir, "k.pem")
	if out, err := exec.Command("openssl", "genpkey", "-algorithm", "ed25519", "-out", pem).CombinedOutput(); err != nil {
		t.Skipf("openssl can't make ed25519 keys: %s", out)
	}
	pubDER, err := exec.Command("openssl", "pkey", "-in", pem, "-pubout", "-outform", "DER").Output()
	if err != nil || len(pubDER) < 32 {
		t.Fatal(err)
	}
	pub := pubDER[len(pubDER)-32:]
	file, sig := filepath.Join(dir, "checksums.txt"), filepath.Join(dir, "checksums.txt.sig")
	os.WriteFile(file, []byte("abc  meshpanel_linux_amd64\n"), 0o644)
	key, _ := os.ReadFile(pem)
	cmd := exec.Command("../../scripts/sign.sh", file, sig)
	cmd.Env = append(os.Environ(), "MESHPANEL_SIGNING_KEY="+string(key))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sign.sh: %v %s", err, out)
	}
	sums, _ := os.ReadFile(file)
	sg, _ := os.ReadFile(sig)
	if err := verifySignature(pub, sums, sg); err != nil {
		t.Fatalf("script signature does not verify: %v", err)
	}
	// Without a key the script refuses (no unsigned releases).
	cmd = exec.Command("../../scripts/sign.sh", file, sig)
	cmd.Env = append(os.Environ(), "MESHPANEL_SIGNING_KEY=")
	if err := cmd.Run(); err == nil {
		t.Fatal("sign.sh signed without a key")
	}
}
