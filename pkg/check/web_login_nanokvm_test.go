package check

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// nanokvmDecrypt reverses nanokvmEncrypt (aes-everywhere: OpenSSL Salted__
// AES-256-CBC, MD5 EVP_BytesToKey, base64, URL-escape) so the emulator can
// validate the credential exactly as the real NanoKVM-Server does.
func nanokvmDecrypt(t *testing.T, enc, passphrase string) string {
	t.Helper()
	unesc, err := url.QueryUnescape(enc)
	if err != nil {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(unesc)
	if err != nil || len(raw) < 16 || string(raw[:8]) != "Salted__" {
		return ""
	}
	salt, ct := raw[8:16], raw[16:]
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return ""
	}
	key, iv := nanokvmEVPKDF([]byte(passphrase), salt, 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad <= 0 || pad > aes.BlockSize || pad > len(pt) {
		return ""
	}
	return string(pt[:len(pt)-pad])
}

// nanokvmEmulator mirrors the live NanoKVM API shapes:
//   - GET /                 -> the NanoKVM fingerprint page
//   - POST /api/auth/login  -> 200 {"code":0,"data":{"token":<JWT>}} when the
//     username matches and the decrypted password matches; otherwise 200
//     {"code":-2,"msg":"invalid username or password","data":null}.
//   - GET /api/auth/account -> 200 {"code":0,"data":{"username":...}} when the
//     nano-kvm-token cookie carries the minted JWT; otherwise 401 "unauthorized".
func nanokvmEmulator(t *testing.T, okUser, okPass string) *httptest.Server {
	t.Helper()
	const token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoicm9vdCIsImV4cCI6MH0.c2lnbmF0dXJlZGVtbw"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("<title>NanoKVM</title>"))
		case "/api/auth/login":
			var in struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Username == okUser && nanokvmDecrypt(t, in.Password, nanokvmFleetKey) == okPass {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"code":0,"msg":"success","data":{"token":"` + token + `"}}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":-2,"msg":"invalid username or password","data":null}`))
		case "/api/auth/account":
			if c, err := r.Cookie(nanokvmTokenCookie); err == nil && c.Value == token {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"code":0,"msg":"success","data":{"username":"` + okUser + `"}}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`"unauthorized"`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNanokvmAdapterLogin_Success(t *testing.T) {
	srv := nanokvmEmulator(t, "admin", "admin")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "nanokvm", "NanoKVM", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.Identity.Class = engine.ClassKVM

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.nanokvm.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.nanokvm.defaultCreds via nanokvm adapter, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpJson" {
		t.Errorf("loginVia = %q, want httpJson", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "admin" || p != "admin" {
		t.Errorf("recovered %q/%q, want admin/admin", u, p)
	}
	proof := fieldVal(f.Fields, "proof")
	if !strings.Contains(proof, "loginPath=/api/auth/login") ||
		!strings.Contains(proof, "tokenLen=") ||
		!strings.Contains(proof, "authedPath=/api/auth/account") ||
		!strings.Contains(proof, "username=admin") {
		t.Errorf("proof missing dynamic token/authed-endpoint evidence: %q", proof)
	}
}

// TestNanokvmAdapterLogin_WrongCreds is the FP guard: a rotated unit returns
// code=-2 with data=null (no token), and the adapter must report nothing.
func TestNanokvmAdapterLogin_WrongCreds(t *testing.T) {
	srv := nanokvmEmulator(t, "admin", "rotated")
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "nanokvm", "NanoKVM", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.Identity.Class = engine.ClassKVM

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding for rejected default (code=-2 data=null), got %+v", got)
	}
}

// TestNanokvmAdapterLogin_NoToken guards the other rejection shape: a device that
// answers code=0 but returns no token must not be reported (the JWT is the signal).
func TestNanokvmAdapterLogin_NoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("<title>NanoKVM</title>"))
		case "/api/auth/login":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":0,"msg":"ok","data":null}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "nanokvm", "NanoKVM", map[string]string{"web.port": port, "web.scheme": "http"})
	tgt.Identity.Class = engine.ClassKVM

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding for code=0 without a token, got %+v", got)
	}
}
