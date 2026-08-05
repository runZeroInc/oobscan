package check

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type nanokvmAdapter struct{}

func (nanokvmAdapter) mechanism() string { return "httpJson" }

const nanokvmFleetKey = "nanokvm-sipeed-2024"

const nanokvmTokenCookie = "nano-kvm-token"

func (nanokvmAdapter) login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error) {
	reqBody, _ := json.Marshal(map[string]string{
		"username": user,
		"password": nanokvmEncrypt(pass, nanokvmFleetKey),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/auth/login", strings.NewReader(string(reqBody)))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	var env struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &env) != nil {
		return false, "", errNotThisDevice
	}

	if env.Code != 0 || env.Data.Token == "" {
		return false, "", nil
	}
	token := env.Data.Token
	proof = proofKV(
		"loginPath", "/api/auth/login",
		"code", "0",
		"cookie", nanokvmTokenCookie,
		"tokenLen", strconv.Itoa(len(token)),
	)

	if u, aok := nanokvmAuthedAccount(ctx, client, base, token); aok {
		proof += " " + proofKV(
			"authedPath", "/api/auth/account",
			"authedStatus", "200",
			"accountCode", "0",
			"username", u,
		)
	}
	return true, proof, nil
}

func nanokvmAuthedAccount(ctx context.Context, client *http.Client, base, token string) (username string, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/auth/account", nil)
	if err != nil {
		return "", false
	}
	req.AddCookie(&http.Cookie{Name: nanokvmTokenCookie, Value: token})
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var env struct {
		Code int `json:"code"`
		Data struct {
			Username string `json:"username"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &env) != nil || env.Code != 0 {
		return "", false
	}
	return env.Data.Username, true
}

func nanokvmEncrypt(plain, passphrase string) string {
	salt := make([]byte, 8)
	_, _ = rand.Read(salt)
	key, iv := nanokvmEVPKDF([]byte(passphrase), salt, 32, 16)
	ct := nanokvmAESCBCPKCS7(key, iv, []byte(plain))
	blob := append([]byte("Salted__"), salt...)
	blob = append(blob, ct...)
	return url.QueryEscape(base64.StdEncoding.EncodeToString(blob))
}

func nanokvmEVPKDF(pass, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	var d, out []byte
	for len(out) < keyLen+ivLen {
		h := md5.New()
		h.Write(d)
		h.Write(pass)
		h.Write(salt)
		d = h.Sum(nil)
		out = append(out, d...)
	}
	return out[:keyLen], out[keyLen : keyLen+ivLen]
}

func nanokvmAESCBCPKCS7(key, iv, pt []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	pad := aes.BlockSize - len(pt)%aes.BlockSize
	padded := append(append([]byte{}, pt...), padBytes(byte(pad), pad)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return ct
}

func padBytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func init() { registerWebLoginAdapter("nanokvm", nanokvmAdapter{}) }
