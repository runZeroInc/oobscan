package report

import "strings"

var publishableSecrets = map[string]bool{

	"admin": true, "ADMIN": true, "Admin": true, "administrator": true,
	"Administrator": true, "root": true, "calvin": true, "superuser": true,
	"sysadmin": true, "user": true, "guest": true, "operator": true,
	"changeme": true, "CHANGEME": true, "public": true, "private": true,
	"support": true, "0penBmc": true, "openbmc": true, "hpinvent": true,
	"advantech": true, "ipmi": true, "IPMI": true, "unknown": true,
	"Supermicro": true, "supermicro": true, "PASSWORD": true,

	"password": true, "Password": true, "password1": true, "Password1": true,
	"passw0rd": true, "Passw0rd": true, "P@ssw0rd": true, "p@ssw0rd": true,
	"PASSW0RD": true, "admin123": true, "Admin123": true, "admin1234": true,
	"123456": true, "1234567": true, "12345678": true, "123456789": true,
	"1234567890": true, "12345": true, "111111": true, "000000": true,
	"qwerty": true, "letmein": true, "welcome": true, "Welcome1": true,
	"abc123": true, "test": true, "test123": true, "toor": true,
	"adminadmin": true, "rootroot": true, "ADMINADMIN": true,
}

var placeholderSecrets = map[string]string{
	"common": "<common>",
	"":       "<empty>",
}

func redactSecret(pw string) string {
	if p, ok := placeholderSecrets[pw]; ok {
		return p
	}
	if pw == smcrakpFixedKeyMarker {
		return pw
	}
	if publishableSecrets[pw] {
		return pw
	}
	mask, _, ok := passwordShape(pw)
	if !ok {
		return "<redacted>"
	}
	return "<redacted:" + mask + ">"
}

func redactSecretPairs(in []Pair) []Pair {
	if len(in) == 0 {
		return nil
	}
	out := make([]Pair, 0, len(in))
	at := map[string]int{}
	for _, p := range in {
		v := redactSecret(p.Value)
		if i, seen := at[v]; seen {
			out[i].Count += p.Count
			continue
		}
		at[v] = len(out)
		out = append(out, Pair{Value: v, Count: p.Count})
	}
	return out
}

func isOrgAttributable(pw string) bool {
	return strings.HasPrefix(redactSecret(pw), "<redacted")
}
