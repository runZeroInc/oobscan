package identify

import "testing"

func TestFaviconHref(t *testing.T) {
	cases := []struct {
		name string
		html string
		want string
	}{
		{
			// Raritan Xerus: the icon lives at a non-root path, declared via <link>.
			name: "shortcut icon non-root",
			html: `<head><link rel="shortcut icon" href="/faviconit/favicon.ico"></head>`,
			want: "/faviconit/favicon.ico",
		},
		{
			name: "rel icon relative",
			html: `<link rel="icon" type="image/x-icon" href="favicon.ico">`,
			want: "favicon.ico",
		},
		{
			name: "href before rel",
			html: `<link href="/static/fav.ico" rel="icon">`,
			want: "/static/fav.ico",
		},
		{
			// apple-touch-icon / mask-icon point at differently-hashed assets and
			// must not be picked as the favicon.
			name: "apple-touch-icon excluded",
			html: `<link rel="apple-touch-icon" href="/apple.png"><link rel="mask-icon" href="/m.svg">`,
			want: "",
		},
		{
			name: "apple-touch-icon then real icon",
			html: `<link rel="apple-touch-icon" href="/apple.png"><link rel="icon" href="/real.ico">`,
			want: "/real.ico",
		},
		{
			name: "no link",
			html: `<html><head><title>x</title></head></html>`,
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := faviconHref([]byte(c.html)); got != c.want {
				t.Errorf("faviconHref(%q) = %q, want %q", c.html, got, c.want)
			}
		})
	}
}
