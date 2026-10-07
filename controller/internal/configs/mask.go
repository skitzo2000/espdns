package configs

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

// Hidden stands in for the Wi-Fi password in what the API shows: the page edits the text
// with it, and a save or check puts the saved password back where it still is. It can't be
// a real one (a WPA passphrase is printable ASCII).
const Hidden = "••••••••"

// span is a string value's bytes in a config's text, quotes included.
type span struct{ start, end int }

// passwordSpans finds every wifi.password string value in a config's text. For text that
// isn't one JSON object (mid-edit, or more after it), any "password": "..." (a config has
// no other key of that name).
func passwordSpans(text []byte) []span {
	if s, err := walkPasswords(text); err == nil {
		return s
	}
	var out []span
	for _, m := range looseRE.FindAllSubmatchIndex(text, -1) {
		out = append(out, span{m[2], m[3]})
	}
	return out
}

var looseRE = regexp.MustCompile(`(?i)"password"\s*:\s*("(?:[^"\\]|\\.)*"?)`)

// key says whether a JSON object key is name as nodecfg.Parse reads it: encoding/json
// matches keys case-insensitively (with Unicode folding), so "WiFi": {"Password": ...} is
// the password too.
func key(t json.Token, name string) bool {
	s, ok := t.(string)
	return ok && strings.EqualFold(s, name)
}

// walkPasswords walks the JSON tokens: the top-level object's "wifi" objects'
// "password" strings, keys matched as nodecfg.Parse matches them. An error if the text is
// anything but one object (what follows it is left to the loose match).
func walkPasswords(text []byte) ([]span, error) {
	d := json.NewDecoder(bytes.NewReader(text))
	d.UseNumber()
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	var out []span
	for d.More() {
		k, err := d.Token()
		if err != nil {
			return nil, err
		}
		if !key(k, "wifi") {
			if err := skip(d); err != nil {
				return nil, err
			}
			continue
		}
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		if t != json.Delim('{') {
			if _, ok := t.(json.Delim); ok {
				if err := skipRest(d); err != nil {
					return nil, err
				}
			}
			continue
		}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return nil, err
			}
			if !key(k, "password") {
				if err := skip(d); err != nil {
					return nil, err
				}
				continue
			}
			from := int(d.InputOffset())
			t, err := d.Token()
			if err != nil {
				return nil, err
			}
			end := int(d.InputOffset())
			if _, ok := t.(string); ok {
				if i := bytes.IndexByte(text[from:end], '"'); i >= 0 {
					out = append(out, span{from + i, end})
				}
			} else if _, ok := t.(json.Delim); ok {
				if err := skipRest(d); err != nil {
					return nil, err
				}
			}
		}
		if _, err := d.Token(); err != nil { // the wifi object's '}'
			return nil, err
		}
	}
	if _, err := d.Token(); err != nil { // the top-level '}'
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("more after the object")
	}
	return out, nil
}

// skip reads one value.
func skip(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if _, ok := t.(json.Delim); ok {
		return skipRest(d)
	}
	return nil
}

// skipRest reads the rest of an object or array whose opening it read.
func skipRest(d *json.Decoder) error {
	for depth := 1; depth > 0; {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return nil
}

var hiddenJSON, _ = json.Marshal(Hidden)

// Mask returns the text with every Wi-Fi password replaced by Hidden (an empty one, an
// open network, stays empty), and whether there was one.
func Mask(text []byte) ([]byte, bool) {
	spans := passwordSpans(text)
	if len(spans) == 0 {
		return text, false
	}
	var out []byte
	at := 0
	for _, s := range spans {
		out = append(out, text[at:s.start]...)
		if string(text[s.start:s.end]) == `""` {
			out = append(out, `""`...)
		} else {
			out = append(out, hiddenJSON...)
		}
		at = s.end
	}
	return append(out, text[at:]...), true
}

// ErrHiddenPassword: a text with Hidden for a password, with no saved one to put back.
var ErrHiddenPassword = errors.New(`wifi.password is hidden ("` + Hidden + `") and there is no saved password to keep: type the password`)

// Unmask puts the saved config's Wi-Fi password back where text still has Hidden. saved is
// the file as saved (nil for a new one).
func Unmask(text, saved []byte) ([]byte, error) {
	// The last, as nodecfg.Parse takes a key given twice.
	var real []byte
	if s := passwordSpans(saved); len(s) > 0 {
		real = saved[s[len(s)-1].start:s[len(s)-1].end]
	}
	var out []byte
	at := 0
	for _, s := range passwordSpans(text) {
		var v string
		if json.Unmarshal(text[s.start:s.end], &v) != nil || v != Hidden {
			continue
		}
		if real == nil || string(real) == `""` {
			return nil, ErrHiddenPassword
		}
		out = append(out, text[at:s.start]...)
		out = append(out, real...)
		at = s.end
	}
	if out == nil {
		return text, nil
	}
	return append(out, text[at:]...), nil
}
