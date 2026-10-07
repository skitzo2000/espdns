package configs

import "strings"

// DiffLine is one line of a diff: Op " " (in both), "-" (only in the old) or "+" (only in
// the new).
type DiffLine struct {
	Op   string `json:"op"`
	Text string `json:"text"`
	// Old and New are the line's numbers in each text (0: not in it).
	Old int `json:"old,omitempty"`
	New int `json:"new,omitempty"`
}

// maxDiffLines bounds the diff's table (a config is a few dozen lines; MaxFile is 64 KB).
const maxDiffLines = 4000

// Diff is a line diff of two texts (a longest common subsequence of lines): every line of
// both, in order. Nil when they are the same.
func Diff(old, new []byte) []DiffLine {
	if string(old) == string(new) {
		return nil
	}
	a, b := lines(old), lines(new)
	if len(a) > maxDiffLines || len(b) > maxDiffLines {
		return []DiffLine{{Op: "-", Text: "(too long to compare line by line)"}, {Op: "+", Text: "(changed)"}}
	}
	// lcs[i][j]: the longest common subsequence of a[i:] and b[j:].
	lcs := make([][]int32, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int32, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []DiffLine
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			out = append(out, DiffLine{Op: " ", Text: a[i], Old: i + 1, New: j + 1})
			i, j = i+1, j+1
		case i < len(a) && (j == len(b) || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, DiffLine{Op: "-", Text: a[i], Old: i + 1})
			i++
		default:
			out = append(out, DiffLine{Op: "+", Text: b[j], New: j + 1})
			j++
		}
	}
	return out
}

func lines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
