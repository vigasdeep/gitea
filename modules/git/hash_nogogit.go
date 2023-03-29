//go:build !gogit

package git

type Sha1Hash struct {
	val [20]byte
}
