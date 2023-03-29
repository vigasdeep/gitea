//go:build gogit

package git

import (
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/hash"
)

type Sha1Hash struct {
	val plumbing.Hash
}

func ParseGogitHash(h plumbing.Hash) HashTypeInterface {
	switch hash.Size {
	case 20:
		return NewSha1().MustID(h[:])
	}

	return nil
}

func ParseGogitHashArray(hashes []plumbing.Hash) []HashTypeInterface {
	ret := make([]HashTypeInterface, len(hashes))
	for i, h := range hashes {
		ret[i] = ParseGogitHash(h)
	}

	return ret
}

func defaultHashType() HashTypeInterface {
	switch hash.Size {
	case 20:
		return NewSha1()
	}

	return nil
}
