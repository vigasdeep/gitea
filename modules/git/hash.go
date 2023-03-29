// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package git

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"strings"
)

type HashType int

const (
	Sha1 HashType = iota
	Sha256
)

// sha1Pattern can be used to determine if a string is an valid sha
var sha1Pattern = regexp.MustCompile(`^[0-9a-f]{4,40}$`)

type HashTypeInterface interface {
	IsZero() bool
	RawValue() []byte
	String() string

	Type() HashType
	ToTypeString() string

	// Empty is the hash of empty git
	Empty() string
	// EmptyTree is the hash of an empty tree
	EmptyTree() string
	// FullLength is the length of the hash's hex string
	FullLength() int

	IsValid(input string) bool
	MustID(b []byte) HashTypeInterface
	MustIDFromString(s string) HashTypeInterface
	NewID(b []byte) (HashTypeInterface, error)
	NewIDFromString(s string) (HashTypeInterface, error)
	NewEmptyID() HashTypeInterface

	NewHasher() HasherInterface
}

func HashTypeInterfaceFromHashString(hexHash string) (HashTypeInterface, error) {
	switch len(hexHash) {
	case 40:
		h := NewSha1()
		if _, err := h.NewIDFromString(hexHash); err != nil {
			return nil, err
		}
		return h, nil
	}

	return nil, fmt.Errorf("invalid hash hex string: %s", hexHash)
}

func (h *Sha1Hash) RawValue() []byte { return h.val[:] }
func (h *Sha1Hash) IsZero() bool {
	empty := Sha1Hash{}
	return bytes.Equal(empty.val[:], h.val[:])
}

func (h *Sha1Hash) String() string {
	return hex.EncodeToString(h.val[:])
}
func (*Sha1Hash) Type() HashType       { return Sha1 }
func (*Sha1Hash) ToTypeString() string { return "sha1" }
func (*Sha1Hash) Empty() string        { return "0000000000000000000000000000000000000000" }
func (*Sha1Hash) EmptyTree() string    { return "4b825dc642cb6eb9a060e54bf8d69288fbee4904" }
func (*Sha1Hash) FullLength() int      { return 40 }
func (*Sha1Hash) IsValid(input string) bool {
	return sha1Pattern.MatchString(input)
}

func (*Sha1Hash) MustID(b []byte) HashTypeInterface {
	var id Sha1Hash
	copy(id.val[0:20], b)
	return &id
}

func (h *Sha1Hash) MustIDFromString(s string) HashTypeInterface {
	return hashTypeMustIDFromString(h, s)
}

func (h *Sha1Hash) NewID(b []byte) (HashTypeInterface, error) {
	return hashTypeNewID(h, b)
}

func (h *Sha1Hash) NewIDFromString(s string) (HashTypeInterface, error) {
	return hashTypeNewIDFromString(h, s)
}

func (*Sha1Hash) NewEmptyID() HashTypeInterface {
	return NewSha1()
}

func (h *Sha1Hash) NewHasher() HasherInterface {
	return &Sha1Hasher{sha1.New()}
}

func NewSha1() *Sha1Hash {
	return &Sha1Hash{}
}

// generic implementations
func NewHashTypeInterface(hash string) (HashTypeInterface, error) {
	hash = strings.ToLower(hash)
	switch hash {
	case "sha1":
		return &Sha1Hash{}, nil
	}

	return nil, errors.New("unsupported hash type")
}

func hashTypeNewID(h HashTypeInterface, b []byte) (HashTypeInterface, error) {
	if len(b) != h.FullLength()/2 {
		return h.MustID([]byte(h.Empty())), fmt.Errorf("length must be %d: %v", h.FullLength(), b)
	}
	return h.MustID(b), nil
}

func hashTypeMustIDFromString(h HashTypeInterface, s string) HashTypeInterface {
	b, _ := hex.DecodeString(s)
	return h.MustID(b)
}

func hashTypeNewIDFromString(h HashTypeInterface, s string) (HashTypeInterface, error) {
	s = strings.TrimSpace(s)
	if len(s) != h.FullLength() {
		return h.MustID([]byte(h.Empty())), fmt.Errorf("length must be %d: %s", h.FullLength(), s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return h.MustID([]byte(h.Empty())), err
	}
	return h.NewID(b)
}

// Sha1Hasher is a struct that will generate a HashTypeInterface
type HasherInterface interface {
	hash.Hash

	HashSum() HashTypeInterface
}

type Sha1Hasher struct {
	hash.Hash
}

// ComputeBlobHash compute the hash for a given blob content
func ComputeBlobHash(hash HashTypeInterface, content []byte) HashTypeInterface {
	return ComputeHash(hash, ObjectBlob, content)
}

// ComputeHash compute the hash for a given ObjectType and content
func ComputeHash(hash HashTypeInterface, t ObjectType, content []byte) HashTypeInterface {
	h := hash.NewHasher()
	_, _ = h.Write(t.Bytes())
	_, _ = h.Write([]byte(" "))
	_, _ = h.Write([]byte(strconv.FormatInt(int64(len(content)), 10)))
	_, _ = h.Write([]byte{0})
	return h.HashSum()
}

// Sum generates a SHA1 for the provided hash
func (h *Sha1Hasher) HashSum() HashTypeInterface {
	var sha1 Sha1Hash
	copy(sha1.val[:], h.Hash.Sum(nil))
	return &sha1
}

type ErrInvalidSHA struct {
	SHA string
}

func (err ErrInvalidSHA) Error() string {
	return fmt.Sprintf("invalid sha: %s", err.SHA)
}
