package chunk

import (
	"bytes"
	"io"
	"os"
)

// CryptSplitter provides a wrapped
// sizeSpliiterv2 that encrypts chunks
// before they are returned from NextBytes
type CryptSplitter struct {
	ssv  sizeSplitterv2
	pass string

	ecm *EncryptManager
}

// NewCryptChunker provides a chunking algorithm which encrypts
// chunks using the provided pass. If pass is "" the system hostname is used.
func NewCryptChunker(r io.Reader, pass string) (Splitter, error) {
	var err error
	if pass == "" {
		pass, err = os.Hostname()
		if err != nil {
			return nil, err
		}
	}
	ssv := sizeSplitterv2{r: r, size: uint32(DefaultBlockSize)}
	return &CryptSplitter{ssv, pass, NewEncryptManager(pass)}, nil
}

// NextBytes produces a new chunk.
func (cs *CryptSplitter) NextBytes() ([]byte, error) {
	b, err := cs.NextBytes()
	if err != nil {
		return nil, err
	}
	return cs.ecm.Encrypt(bytes.NewReader(b))
}

// Reader returns the io.Reader associated to this Splitter.
func (cs *CryptSplitter) Reader() io.Reader {
	return cs.ssv.Reader()
}
