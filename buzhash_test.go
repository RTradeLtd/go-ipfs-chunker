package chunk

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	util "github.com/ipfs/go-ipfs-util"
)

func TestBuzhashChunking(t *testing.T) {
	data := make([]byte, 1024*1024*16)
	util.NewTimeSeededRand().Read(data)

	r := NewBuzhash(bytes.NewReader(data))

	var chunks [][]byte

	for {
		chunk, err := r.NextBytes()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}

		chunks = append(chunks, chunk)
	}

	t.Logf("average block size: %d\n", len(data)/len(chunks))

	unchunked := bytes.Join(chunks, nil)
	if !bytes.Equal(unchunked, data) {
		fmt.Printf("%d %d\n", len(unchunked), len(data))
		//ioutil.WriteFile("./incorrect", unchunked, 0777)
		//ioutil.WriteFile("./correct", data, 0777)
		t.Fatal("data was chunked incorrectly")
	}
}

func TestBuzhashChunkReuse(t *testing.T) {
	newBuzhash := func(r io.Reader) Splitter {
		return NewBuzhash(r)
	}
	testReuse(t, newBuzhash)
}

func BenchmarkBuzhash2(b *testing.B) {
	benchmarkChunker(b, func(r io.Reader) Splitter {
		return NewBuzhash(r)
	})
}

func TestBuzhashBitsHashBias(t *testing.T) {
	counts := make([]byte, 32)
	for _, h := range bytehash {
		for i := 0; i < 32; i++ {
			if h&1 == 1 {
				counts[i]++
			}
			h = h >> 1
		}
	}
	for i, c := range counts {
		if c != 128 {
			t.Errorf("Bit balance in position %d broken, %d ones", i, c)
		}
	}
}
