package multidigest

import (
	"code.google.com/p/go.crypto/ripemd160"
	"code.google.com/p/go.crypto/sha3"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"io"
)

type SizeWriter uint64

func (s *SizeWriter) Write(p []byte) (int, error) {
	l := len(p)
	*s = SizeWriter(uint64(*s) + uint64(l))
	return l, nil
}

type MultiHashContext struct {
	contexts map[string]hash.Hash
	sw       *SizeWriter
}

func New() MultiHashContext {
	contexts := make(map[string]hash.Hash)
	contexts["adler32"] = adler32.New()
	contexts["crc32"] = crc32.NewIEEE()
	contexts["md5"] = md5.New()
	contexts["ripemd160"] = ripemd160.New()
	contexts["sha1"] = sha1.New()
	contexts["sha2-256"] = sha256.New()
	contexts["sha2-512"] = sha512.New()
	contexts["sha3-256"] = sha3.NewKeccak256()
	s := SizeWriter(0)
	return MultiHashContext{contexts: contexts, sw: &s}
}

func (h *MultiHashContext) Writer() io.Writer {
	var elements []io.Writer
	for _, v := range h.contexts {
		elements = append(elements, v)
	}
	elements = append(elements, h.sw)
	return io.MultiWriter(elements...)
}

func (h *MultiHashContext) Result() map[string]string {
	result := make(map[string]string)
	for k, v := range h.contexts {
		result[k] = fmt.Sprintf("%x", v.Sum(nil))
	}
	result["size"] = fmt.Sprintf("%d", uint64(*h.sw))
	return result
}

//func main() {
//	h := New()
//	w := h.Writer()
//	data, _ := ioutil.ReadFile(os.Args[1])
//	w.Write(data)
//	s, _ := json.MarshalIndent(h.Result(), "", "  ")
//	fmt.Printf("%s\n", string(s))
//}
