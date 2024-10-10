package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/zuiwuchang/seal"
)

const (
	TagPrivateChain = "seal_pri."
	TagPublicChain  = "seal_pub."
)

var input = bufio.NewReader(os.Stdin)

func openFile(yes bool, pri bool, path string) (f *os.File, e error) {
	var (
		mode fs.FileMode
	)
	if pri {
		mode = 0600
	} else {
		mode = 0644
	}
	if !yes {
		f, e = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
		if e != nil {
			if !os.IsExist(e) {
				return
			}
			var (
				err error
				s   string
			)
			for !yes {
				fmt.Printf("%q already exists, do you want to overwrite? [y/n]: ", path)
				s, err = input.ReadString('\n')
				if err != nil {
					e = err
					return
				}
				switch strings.ToLower(strings.TrimSpace(s)) {
				case `y`, `yes`, `true`:
					yes = true
				case `n`, `no`, `false`:
					return
				}
			}
		}
	}
	f, e = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	return
}
func writeFile(yes bool, pri bool, path string, data []byte) (e error) {
	f, e := openFile(yes, pri, path)
	if e != nil {
		return
	}
	if pri {
		_, e = f.Write([]byte(TagPrivateChain))
	} else {
		_, e = f.Write([]byte(TagPublicChain))
	}
	if e != nil {
		return
	}

	w := base64.NewEncoder(base64.RawURLEncoding, f)

	gw := gzip.NewWriter(w)
	_, e = gw.Write(data)
	if e != nil {
		return
	}
	e = gw.Close()
	if e != nil {
		return
	}
	e = w.Close()
	if e != nil {
		return
	}

	_, e = f.Write([]byte("\n"))
	if e != nil {
		return
	}

	e = f.Sync()
	if e != nil {
		return
	}
	e = f.Close()
	return
}

func readPrivateChain(path string) (pri *seal.PrivateChain, e error) {
	f, e := os.Open(path)
	if e != nil {
		return
	}
	defer f.Close()
	size := len(TagPrivateChain)
	buf := make([]byte, size)
	_, e = io.ReadAtLeast(f, buf, size)
	if e != nil {
		return
	}
	if !bytes.Equal(buf, []byte(TagPrivateChain)) {
		e = errors.New(`not a private chain file`)
		return
	}
	br := bufio.NewReader(f)
	b, e := br.ReadBytes('\n')
	if e != nil {
		return
	}
	gr, e := gzip.NewReader(
		base64.NewDecoder(base64.RawURLEncoding, bytes.NewReader(b[:len(b)-1])))
	if e != nil {
		return
	}
	b, e = io.ReadAll(gr)
	if e != nil {
		return
	}

	pri, e = seal.ParsePrivateChainWithTime(b, time.Now().Unix())
	return
}
func readChain(path string) (pri *seal.PrivateChain, pub *seal.PublicChain, e error) {
	f, e := os.Open(path)
	if e != nil {
		return
	}
	defer f.Close()
	size := len(TagPrivateChain)
	buf := make([]byte, size)
	_, e = io.ReadAtLeast(f, buf, size)
	if e != nil {
		return
	}
	pubchain := false
	if bytes.Equal(buf, []byte(TagPrivateChain)) {
	} else if bytes.Equal(buf, []byte(TagPublicChain)) {
		pubchain = true
	} else {
		e = errors.New(`not a private chain file`)
		return
	}
	br := bufio.NewReader(f)
	b, e := br.ReadBytes('\n')
	if e != nil {
		return
	}
	gr, e := gzip.NewReader(
		base64.NewDecoder(base64.RawURLEncoding, bytes.NewReader(b[:len(b)-1])))
	if e != nil {
		return
	}
	b, e = io.ReadAll(gr)
	if e != nil {
		return
	}
	if pubchain {
		pub, e = seal.ParsePublicChainWithTime(b, time.Now().Unix())
	} else {
		pri, e = seal.ParsePrivateChainWithTime(b, time.Now().Unix())
	}
	return
}
