package main

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"time"

	"strings"

	"github.com/spf13/cobra"
	"github.com/zuiwuchang/seal"
)

func sign() (cmd *cobra.Command) {
	var (
		yes        bool
		parentPath string
		publicPath string
		hash       string
		duration   string

		country, state, locality, organization, organizational, content string
		contentPath                                                     string
		ignoreTime                                                      bool
	)
	cmd = &cobra.Command{
		Use:   "sign",
		Short: "Sign a piece of content",
		Run: func(cmd *cobra.Command, args []string) {
			e := func() (e error) {
				h := seal.GetHash(hash)
				if !h.Available() {
					e = fmt.Errorf(`hash not available: %q`, hash)
					return
				}
				md := seal.Metadata{
					Hash:  h,
					Afrer: time.Now(),

					Country:        country,
					State:          state,
					Locality:       locality,
					Organization:   organization,
					Organizational: organizational,
				}
				if contentPath == `` {
					md.Content = []byte(content)
				} else {
					md.Content, e = os.ReadFile(contentPath)
					if e != nil {
						return e
					}
				}
				if duration != `` {
					d, err := time.ParseDuration(duration)
					if err != nil {
						e = err
						return
					}
					if d < time.Second {
						e = errors.New(`duration invalid: ` + duration)
						return
					}
					md.Before = md.Afrer.Add(d)
				}

				pri, e := readPrivateChain(parentPath, ignoreTime)
				if e != nil {
					return
				}
				pub, e := pri.SignContent(md)
				if e != nil {
					return
				}
				e = writeFile(yes, false, publicPath, pub.Marshal())
				if e != nil {
					return
				}
				fmt.Println(`public chain:`, publicPath)
				return
			}()
			if e != nil {
				fmt.Println(e)
				os.Exit(1)
			}
		},
	}
	flags := cmd.Flags()
	flags.BoolVarP(&yes, "yes", "y", false, "automatically agree to all options")
	flags.StringVarP(&parentPath, "parent", "p", "", "parent chain path")
	flags.StringVar(&publicPath, "pub", "ca.pub", "public chain save path")
	strs := make([]string, len(seal.Hash))
	for i := 0; i < len(strs); i++ {
		strs[i] = `"` + seal.Hash[i].String() + `"`
	}
	flags.StringVarP(&hash, "hash", "H", crypto.SHA256.String(), "hash algorithm ["+strings.Join(strs, ",")+"]")
	flags.StringVarP(&duration, "duration", "d", "", "valid time")

	flags.StringVarP(&country, "country", "C", "", "country")
	flags.StringVarP(&state, "state", "S", "", "state or province")
	flags.StringVarP(&locality, "locality", "L", "", "locality or city")
	flags.StringVarP(&organization, "organization", "O", "", "organization or company")
	flags.StringVarP(&organizational, "organizational", "o", "", "organizational or section")
	flags.StringVarP(&content, "content", "c", "", "content")
	flags.StringVarP(&contentPath, "content-file", "f", "", "read content from a file")

	flags.BoolVarP(&ignoreTime, "time", "t", false, "ignore time error")
	return
}
