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

func ca() (cmd *cobra.Command) {
	var (
		yes                     bool
		parentPath              string
		privatePath, publicPath string
		hash                    string
		bitSize                 int
		duration                string

		country, state, locality, organization, organizational, content string
		ignoreTime                                                      bool
	)
	cmd = &cobra.Command{
		Use:   "ca",
		Short: "Create a private chain, private chain can be used to create other sub-chains",
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
					Content:        []byte(content),
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

				var (
					pri *seal.PrivateChain
				)
				if parentPath == "" {
					pri, e = seal.New(md, bitSize)
				} else {
					pri, e = readPrivateChain(parentPath, ignoreTime)
					if e != nil {
						return
					}
					pri, e = pri.SignPrivate(md, bitSize)
				}
				if e != nil {
					return
				}
				e = writeFile(yes, true, privatePath, pri.Marshal())
				if e != nil {
					return
				}
				fmt.Println(`private chain:`, privatePath)
				e = writeFile(yes, false, publicPath, pri.PublicChain.Marshal())
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
	flags.StringVar(&privatePath, "pri", "ca.pri", "private chain save path")
	flags.StringVar(&publicPath, "pub", "ca.pub", "public chain save path")
	strs := make([]string, len(seal.Hash))
	for i := 0; i < len(strs); i++ {
		strs[i] = `"` + seal.Hash[i].String() + `"`
	}
	flags.StringVarP(&hash, "hash", "H", crypto.SHA256.String(), "hash algorithm ["+strings.Join(strs, ",")+"]")
	flags.IntVarP(&bitSize, "bits", "b", 2048, "rsa bitsize")
	flags.StringVarP(&duration, "duration", "d", "", "valid time")

	flags.StringVarP(&country, "country", "C", "", "country")
	flags.StringVarP(&state, "state", "S", "", "state or province")
	flags.StringVarP(&locality, "locality", "L", "", "locality or city")
	flags.StringVarP(&organization, "organization", "O", "", "organization or company")
	flags.StringVarP(&organizational, "organizational", "o", "", "organizational or section")
	flags.StringVarP(&content, "content", "c", "", "content")

	flags.BoolVarP(&ignoreTime, "time", "t", false, "ignore time error")
	return
}
