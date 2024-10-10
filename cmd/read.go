package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zuiwuchang/seal"
)

func read() (cmd *cobra.Command) {
	var (
		full, ignoreTime bool
	)
	cmd = &cobra.Command{
		Use:   "read",
		Short: "Read pri or pub file",
		Long: `Read pri or pub file
  seal read ca.pri ca.pub
  seal read ca.pri ca.pub -f
`,
		Run: func(cmd *cobra.Command, args []string) {
			e := func() (e error) {
				var (
					pri *seal.PrivateChain
					pub *seal.PublicChain
				)
				for _, arg := range args {
					fmt.Printf("--- %s ---\n", arg)
					pri, pub, e = readChain(arg, ignoreTime)
					if e != nil {
						return
					} else if pri != nil {
						fmt.Println(`  PrivateKey:`, base64.RawURLEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(pri.PrivateKey())))
						pub = pri.PublicChain
						if full {
							for ; pub != nil; pub = pub.Parent() {
								printPub(pub)
							}
						} else {
							printPub(pub)
						}
					} else {
						if full {
							for ; pub != nil; pub = pub.Parent() {
								printPub(pub)
							}
						} else {
							printPub(pub)
						}
					}
				}
				return
			}()
			if e != nil {
				fmt.Println(e)
				os.Exit(1)
			}
		},
	}
	flags := cmd.Flags()
	flags.BoolVarP(&full, "full", "f", false, "print all chain")
	flags.BoolVarP(&ignoreTime, "time", "t", false, "ignore time error")
	return
}
func printPub(pub *seal.PublicChain) {
	md := pub.Metadata()
	printMetadata(md)
}
func printMetadata(md *seal.Metadata) {
	if md.PublicKey != nil {
		fmt.Println(`  PublicKey:`, base64.RawURLEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(md.PublicKey)))
	}
	if md.Parent != nil {
		fmt.Println(`  Parent:`, base64.RawURLEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(md.Parent)))
	}
	fmt.Println(`  Hash:`, md.Hash.String())

	if !md.Afrer.IsZero() {
		fmt.Println(`  Afrer:`, md.Afrer.Local())
	}
	if !md.Before.IsZero() {
		fmt.Println(`  Before:`, md.Before.Local())
	}

	if md.Country != `` {
		fmt.Println(`  Country:`, md.Country)
	}
	if md.State != `` {
		fmt.Println(`  State:`, md.State)
	}
	if md.Locality != `` {
		fmt.Println(`  Locality:`, md.Locality)
	}
	if md.Organization != `` {
		fmt.Println(`  Organization:`, md.Organization)
	}
	if md.Organizational != `` {
		fmt.Println(`  Organizational:`, md.Organizational)
	}
	if len(md.Content) != 0 {
		fmt.Printf("  Content: %s\n", md.Content)
	}
	fmt.Println()
}
