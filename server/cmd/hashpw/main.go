package main

import (
	"fmt"
	"os"

	"github.com/t3rmit3/slither/server/internal/store/pg"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hashpw <plaintext>")
		os.Exit(1)
	}
	h, err := pg.HashArgon2id(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(h)
}
