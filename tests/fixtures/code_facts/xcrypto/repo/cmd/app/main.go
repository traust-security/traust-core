package main

import (
	"fmt"

	"example.com/app/pkg/hash"
	"golang.org/x/crypto/ssh"
)

func main() {
	cfg := &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	fmt.Println(cfg.User, hash.Sum("x"))
}
