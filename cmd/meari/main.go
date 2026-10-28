package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/client"
	"github.com/freekrpark/meari/internal/vault"
	"golang.org/x/term"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "meari:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  meari [-vault FILE] init [-server URL]
  meari [-vault FILE] id
  meari [-vault FILE] send ID MESSAGE...
  meari [-vault FILE] recv
`)
}

func run(args []string) error {
	fs := flag.NewFlagSet("meari", flag.ContinueOnError)
	fs.Usage = usage
	vaultPath := fs.String("vault", defaultVaultPath(), "vault file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		usage()
		return errors.New("missing command")
	}
	cmd, rest := fs.Arg(0), fs.Args()[1:]

	switch cmd {
	case "init":
		return cmdInit(*vaultPath, rest)
	case "id":
		c, err := open(*vaultPath)
		if err != nil {
			return err
		}
		fmt.Println(c.ID())
		return nil
	case "send":
		if len(rest) < 2 {
			usage()
			return errors.New("send needs an ID and a message")
		}
		to, err := auth.ParseAccountID(rest[0])
		if err != nil {
			return fmt.Errorf("invalid account ID %q", rest[0])
		}
		c, err := open(*vaultPath)
		if err != nil {
			return err
		}
		return c.Send(to, strings.Join(rest[1:], " "))
	case "recv":
		c, err := open(*vaultPath)
		if err != nil {
			return err
		}
		msgs, err := c.Receive()
		for _, m := range msgs {
			if m.Err != nil {
				fmt.Printf("! %s: unreadable message dropped (%v)\n", m.From, m.Err)
				continue
			}
			fmt.Printf("%s: %s\n", m.From, m.Text)
		}
		return err
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func cmdInit(path string, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "relay server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	pw, err := readPassword("New vault password: ")
	if err != nil {
		return err
	}
	again, err := readPassword("Repeat password: ")
	if err != nil {
		return err
	}
	if !bytes.Equal(pw, again) {
		return errors.New("passwords do not match")
	}

	c, err := client.Init(path, *server, pw, vault.DefaultParams)
	if err != nil {
		return err
	}
	fmt.Println("Your account ID (give this to people who want to message you):")
	fmt.Println(c.ID())
	return nil
}

func open(path string) (*client.Client, error) {
	pw, err := readPassword("Vault password: ")
	if err != nil {
		return nil, err
	}
	return client.Open(path, pw)
}

var stdin = bufio.NewReader(os.Stdin)

func readPassword(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return pw, err
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return nil, errors.New("no password on standard input")
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func defaultVaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "meari.vault"
	}
	return filepath.Join(dir, "meari", "meari.vault")
}
