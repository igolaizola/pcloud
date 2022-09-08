package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/igolaizola/pcloud"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
)

func NewCommand() *ffcli.Command {
	fs := flag.NewFlagSet("pcloud", flag.ExitOnError)

	return &ffcli.Command{
		ShortUsage: "pcloud [flags] <subcommand>",
		FlagSet:    fs,
		Exec: func(context.Context, []string) error {
			return flag.ErrHelp
		},
		Subcommands: []*ffcli.Command{
			newExportCommand(),
			newListCommand(),
			newUploadCommand(),
		},
	}
}

func newExportCommand() *ffcli.Command {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	_ = fs.String("config", "", "config file (optional)")
	newClient := clientWithOptions(fs, false, false)

	keyFile := fs.String("key", "key.pem", "private key file to be created")

	return &ffcli.Command{
		Name:       "export",
		ShortUsage: "pcloud export [flags] <key> <value data...>",
		Options: []ff.Option{
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ff.PlainParser),
			ff.WithEnvVarPrefix("PCLOUD"),
		},
		ShortHelp: "pcloud ls",
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			if *keyFile == "" {
				return errors.New("empty private key file")
			}
			pc, err := newClient(ctx)
			if err != nil {
				return err
			}
			token := pc.AuthToken()
			key := pc.PrivateKey()
			if err := pcloud.SavePrivateKey(key, *keyFile); err != nil {
				return err
			}
			fmt.Printf("token: %s\n", token)
			return nil
		},
	}
}

func newListCommand() *ffcli.Command {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	_ = fs.String("config", "", "config file (optional)")
	newClient := client(fs)

	path := fs.String("path", "/", "path")

	return &ffcli.Command{
		Name:       "list",
		ShortUsage: "pcloud list [flags] <key> <value data...>",
		Options: []ff.Option{
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ff.PlainParser),
			ff.WithEnvVarPrefix("PCLOUD"),
		},
		ShortHelp: "pcloud list",
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			if *path == "" {
				return errors.New("missing path")
			}
			pc, err := newClient(ctx)
			if err != nil {
				return err
			}
			folders, files, err := pc.List(ctx, *path)
			if err != nil {
				return err
			}
			for _, f := range folders {
				fmt.Println(f)
			}
			for _, f := range files {
				fmt.Println(f)
			}
			return nil
		},
	}
}

func newUploadCommand() *ffcli.Command {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	_ = fs.String("config", "", "config file (optional)")
	newClient := client(fs)

	src := fs.String("src", "", "src")
	dst := fs.String("dst", "/", "dst")

	return &ffcli.Command{
		Name:       "upload",
		ShortUsage: "pcloud upload [flags] <key> <value data...>",
		Options: []ff.Option{
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ff.PlainParser),
			ff.WithEnvVarPrefix("PCLOUD"),
		},
		ShortHelp: "pcloud upload",
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			if *src == "" {
				return errors.New("missing src")
			}
			if *dst == "" {
				return errors.New("missing dst")
			}
			pc, err := newClient(ctx)
			if err != nil {
				return err
			}
			if err := pc.UploadFile(ctx, *src, *dst); err != nil {
				return err
			}
			return nil
		},
	}
}

func client(fs *flag.FlagSet) func(context.Context) (*pcloud.Client, error) {
	return clientWithOptions(fs, true, true)
}

func clientWithOptions(fs *flag.FlagSet, hasToken, hasKey bool) func(context.Context) (*pcloud.Client, error) {
	debug := fs.Bool("debug", false, "debug")
	endpoint := fs.String("endpoint", "eapi.pcloud.com", "endpoint")

	user := fs.String("user", "", "username")
	pass := fs.String("pass", "", "password")
	cryptoPass := fs.String("cryptopass", "", "cryptopass")

	empty := ""
	token := &empty
	if hasToken {
		token = fs.String("token", "", "token")
	}
	key := &empty
	if hasKey {
		key = fs.String("key", "", "key")
	}

	return func(ctx context.Context) (*pcloud.Client, error) {
		var opts []pcloud.Option
		if *debug {
			opts = append(opts, pcloud.WithDebug())
		}
		switch {
		case *token != "":
			opts = append(opts, pcloud.WithToken(*token))
		case *user != "" && *pass != "":
			opts = append(opts, pcloud.WithCredentials(*user, *pass))
		default:
			return nil, errors.New("missing user and password or auth token")
		}
		switch {
		case *key != "":
			privateKey, err := pcloud.LoadPrivateKey(*key)
			if err != nil {
				return nil, err
			}
			opts = append(opts, pcloud.WithPrivateKey(privateKey))
		case *cryptoPass != "":
			opts = append(opts, pcloud.WithCryptoPassword(*cryptoPass))
		default:
			return nil, errors.New("missing crypto password or private key")
		}
		cli := pcloud.New(*endpoint, opts...)
		return cli, cli.Start(ctx)
	}
}
