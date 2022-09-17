package pcloud

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/igolaizola/pcloud/pkg/api"
	"github.com/igolaizola/pcloud/pkg/crypto"
)

type Client struct {
	debug      bool
	api        *api.Client
	auth       string
	priv       *rsa.PrivateKey
	user       string
	pass       string
	cryptoPass string
}

type Option func(*Client)

func WithCredentials(user, pass string) Option {
	return func(c *Client) {
		c.user = user
		c.pass = pass
	}
}

func WithToken(auth string) Option {
	return func(s *Client) {
		s.auth = auth
	}
}

func WithPrivateKey(priv *rsa.PrivateKey) Option {
	return func(s *Client) {
		s.priv = priv
	}
}

func WithCryptoPassword(cryptoPass string) Option {
	return func(s *Client) {
		s.cryptoPass = cryptoPass
	}
}

func WithDebug() Option {
	return func(c *Client) {
		c.debug = true
	}
}

func New(endpoint string, opts ...Option) *Client {
	cli := &Client{}
	for _, o := range opts {
		o(cli)
	}
	cli.api = api.New(cli.debug, endpoint)
	return cli
}

func (c *Client) Start(ctx context.Context) error {
	if c.auth == "" {
		if err := c.Login(ctx, c.user, c.pass); err != nil {
			return err
		}
	}
	if c.priv == nil {
		if err := c.UnlockCrypto(ctx, c.cryptoPass); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) AuthToken() string {
	return c.auth
}

func (c *Client) PrivateKey() *rsa.PrivateKey {
	return c.priv
}

func LoadPrivateKey(privFile string) (*rsa.PrivateKey, error) {
	privPEM, err := ioutil.ReadFile(privFile)
	if err != nil {
		return nil, fmt.Errorf("pcloud: couldn't read private key file: %w", err)
	}
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("pcloud: failed to parse PEM block containing the key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pcloud: couldn't parse private key: %w", err)
	}
	return priv, nil
}

func SavePrivateKey(priv *rsa.PrivateKey, dst string) error {
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		},
	)
	return ioutil.WriteFile(dst, privPem, fs.FileMode(0600))
}

func (c *Client) Login(ctx context.Context, user, pass string) error {
	digestResponse, err := c.api.GetDigest(ctx)
	if err != nil {
		return fmt.Errorf("pcloud: couldn't get digest: %w", err)
	}

	// sha1( password + sha1( lowercase of username ) + digest)
	passDigest := crypto.SHA1(pass + crypto.SHA1(strings.ToLower(user)) + digestResponse.Digest)

	userInfoResp, err := c.api.UserInfo(ctx, &api.UserInfoRequest{
		GetAuth:        "1",
		Username:       user,
		Digest:         digestResponse.Digest,
		PasswordDigest: passDigest,
	})
	if err != nil {
		return fmt.Errorf("pcloud: couldn't get user info: %w", err)
	}
	c.auth = userInfoResp.Auth
	return nil
}

func (c *Client) UnlockCrypto(ctx context.Context, cryptoPass string) error {
	keysResp, err := c.api.CryptoGetUserKeys(ctx, c.auth)
	if err != nil {
		return fmt.Errorf("pcloud: couldn't get crypto keys: %w", err)
	}
	priv, err := crypto.DecryptPrivateKey(keysResp.PrivateKey, cryptoPass)
	if err != nil {
		return fmt.Errorf("pcloud: couldn't decrypt private key: %w", err)
	}

	c.priv = priv
	return nil
}

func (c *Client) List(ctx context.Context, path string) ([]string, []string, error) {
	folder, err := c.searchFolder(ctx, path)
	if err != nil {
		return nil, nil, fmt.Errorf("pcloud: couldn't get folder id: %w", err)
	}
	var folders, files []string
	for k, v := range folder.Items {
		if v.IsFolder {
			folders = append(folders, k)
		} else {
			files = append(files, k)
		}
	}
	return folders, files, nil
}

func (c *Client) searchFolder(ctx context.Context, path string) (*folder, error) {
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")

	currID := 0
	var curr *folder
	for i := range parts {
		curr, err := c.listFolder(ctx, currID)
		if err != nil {
			return nil, fmt.Errorf("pcloud: couldn't list folder: %w", err)
		}
		if i == len(parts)-1 {
			return curr, nil
		}
		part := parts[i+1]
		metadata, ok := curr.Items[part]
		if !ok {
			return nil, fmt.Errorf("pcloud: folder %s not found", part)
		}
		if !metadata.IsFolder {
			return nil, fmt.Errorf("pcloud: %s is not a folder", part)
		}
		currID = metadata.FolderID
	}
	return curr, nil
}

type folder struct {
	Metadata *api.Metadata
	Key      string
	Items    map[string]*api.Metadata
}

func (c *Client) listFolder(ctx context.Context, folderID int) (*folder, error) {
	listResp, err := c.api.ListFolder(ctx, c.auth, folderID)
	if err != nil {
		return nil, fmt.Errorf("pcloud: couldn't list folder: %w", err)
	}

	nameFunc := func(n string) (string, error) { return n, nil }
	if listResp.Metadata.Encrypted {
		aesKey, hmacKey, err := crypto.DecryptKey(c.priv, listResp.Key)
		if err != nil {
			return nil, fmt.Errorf("pcloud: couldn't decrypt key: %w", err)
		}
		nameFunc = func(n string) (string, error) {
			return crypto.DecryptName(aesKey, hmacKey, n)
		}
	}

	items := make(map[string]*api.Metadata)
	for _, item := range listResp.Metadata.Contents {
		name, err := nameFunc(item.Name)
		if err != nil {
			return nil, err
		}
		items[name] = item
	}
	return &folder{
		Metadata: listResp.Metadata,
		Key:      listResp.Key,
		Items:    items,
	}, nil
}

func (c *Client) UploadFile(ctx context.Context, src, dst string) error {
	// Obtain folder modified time
	fileInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("pcloud: couldn't stat file: %w", err)
	}
	mtime := fileInfo.ModTime().Unix()
	size := fileInfo.Size()

	// Read file
	file, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("pcloud: couldn't read file: %w", err)
	}
	fileName := filepath.Base(src)
	reader := io.Reader(file)

	// Search folder
	folder, err := c.searchFolder(ctx, dst)
	if err != nil {
		return fmt.Errorf("pcloud: couldn't get folder id: %w", err)
	}

	var encrypted int
	var key string
	if folder.Metadata.Encrypted {
		encrypted = 1

		// Encrypt file
		fileAesKey, fileHmacKey, err := crypto.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("pcloud: couldn't generate key: %w", err)
		}
		key, err = crypto.EncryptKey(&c.priv.PublicKey, fileAesKey, fileHmacKey)
		if err != nil {
			return fmt.Errorf("pcloud: couldn't encrypt key: %w", err)
		}
		reader = crypto.Encrypt(rand.Reader, fileAesKey, fileHmacKey, reader, int(size))

		// Encrypt file name using folder key
		folderAesKey, folderHmacKey, err := crypto.DecryptKey(c.priv, folder.Key)
		if err != nil {
			return fmt.Errorf("pcloud: couldn't decrypt key: %w", err)
		}
		fileName, err = crypto.EncryptName(folderAesKey, folderHmacKey, fileName)
		if err != nil {
			return fmt.Errorf("pcloud: couldn't encrypt name: %w", err)
		}
	}

	// Create upload
	createResp, err := c.api.UploadCreate(ctx, c.auth)
	if err != nil {
		return fmt.Errorf("pcloud: couldn't create upload: %w", err)
	}

	// Upload data in chunks
	buf := make([]byte, crypto.EncryptBufferSize)
	var i, offset int
	for {
		n, err := reader.Read(buf[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("pcloud: couldn't read file: %w", err)
		}
		body := make([]byte, n)
		copy(body, buf[:n])
		if err := c.api.UploadWrite(ctx, c.auth, &api.UploadWriteRequest{
			UploadID:     createResp.UploadID,
			UploadOffset: offset,
			UploadSize:   len(body),
			Data:         body,
		}); err != nil {
			return fmt.Errorf("pcloud: couldn't write upload: %w", err)
		}
		i++
		offset += len(body)
	}

	// Finish upload
	if _, err := c.api.UploadSave(ctx, c.auth, &api.UploadSaveRequest{
		UploadID:  createResp.UploadID,
		FolderID:  folder.Metadata.FolderID,
		Name:      fileName,
		Key:       key,
		MTime:     mtime,
		Encrypted: encrypted,
	}); err != nil {
		return fmt.Errorf("pcloud: couldn't save upload: %w", err)
	}
	return nil
}

type Metadata struct {
	Name     string
	IsFolder bool
	ID       int
}
