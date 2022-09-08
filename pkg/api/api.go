package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/go-querystring/query"
)

func New(debug bool, endpoint string) *Client {
	return &Client{
		endpoint: endpoint,
		debug:    debug,
	}
}

type Client struct {
	endpoint string
	debug    bool
}

type UserInfoRequest struct {
	GetAuth        string `url:"getauth"`
	Username       string `url:"username"`
	Digest         string `url:"digest"`
	PasswordDigest string `url:"passworddigest"`
}

type UserInfoResponse struct {
	Auth           string `json:"auth"`
	Email          string `json:"email"`          // address of the user
	EmailVerified  bool   `json:"emailverified"`  // true if the user had verified it's email
	Premium        bool   `json:"premium"`        // true if the user is premium
	PremiumExpires string `json:"premiumexpires"` // date when the premium expires
	Quota          int    `json:"quota"`          // quota in bytes
	UsedQuota      int    `json:"usedquota"`      // used quota in bytes
	Language       string `json:"language"`       // 2-3 characters lowercase languageid
}

func (c *Client) UserInfo(ctx context.Context, req *UserInfoRequest) (*UserInfoResponse, error) {
	values, _ := query.Values(req)
	u := fmt.Sprintf("userinfo?%s", values.Encode())

	var resp UserInfoResponse
	if err := c.do(ctx, "GET", u, nil, &resp); err != nil {
		return nil, fmt.Errorf("pcloud: couldn't get user info: %w", err)
	}
	return &resp, nil
}

type ListFolderResponse struct {
	Key      string    `json:"key"`
	Metadata *Metadata `json:"metadata"`
}
type Metadata struct {
	Name           string          `json:"name"`
	Created        string          `json:"created"`
	IsMine         bool            `json:"ismine"`
	Thumb          bool            `json:"thumb"`
	Modified       string          `json:"modified"`
	Comments       int             `json:"comments"`
	Encrypted      bool            `json:"encrypted"`
	ID             string          `json:"id"`
	IsShared       bool            `json:"isshared"`
	Icon           string          `json:"icon"`
	ParentFolderID int             `json:"parentfolderid"`
	FolderID       int             `json:"folderid"`
	Contents       []*Metadata     `json:"contents"`
	IsFolder       bool            `json:"isfolder"`
	FileID         int             `json:"fileid"`
	Category       int             `json:"category"`
	Size           int             `json:"size"`
	ContentType    string          `json:"contenttype"`
	Hash           json.RawMessage `json:"hash"`
}

func (c *Client) ListFolder(ctx context.Context, auth string, folderID int) (*ListFolderResponse, error) {
	values := url.Values{}
	values.Set("auth", auth)
	values.Set("folderid", fmt.Sprintf("%d", folderID))
	values.Set("recursive", "0")
	values.Set("getkey", "1")
	u := fmt.Sprintf("listfolder?%s", values.Encode())

	var resp ListFolderResponse
	if err := c.do(ctx, "GET", u, nil, &resp); err != nil {
		return nil, fmt.Errorf("pcloud: couldn't list folder: %w", err)
	}
	return &resp, nil
}

type GetFileLinkResponse struct {
	Path    string          `json:"path"`
	DWLTag  string          `json:"dwltag"`
	Size    int             `json:"size"`
	Expires string          `json:"expires"`
	Key     string          `json:"key"`
	Hosts   []string        `json:"hosts"`
	Hash    json.RawMessage `json:"hash"`
}

func (c *Client) GetFileLink(ctx context.Context, auth string, fileID int) (*GetFileLinkResponse, error) {
	values := url.Values{}
	values.Set("auth", auth)
	values.Set("fileid", fmt.Sprintf("%d", fileID))
	values.Set("recursive", "1")
	values.Set("getkey", "1")
	u := fmt.Sprintf("getfilelink?%s", values.Encode())

	var resp GetFileLinkResponse
	if err := c.do(ctx, "GET", u, nil, &resp); err != nil {
		return nil, fmt.Errorf("pcloud: couldn't get file link: %w", err)
	}
	return &resp, nil
}

type CryptoGetUserKeysResponse struct {
	PrivateKey string `json:"privatekey"`
	PublicKey  string `json:"publickey"`
}

func (c *Client) CryptoGetUserKeys(ctx context.Context, auth string) (*CryptoGetUserKeysResponse, error) {
	values := url.Values{}
	values.Set("auth", auth)
	u := fmt.Sprintf("crypto_getuserkeys?%s", values.Encode())

	var resp CryptoGetUserKeysResponse
	if err := c.do(ctx, "GET", u, nil, &resp); err != nil {
		return nil, fmt.Errorf("pcloud: couldn't get crypto keys: %w", err)
	}
	return &resp, nil
}

type CryptoGetRootResponse struct {
	Metadata *RootMetadata `json:"metadata"`
}

type RootMetadata struct {
	Name           string `json:"name"`
	Created        string `json:"created"`
	IsMine         bool   `json:"ismine"`
	Thumb          bool   `json:"thumb"`
	Modified       string `json:"modified"`
	Comments       int    `json:"comments"`
	Encrypted      bool   `json:"encrypted"`
	ID             string `json:"id"`
	IsShared       bool   `json:"isshared"`
	Icon           string `json:"icon"`
	IsFolder       bool   `json:"isfolder"`
	ParentFolderID int    `json:"parentfolderid"`
	FolderID       int    `json:"folderid"`
}

func (c *Client) CryptoGetRoot(ctx context.Context, auth string) (*CryptoGetRootResponse, error) {
	values := url.Values{}
	values.Set("auth", auth)
	u := fmt.Sprintf("crypto_getroot?%s", values.Encode())

	var resp CryptoGetRootResponse
	if err := c.do(ctx, "GET", u, nil, &resp); err != nil {
		return nil, fmt.Errorf("pcloud: couldn't get crypto root: %w", err)
	}
	return &resp, nil
}

type UploadCreateResponse struct {
	UploadID int `json:"uploadid"`
}

func (c *Client) UploadCreate(ctx context.Context, auth string) (*UploadCreateResponse, error) {
	values := url.Values{}
	values.Set("auth", auth)
	u := fmt.Sprintf("upload_create?%s", values.Encode())

	var resp UploadCreateResponse
	if err := c.do(ctx, "GET", u, nil, &resp); err != nil {
		return nil, fmt.Errorf("pcloud: couldn't create upload: %w", err)
	}
	return &resp, nil
}

type UploadWriteRequest struct {
	UploadID     int    `url:"uploadid"`
	UploadOffset int    `url:"uploadoffset"`
	UploadSize   int    `url:"uploadsize"`
	Data         []byte `url:"-"`
}

func (c *Client) UploadWrite(ctx context.Context, auth string, req *UploadWriteRequest) error {
	values, _ := query.Values(req)
	values.Set("auth", auth)
	u := fmt.Sprintf("upload_write?%s", values.Encode())
	body := bytes.NewReader(req.Data)

	if err := c.do(ctx, "PUT", u, body, nil); err != nil {
		return fmt.Errorf("pcloud: couldn't write upload: %w", err)
	}
	return nil
}

type UploadSaveRequest struct {
	UploadID  int    `url:"uploadid"`
	FolderID  int    `url:"folderid"`
	Name      string `url:"name"`
	Encrypted int    `url:"encrypted"`
	Key       string `url:"key"`
	MTime     int64  `url:"mtime"`
}

type UploadSaveResponse struct {
	Metadata Metadata `json:"metadata"`
}

func (c *Client) UploadSave(ctx context.Context, auth string, req *UploadSaveRequest) (*UploadSaveResponse, error) {
	values, _ := query.Values(req)
	values.Set("auth", auth)
	u := fmt.Sprintf("upload_save?%s", values.Encode())

	var resp UploadSaveResponse
	if err := c.do(ctx, "GET", u, nil, &resp); err != nil {
		return nil, fmt.Errorf("pcloud: couldn't save upload: %w", err)
	}
	return &resp, nil
}

type GetDigestResponse struct {
	Digest  string `json:"digest"`
	Expires string `json:"expires"`
}

func (c *Client) GetDigest(ctx context.Context) (*GetDigestResponse, error) {
	var resp GetDigestResponse
	if err := c.do(ctx, "GET", "getdigest", nil, &resp); err != nil {
		return nil, fmt.Errorf("pcloud: couldn't get digest: %w", err)
	}
	return &resp, nil
}

type result struct {
	Result int `json:"result"`
}

func (c *Client) do(ctx context.Context, method, action string, body io.Reader, v interface{}) error {
	client := http.Client{
		Timeout: time.Second * 10,
	}
	u := fmt.Sprintf("https://%s/%s", c.endpoint, action)
	if c.debug {
		log.Println("🚀", u)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if c.debug {
		log.Println("🐛", string(data))
	}
	var r result
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("couldn't unmarshal result: %w", err)
	}
	if r.Result != 0 {
		return fmt.Errorf("result: %d", r.Result)
	}
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("couldn't unmarshal response: %w", err)
	}
	return nil
}
