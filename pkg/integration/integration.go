package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Run launches a new Chrome instance that intercepts requests to pcloud in order to
// generate test data.
func Run(ctx context.Context) error {
	ctx, cancel := chromedp.NewExecAllocator(ctx, append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false))...)
	defer cancel()

	// To launch using an existing Chrome instance:
	// ctx, cancel := chromedp.NewRemoteAllocator(ctx, "ws://localhost:9222")

	// create chrome instance
	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	err := chromedp.Run(ctx, chromedp.Tasks{
		chromedp.ActionFunc(func(context context.Context) error {
			network.Enable().Do(context)
			return nil
		}),
	})
	if err != nil {
		return err
	}

	dir := "data"
	var counter int32

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			if ev.Request.Method == "OPTIONS" {
				return
			}
			if strings.HasPrefix(ev.Request.URL, "https://eapi.pcloud.com/upload_write") {
				if len(ev.Request.PostDataEntries) == 0 {
					return
				}
				data, err := base64.StdEncoding.DecodeString(ev.Request.PostDataEntries[0].Bytes)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println(ev.Request.URL, len(data))
				i := atomic.AddInt32(&counter, 1)
				ioutil.WriteFile(fmt.Sprintf("%s/enc_%03d.dat", dir, i), data, 0644)

			}
			if strings.HasPrefix(ev.Request.URL, "https://eapi.pcloud.com/upload_save") {
				log.Println(ev.Request.URL)
				u, err := url.Parse(ev.Request.URL)
				if err != nil {
					log.Println(err)
					return
				}
				key := u.Query().Get("key")
				ioutil.WriteFile(fmt.Sprintf("%s/enc_key.txt", dir), []byte(key), 0644)
			}
		}
	})
	<-ctx.Done()
	return nil
}
