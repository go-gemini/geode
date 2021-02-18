package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
	"gopkg.in/gemini.v0"
)

/*
   opts.optopt(
       "",
       "lang",
       "RFC 4646 Language code(s) for text/gemini documents",
       "LANG",
   );
   opts.optflag("", "log-ip", "Output IP addresses when logging");
*/

var confRegex = regexp.MustCompile(`^([^:=]+)[:=] ?(\d\d) (.+)$`)

var (
	contentDir  = pflag.String("content", "./content", "Root of the content directory")
	certFiles   = pflag.StringSlice("cert", []string{"./cert.pem"}, "TLS certificate PEM file")
	keyFiles    = pflag.StringSlice("key", []string{"./key.rsa"}, "PKCS8 private key file")
	silentMode  = pflag.Bool("silent", false, "Disable logging output")
	onlyTLS13   = pflag.BoolP("only-tls13", "3", false, "Only use TLSv1.3 (default also allows TLSv1.2)")
	addresses   = pflag.StringSlice("addr", []string{"0.0.0.0:1965", "[::]:1965"}, "Comma separated list of address to listen on")
	serveSecret = pflag.Bool("serve-secret", false, "Enable serving secret files (files/directories starting with a dot)")
	hostnames   = pflag.StringSlice("hostname", []string{}, "Domain name of this Gemini server (default is not checking hostname or port; multiple occurences means basic vhosts)")
	centralConf = pflag.BoolP("central-conf", "C", false, "Use a central .meta file in the content root directory")
)

type responseMeta struct {
	status int
	meta   string
}

type Metadata map[string]responseMeta

func ReadMetadata(root fs.FS, name string) Metadata {
	ret := Metadata{}

	var target string

	if *centralConf {
		target = ".meta"
	} else {
		name = strings.TrimSuffix(name, "/")
		if name == "" {
			name = "."
		}

		info, err := fs.Stat(root, name)
		if err != nil {
			if !os.IsNotExist(err) {
				fmt.Println(err)
			}

			return ret
		}

		if info.IsDir() {
			target = name + "/.meta"
			target = strings.TrimPrefix(target, "./")
		} else {
			up := path.Dir(name)
			if up == "." {
				target = ".meta"
			} else {
				target = up + "/.meta"
			}
		}
	}

	f, err := root.Open(target)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Println(err)
		}

		return ret
	}
	defer f.Close()

	rawData, err := io.ReadAll(f)
	if err != nil {
		return ret
	}

	data := string(rawData)
	lines := strings.Split(data, "\n")

	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := confRegex.FindStringSubmatch(line)
		if matches == nil {
			log.Printf("geode: invalid config line %q, skipping", line)
			continue
		}

		status, err := strconv.Atoi(matches[2])
		if err != nil {
			log.Printf("geode: invalid status %q", matches[2])
			continue
		}

		ret[matches[1]] = responseMeta{
			status: status,
			meta:   matches[3],
		}
	}

	return ret
}

type wrappedHandler struct {
	root  fs.FS
	inner gemini.Handler
}

func (wh *wrappedHandler) ServeGemini(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
	target := strings.TrimPrefix(r.URL.Path, "/")

	md := ReadMetadata(wh.root, target)

	if *centralConf {
		if resp, ok := md[target]; ok {
			w.WriteStatus(resp.status, resp.meta)
			return
		}
	} else {
		if resp, ok := md[path.Base(target)]; ok {
			w.WriteStatus(resp.status, resp.meta)
			return
		}
	}

	wh.inner.ServeGemini(ctx, w, r)
}

func main() {
	pflag.Parse()

	_ = mime.AddExtensionType(".gmi", "text/gemini")
	_ = mime.AddExtensionType(".gemini", "text/gemini")

	var handler gemini.Handler

	if len(*hostnames) != 0 {
		hostMux := gemini.NewHostMux()

		for _, hostname := range *hostnames {
			if _, ok := hostMux.Children[hostname]; ok {
				panic("Duplicate hostnames")
			}

			rootFS := os.DirFS(path.Join(*contentDir, hostname))
			fsHandler := gemini.FS(rootFS)
			fsHandler.AllowDotfiles = *serveSecret

			hostMux.Children[hostname] = &wrappedHandler{rootFS, fsHandler}
		}

		handler = hostMux
	} else {
		rootFS := os.DirFS(*contentDir)
		fsHandler := gemini.FS(rootFS)
		fsHandler.AllowDotfiles = *serveSecret

		handler = &wrappedHandler{rootFS, fsHandler}
	}

	server := gemini.Server{
		TLS:     &tls.Config{},
		Handler: handler,
	}

	if *silentMode {
		server.Log = &gemini.NopServerLogger{}
	}

	if *onlyTLS13 {
		server.TLS.MinVersion = tls.VersionTLS13
	}

	if len(*certFiles) != len(*keyFiles) {
		panic("Mismatched number of cert and key files")
	}

	for i := range *certFiles {
		certFile := (*certFiles)[i]
		keyFile := (*keyFiles)[i]

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			panic(err.Error())
		}
		server.TLS.Certificates = []tls.Certificate{cert}
	}

	group, _ := errgroup.WithContext(context.Background())

	for _, addr := range *addresses {
		// HACK: There's a weird issue where if you create a goroutine with a
		// closure in a for loop, the goroutines will only have the last value
		// in the slice. By creating a function and calling it, we can
		// explicitly pass through the values.
		func(addr string) {
			group.Go(func() error {
				l, err := net.Listen("tcp", addr)
				if err != nil {
					return err
				}

				return server.Serve(l)
			})
		}(addr)
	}

	err := group.Wait()
	if err != nil {
		panic(err.Error())
	}
}
