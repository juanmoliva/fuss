package main

import (
	"bufio"
	"fmt"
	"fuss/internal/requests"
	fusstarget "fuss/pkg/fussTarget"
	"net/url"
	"os"
	"strings"
	"sync"

	flag "github.com/spf13/pflag"
)

func main() {

	var DebugMode bool
	var Threads int
	var Proxy string
	var DenseFuss bool

	flag.BoolVarP(&DebugMode, "debug", "d", false, "enable debug mode")
	flag.IntVarP(&Threads, "threads", "t", 5, "number of threads, default 5")
	flag.BoolVar(&DenseFuss, "dense", false, "enable dense fuzzing mode: every path segment and every combination tested.")
	flag.StringVarP(&Proxy, "proxy", "p", "", "proxy to use for requests")

	flag.Parse()

	if Threads < 1 {
		fmt.Println("Threads must be greater than 0")
		os.Exit(1)
	}

	sc := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	httpClientConfig := requests.HttpClientConfig{
		DebugMode: DebugMode,
		Proxy:     Proxy,
	}

	var httpClients []requests.HttpClient
	for i := 0; i < Threads; i++ {
		httpClients = append(httpClients, requests.NewClient(httpClientConfig))
	}

	urls := make(chan string)
	output := make(chan fusstarget.FussTarget)

	targetColl := fusstarget.NewTargetCollection()

	var wg sync.WaitGroup
	for i := 0; i < Threads; i++ {
		wg.Add(1)

		go func(i int) {
			for u := range urls {
				/* output <- FussTarget{
					Url:      u,
					Type:     PARAM_DISCOVERY,
					ParamKey: ReplaceFuss,
				} */

				parsed, err := url.Parse(u)
				if err != nil || parsed.Host == "" {
					fmt.Fprintf(os.Stderr, "fuss, failed to parse url: %s\n", err)
					continue
				}

				qparams := parsed.Query()
				for key, value := range qparams {
					// replace the value of the parameter with {FUSSREPLACE}

					p2, err := url.Parse(u)
					qparams2 := p2.Query()
					qparams2.Set(key, fusstarget.ReplaceFuss)

					if err != nil {
						fmt.Fprintf(os.Stderr, "fuss, failed to parse url: %s\n", err)
						continue
					}

					p2.RawQuery = qparams2.Encode()

					t := fusstarget.FussTarget{
						Url:           p2.String(),
						Type:          fusstarget.PARAM,
						ParamKey:      key,
						OriginalValue: value[0],
					}

					output <- t
				}

				path := parsed.Path

				path = strings.ReplaceAll(path, "//", "/")
				pathSegments := strings.Split(strings.Trim(path, "/"), "/")

				for i := range pathSegments {
					pathSegment := pathSegments[i]

					modifiedSegments := append([]string{}, pathSegments...)
					modifiedSegments[i] = fusstarget.ReplaceFuss

					// remove after i from segments
					modifiedSegments = modifiedSegments[:i+1]

					parsed.Path = "/" + strings.Join(modifiedSegments, "/")

					t := fusstarget.FussTarget{
						Url:           parsed.String(),
						Type:          fusstarget.PATH_BIT,
						Path:          parsed.Path,
						Host:          parsed.Host,
						OriginalValue: pathSegment,
					}

					output <- t
				}

				if DenseFuss {
					for i := range pathSegments {
						pathSegment := pathSegments[i]

						// Replace the current segment with {FUSSREPLACE}
						modifiedSegments := append([]string{}, pathSegments...)
						modifiedSegments[i] = fusstarget.ReplaceFuss
						parsed.Path = "/" + strings.Join(modifiedSegments, "/")

						t := fusstarget.FussTarget{
							Url:           parsed.String(),
							Type:          fusstarget.PATH_BIT,
							Path:          parsed.Path,
							Host:          parsed.Host,
							OriginalValue: pathSegment,
						}

						output <- t
					}
				}

				output <- fusstarget.FussTarget{
					Url:  u,
					Type: fusstarget.PARAM_DISCOVERY,
				}

			}

			wg.Done()
		}(i)
	}

	// Output worker
	var outputWG sync.WaitGroup
	for i := 0; i < Threads; i++ {
		outputWG.Add(1)
		go func(i int) {
			for target := range output {
				added := targetColl.AddIfNotExists(target)
				if added {

					err := target.XssScan(&httpClients[i])
					if err != nil {
						fmt.Fprintf(os.Stderr, "fuss, failed to scan for xss: %s\n", err)
						target.XssScan(&httpClients[i])
					}

					err = target.SQLiScan(&httpClients[i])
					if err != nil {
						fmt.Fprintf(os.Stderr, "fuss, failed to scan for sqli: %s\n", err)
						target.SQLiScan(&httpClients[i])
					}

					err = target.ScanForServerErrors(&httpClients[i])
					if err != nil {
						fmt.Fprintf(os.Stderr, "fuss, failed to scan for server errors: %s\n", err)
						target.ScanForServerErrors(&httpClients[i])
					}
				}

			}
			outputWG.Done()
		}(i)
	}

	// Close the output channel when the HTTP workers are done
	go func() {
		wg.Wait()
		close(output)
	}()

	for sc.Scan() {
		u := sc.Text()

		urls <- u
	}

	close(urls)

	// check there were no errors reading stdin (unlikely)
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
	}

	// Wait until the output waitgroup is done
	outputWG.Wait()

	//for _, t := range targetColl.Coll {
	//	 fmt.Println(t)
	//}

}
