package fusstarget

import (
	"fmt"
	"fuss/internal/requests"
	"strconv"
	"strings"
	"sync"
)

type TargetType int

const (
	PARAM TargetType = iota
	PATH_BIT
	PARAM_DISCOVERY
)

var ReplaceFuss = "REPLACEFUSS"

type FussTarget struct {
	Url           string
	Type          TargetType
	Path          string
	Host          string
	ParamKey      string
	OriginalValue string
}

type TargetCollection struct {
	Coll  []FussTarget
	Mutex sync.RWMutex
}

func NewTargetCollection() *TargetCollection {
	tc := TargetCollection{}

	tc.Coll = make([]FussTarget, 0)
	tc.Mutex = sync.RWMutex{}

	return &tc
}

func (t *TargetCollection) AddIfNotExists(target FussTarget) (added bool) {
	defer func() {
		t.Mutex.Unlock()
	}()

	// what if urls have the same parameters but in different order?
	// and urls same parameters but different values?

	t.Mutex.Lock()
	switch target.Type {
	case PATH_BIT:
		for _, tt := range t.Coll {
			if tt.Host == target.Host && tt.Path == target.Path && tt.Type == target.Type {
				return false
			}
		}
	case PARAM:
		for _, tt := range t.Coll {
			if tt.Url == target.Url && tt.Type == target.Type && tt.ParamKey == target.ParamKey {
				return false
			}
		}
	case PARAM_DISCOVERY:
		for _, tt := range t.Coll {
			if tt.Url == target.Url && tt.Type == target.Type {
				return false
			}
		}
	}

	t.Coll = append(t.Coll, target)

	return true

}

var canary = "fusscanary"

// "fuss%27canary", "fuss%22canary", "fuss%3Ccanary"
var XssCheckingPayloads = map[string]string{
	"single": "fuss%27canary",
	"double": "fuss%22canary",
	"angle":  "fuss%3Ccanary",
}

var encodingsPayload = "f%5cu0075sscanaryf%2575sscanaryf%26%23x75%3bsscanary"

// []string{"fuss'canary", "fuss\"canary", "fuss<canary"}
var XssReflectionPatterns = map[string]string{
	"single": "fuss'canary",
	"double": "fuss\"canary",
	"angle":  "fuss<canary",
}

func (t *FussTarget) XssScan(client *requests.HttpClient) error {
	// Check for canary reflection

	xssRefs := []string{}

	var canaryUrl string
	switch t.Type {
	case PATH_BIT:
		canaryUrl = strings.ReplaceAll(t.Url, ReplaceFuss, canary)
	case PARAM:
		canaryUrl = strings.ReplaceAll(t.Url, ReplaceFuss, canary)
	case PARAM_DISCOVERY:
		if strings.Contains(t.Url, "?") {
			canaryUrl = t.Url + "&" + canary
		} else {
			canaryUrl = t.Url + "?" + canary
		}
	}

	httpReqConfig := requests.HttpReqConfig{
		HTTPMethod: requests.GET,
	}
	Resp, err := client.Make(canaryUrl, httpReqConfig)
	if err != nil {
		return fmt.Errorf("failed to make request: %s", err)
	}

	leftFoundSingleQ, leftFoundDoubleQ := false, false
	rightFoundSingleQ, rightFoundDoubleQ := false, false

	if strings.Contains(Resp.ContentType, "html") {
		canaryFoundIdx := strings.Index(string(Resp.Body), canary)
		if canaryFoundIdx != -1 {
			// will check for xss reflections.

			offset := 0
			for ; offset < 25; offset++ {
				if !leftFoundSingleQ && !leftFoundDoubleQ && canaryFoundIdx-offset >= 0 {
					if string(Resp.Body[canaryFoundIdx-offset]) == "'" {
						leftFoundSingleQ = true
					} else if string(Resp.Body[canaryFoundIdx-offset]) == "\"" {
						leftFoundDoubleQ = true
					}
				}

				if !rightFoundSingleQ && !rightFoundDoubleQ && canaryFoundIdx+offset < len(Resp.Body) {
					if string(Resp.Body[canaryFoundIdx+offset]) == "'" {
						rightFoundSingleQ = true
					} else if string(Resp.Body[canaryFoundIdx+offset]) == "\"" {
						rightFoundDoubleQ = true
					}
				}
			}

			for _, xssChar := range []string{"single", "double", "angle"} {
				payload := XssCheckingPayloads[xssChar]
				payloadUrl := strings.ReplaceAll(canaryUrl, canary, payload)

				Resp, err := client.Make(payloadUrl, httpReqConfig)
				if err != nil {
					return fmt.Errorf("failed to make request: %s", err)
				}

				if strings.Contains(string(Resp.Body), XssReflectionPatterns[xssChar]) {
					xssRefs = append(xssRefs, xssChar)

					if xssChar == "angle" {
						payloadUrl := strings.ReplaceAll(canaryUrl, canary, "fuss%3C%2Fcanary")

						RespAngleSlash, err := client.Make(payloadUrl, httpReqConfig)
						if err != nil {
							return fmt.Errorf("failed to make request: %s", err)
						}

						if strings.Contains(string(RespAngleSlash.Body), "fuss<canary") {
							xssRefs = append(xssRefs, "angle-slash")
						}

					}

				}
			}

			ResponseEncodings, err := client.Make(strings.ReplaceAll(canaryUrl, canary, encodingsPayload), httpReqConfig)
			if err != nil {
				return fmt.Errorf("failed to make request: %s", err)
			}

			if strings.Contains(string(ResponseEncodings.Body), "fusscanary") {
				xssRefs = append(xssRefs, "A WEIRD ENCODING REFLECTION")
			}

		}

		if len(xssRefs) > 0 {
			if len(xssRefs) == 1 && xssRefs[0] == "single" {
				if leftFoundSingleQ || rightFoundSingleQ {
					// fair change of single quote xss
					fmt.Printf("XSS Reflections found for %s  (fair change of single quote xss): , type: %d, param: %s,  original value: %s: %s\n", t.Url, t.Type, t.ParamKey, t.OriginalValue, strings.Join(xssRefs, ", "))
				}
			} else {
				fmt.Printf("XSS Reflections found for %s: , type: %d, param: %s, original value: %s: %s\n", t.Url, t.Type, t.ParamKey, t.OriginalValue, strings.Join(xssRefs, ", "))

			}
		}

	}

	return nil
}

type ResponseData struct {
	Status        string
	ContentLength int
	WordsCount    int
}

var Responses = map[string]ResponseData{}

func (t *FussTarget) SQLiScan(client *requests.HttpClient) error {

	// Check for SQLi Reflections
	// --> /**/ original response? --> s/**/ should throw error/different response
	// --> %2b0 original response? --> %2b1 should throw error/different response
	// --> ' different response? --> '' should return original response
	// --> " different response? --> "" should return original response

	// Check for SQLi Reflections

	if t.Type == PARAM_DISCOVERY {
		return nil
	}

	httpReqConfig := requests.HttpReqConfig{
		HTTPMethod: requests.GET,
	}

	var isNumberOriginal = false
	if _, err := strconv.Atoi(t.OriginalValue); err == nil {
		isNumberOriginal = true
	}

	responseData := ResponseData{}
	var originalUrl = strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue)
	if _, ok := Responses[originalUrl]; ok {
		responseData = Responses[originalUrl]

		fmt.Println("Response data already found in map! for url: ", originalUrl)
	} else {
		originalResp, err := client.Make(originalUrl, httpReqConfig)
		if err != nil {
			return fmt.Errorf("failed to make request: %s", err)
		}

		responseData = ResponseData{
			Status:        originalResp.Status,
			ContentLength: len(originalResp.Body),
			WordsCount:    len(strings.Fields(string(originalResp.Body))),
		}
	}

	sqlCommentUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%2f**%2f")
	addZeroUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%2b0")
	addSingleQuoteUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"'")
	addDoubleQuoteUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%22")

	sqlCommentResp, err := client.Make(sqlCommentUrl, httpReqConfig)
	if err != nil {
		fmt.Println(fmt.Errorf("failed to make request: %s", err))
	} else {

		if sqlCommentResp.Status == responseData.Status && len(strings.Fields(string(sqlCommentResp.Body))) == responseData.WordsCount {
			sqlCommentModurl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"s%2f**%2f")
			sqlCommentModResp, err := client.Make(sqlCommentModurl, httpReqConfig)

			if err != nil {
				return fmt.Errorf("failed to make request: %s", err)
			}

			if sqlCommentModResp.Status != responseData.Status || len(strings.Fields(string(sqlCommentModResp.Body))) != responseData.WordsCount {
				fmt.Printf("SQLi Reflections found for %s: , type: %d, param: %s, original value: %s: SQL Comment\n", t.Url, t.Type, t.ParamKey, t.OriginalValue)
				fmt.Printf(" Info, original status: %s, modified status: %s, original words count: %d, modified words count: %d\n", responseData.Status, sqlCommentModResp.Status, responseData.WordsCount, len(strings.Fields(string(sqlCommentModResp.Body))))
			}
		}
	}

	if isNumberOriginal {
		addZeroResp, err := client.Make(addZeroUrl, httpReqConfig)
		if err != nil {
			fmt.Println(fmt.Errorf("failed to make request: %s", err))
		} else {
			if addZeroResp.Status == responseData.Status && len(strings.Fields(string(addZeroResp.Body))) == responseData.WordsCount {

				addZeroRespModUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%2b1")
				addZeroRespModResp, err := client.Make(addZeroRespModUrl, httpReqConfig)

				if err != nil {
					return fmt.Errorf("failed to make request: %s", err)
				}

				if addZeroRespModResp.Status != responseData.Status || len(strings.Fields(string(addZeroRespModResp.Body))) != responseData.WordsCount {
					fmt.Printf("SQLi Reflections found for %s: , type: %d, param: %s, original value: %s: Add Zero verification.\n", t.Url, t.Type, t.ParamKey, t.OriginalValue)
					fmt.Printf(" Info, original status: %s, modified status: %s, original words count: %d, modified words count: %d\n", responseData.Status, addZeroRespModResp.Status, responseData.WordsCount, len(strings.Fields(string(addZeroRespModResp.Body))))
				}
			}
		}
	}

	addSingleQuoteResp, err := client.Make(addSingleQuoteUrl, httpReqConfig)
	if err != nil {
		fmt.Println(fmt.Errorf("failed to make request: %s", err))
	} else {
		if addSingleQuoteResp.Status != responseData.Status || len(strings.Fields(string(addSingleQuoteResp.Body))) != responseData.WordsCount {
			addSingleQuoteRespModUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"''")
			addSingleQuoteRespModResp, err := client.Make(addSingleQuoteRespModUrl, httpReqConfig)

			if err != nil {
				return fmt.Errorf("failed to make request: %s", err)
			}

			if addSingleQuoteRespModResp.Status == responseData.Status && len(strings.Fields(string(addSingleQuoteRespModResp.Body))) == responseData.WordsCount {
				fmt.Printf("SQLi Reflections found for %s: , type: %d, param: %s, original value: %s: Single Quote\n", t.Url, t.Type, t.ParamKey, t.OriginalValue)
				fmt.Printf(" Info, original status: %s, modified status: %s, original words count: %d, modified words count: %d\n", responseData.Status, addSingleQuoteRespModResp.Status, responseData.WordsCount, len(strings.Fields(string(addSingleQuoteRespModResp.Body))))
			}
		}
	}

	addDoubleQuoteResp, err := client.Make(addDoubleQuoteUrl, httpReqConfig)
	if err != nil {
		return fmt.Errorf("failed to make request: %s", err)
	} else {
		if addDoubleQuoteResp.Status != responseData.Status || len(strings.Fields(string(addDoubleQuoteResp.Body))) != responseData.WordsCount {
			addDoubleQuoteRespModUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%22%22")
			addDoubleQuoteRespModResp, err := client.Make(addDoubleQuoteRespModUrl, httpReqConfig)

			if err != nil {
				return fmt.Errorf("failed to make request: %s", err)
			}

			if addDoubleQuoteRespModResp.Status == responseData.Status && len(strings.Fields(string(addDoubleQuoteRespModResp.Body))) == responseData.WordsCount {
				fmt.Printf("SQLi Reflections found for %s: , type: %d, param: %s, original value: %s: Double Quote\n", t.Url, t.Type, t.ParamKey, t.OriginalValue)
				fmt.Printf(" Info, original status: %s, modified status: %s, original words count: %d, modified words count: %d\n", responseData.Status, addDoubleQuoteRespModResp.Status, responseData.WordsCount, len(strings.Fields(string(addDoubleQuoteRespModResp.Body))))
			}
		}
	}

	return nil
}

func (t *FussTarget) ScanForServerErrors(client *requests.HttpClient) error {
	payload := "%24%7B%7B%3C%25%5B%25%27%22%7D%7D%25%5C."

	if t.Type == PARAM_DISCOVERY {
		return nil
	}

	httpReqConfig := requests.HttpReqConfig{
		HTTPMethod: requests.GET,
	}

	payloadUrl := strings.ReplaceAll(t.Url, ReplaceFuss, payload)

	Resp, err := client.Make(payloadUrl, httpReqConfig)
	if err != nil {
		return fmt.Errorf("failed to make request: %s", err)
	}

	if strings.HasPrefix("5", Resp.Status) {
		fmt.Printf("Server Error found for %s: , type: %d, param: %s, original value: %s\n", t.Url, t.Type, t.ParamKey, t.OriginalValue)
	}

	return nil
}
