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

var encodingsPayloadQuotes = "fuss%5cu0022canaryfuss%2522canaryfuss%26%23x22%3bcanary"
var encodingsPayloadAngle = "fuss%5cu003Ccanaryfuss%253Ccanaryfuss%26%23x3C%3Bcanary"

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
		/* commonXssParams := []string{
			"q", "s", "search", "query", "keyword", "lang", "id", "locale",
		}
		var basicCanariesCommonParams string

		for _, param := range commonXssParams {
			basicCanariesCommonParams += fmt.Sprintf("&%s=%s", param, canary)
		}

		// final string of params will be like: &q=fusscanary&s=fusscanary&search=fusscanary&query=fusscanary&keyword=fusscanary&lang=fusscanary&id=fusscanary&locale=fusscanary
		*/
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
				ResponseEncodingsQuotes, err := client.Make(strings.ReplaceAll(canaryUrl, canary, encodingsPayloadQuotes), httpReqConfig)
				if err != nil {
					return fmt.Errorf("failed to make request: %s", err)
				}

				if strings.Contains(string(ResponseEncodingsQuotes.Body), XssReflectionPatterns["double"]) {
					xssRefs = append(xssRefs, "weird-encoding-quotes")
				}

				ResponseEncodingsAngle, err := client.Make(strings.ReplaceAll(canaryUrl, canary, encodingsPayloadAngle), httpReqConfig)
				if err != nil {
					return fmt.Errorf("failed to make request: %s", err)
				}

				if strings.Contains(string(ResponseEncodingsAngle.Body), XssReflectionPatterns["angle"]) {
					xssRefs = append(xssRefs, "weird-encoding-angle")
				}
			}

		}

		if len(xssRefs) > 0 {
			if len(xssRefs) == 1 && xssRefs[0] == "single" {
				if leftFoundSingleQ || rightFoundSingleQ {
					// fair change of single quote xss
					PrintXssResult(t.Url, t.Type, t.ParamKey, t.OriginalValue, xssRefs, "fair change of single quote xss")
				}
			} else {
				PrintXssResult(t.Url, t.Type, t.ParamKey, t.OriginalValue, xssRefs, "")
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
var ResponsesMutex = sync.RWMutex{}

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
	ResponsesMutex.Lock()
	if _, ok := Responses[originalUrl]; ok {
		responseData = Responses[originalUrl]

		fmt.Println("Response data already found in map! for url: ", originalUrl)
	} else {
		originalResp, err := client.Make(originalUrl, httpReqConfig)
		if err != nil {
			ResponsesMutex.Unlock()
			return fmt.Errorf("failed to make request: %s", err)
		}

		responseData = ResponseData{
			Status:        originalResp.Status,
			ContentLength: len(originalResp.Body),
			WordsCount:    len(strings.Fields(string(originalResp.Body))),
		}
	}
	ResponsesMutex.Unlock()

	sqlCommentUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%252f**%252f")
	addZeroUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%2b0")

	sqlCommentResp, err := client.Make(sqlCommentUrl, httpReqConfig)
	if err != nil {
		fmt.Println(fmt.Errorf("failed to make request: %s", err))
	} else {
		if sqlCommentResp.Status == responseData.Status && len(strings.Fields(string(sqlCommentResp.Body))) == responseData.WordsCount {
			var sqliInfo string
			var found403s bool

			sqlCommentModErrorUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"s%252f**%252f")
			sqlCommentModGoodUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%252f*ss*%252f")

			sqlCommentModErrorResp, err := client.Make(sqlCommentModErrorUrl, httpReqConfig)
			if err != nil {
				return fmt.Errorf("failed to make request: %s", err)
			}

			if strings.Contains(sqlCommentModErrorResp.Status, "403") && !strings.Contains(responseData.Status, "403") {
				found403s = true
			}

			diffInStatus := sqlCommentModErrorResp.Status != responseData.Status
			diffInWordCount := len(strings.Fields(string(sqlCommentModErrorResp.Body))) - responseData.WordsCount
			if diffInStatus || diffInWordCount > 0 {
				if diffInStatus {
					sqliInfo += fmt.Sprintf("Difference in Status when adding s%%252f**%%252f: %s vs %s. \n", sqlCommentModErrorResp.Status, responseData.Status)
				}
				if diffInWordCount > 0 {
					sqliInfo += fmt.Sprintf("Difference in word count when adding s%%252f**%%252f: %d words. \n", diffInWordCount)
				}

				sqlCommentModGoodResp, err := client.Make(sqlCommentModGoodUrl, httpReqConfig)
				if err != nil {
					return fmt.Errorf("failed to make request: %s", err)
				}

				if strings.Contains(sqlCommentModGoodResp.Status, "403") && !strings.Contains(responseData.Status, "403") {
					found403s = true
				}

				sameStatus := sqlCommentModGoodResp.Status == responseData.Status
				diffInWordCount := len(strings.Fields(string(sqlCommentModGoodResp.Body))) - responseData.WordsCount
				if sameStatus && diffInWordCount == 0 {
					PrintSQLiResult(t.Url, t.Type, t.ParamKey, t.OriginalValue, "SQL Comment /**/", sqliInfo)
				} else if found403s {
					// some servers return 403 when they see /**/ in the url, at this point there is some indication that s SQLi is possible
					sqliInfo += fmt.Sprintf("Some 403 found during request to s%%252f**%%252f or %%252f*ss*%%252f. \n")
					PrintSQLiResult(t.Url, t.Type, t.ParamKey, t.OriginalValue, "SQL Comment /**/", sqliInfo)
				}

			}
		}
	}

	if isNumberOriginal {
		addZeroResp, err := client.Make(addZeroUrl, httpReqConfig)
		if err != nil {
			fmt.Println(fmt.Errorf("failed to make request: %s", err))
		} else {
			if addZeroResp.Status == responseData.Status && len(strings.Fields(string(addZeroResp.Body))) == responseData.WordsCount {
				var sqliInfo string
				addOneUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%2b1%2b0")
				addTwoZeroesUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+"%2b0%2b0")

				addOneUrlResp, err := client.Make(addOneUrl, httpReqConfig)
				if err != nil {
					return fmt.Errorf("failed to make request: %s", err)
				}

				diffInStatus := addOneUrlResp.Status != responseData.Status
				diffInWordCount := len(strings.Fields(string(addOneUrlResp.Body))) - responseData.WordsCount
				if diffInStatus || diffInWordCount > 0 {
					// different response when adding +1+0, same response on +0

					if diffInStatus {
						sqliInfo += fmt.Sprintf("Difference in Status when adding %%2b1%%2b0: %s vs %s. \n", addOneUrlResp.Status, responseData.Status)
					}
					if diffInWordCount > 0 {
						sqliInfo += fmt.Sprintf("Difference in word count when adding %%2b1%%2b0: %d words. \n", diffInWordCount)
					}

					addTwoZeroesResp, err := client.Make(addTwoZeroesUrl, httpReqConfig)
					if err != nil {
						return fmt.Errorf("failed to make request: %s", err)
					}

					sameStatus := addTwoZeroesResp.Status == responseData.Status
					diffInWordCount := len(strings.Fields(string(addTwoZeroesResp.Body))) - responseData.WordsCount
					if sameStatus && diffInWordCount == 0 {
						sqliInfo += fmt.Sprintf("Same response when adding %%2b0%%2b0. \n")

						PrintSQLiResult(t.Url, t.Type, t.ParamKey, t.OriginalValue, "Add Zero verification", sqliInfo)
					}
				}
			}
		}
	}

	err = t.internalSQLiWithQuotes("'", "Single Quote", client, &responseData)

	if err != nil {
		fmt.Println(fmt.Errorf("failed to make request: %s", err))
	}

	err = t.internalSQLiWithQuotes("%22", "Double Quote", client, &responseData)

	return err
}

// same function works for both single and double quotes
func (t *FussTarget) internalSQLiWithQuotes(quotesChar string, quotesName string, client *requests.HttpClient, baseResp *ResponseData) error {
	httpReqConfig := requests.HttpReqConfig{
		HTTPMethod: requests.GET,
	}
	addQuoteUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+quotesChar)
	addQuoteResp, err := client.Make(addQuoteUrl, httpReqConfig)
	if err != nil {
		return fmt.Errorf("failed to make request: %s", err)
	}

	diffInStatus := addQuoteResp.Status != baseResp.Status
	diffInWordCount := len(strings.Fields(string(addQuoteResp.Body))) - baseResp.WordsCount
	if diffInStatus || diffInWordCount > 0 {
		// different response when adding a quote
		var sqliInfo string
		if diffInStatus {
			sqliInfo += fmt.Sprintf("Difference in Status when adding %s: %s vs %s. \n", quotesChar, addQuoteResp.Status, baseResp.Status)
		}
		if diffInWordCount > 0 {
			sqliInfo += fmt.Sprintf("Difference in word count when adding %s: %d words. \n", quotesChar, diffInWordCount)
		}

		addTwoQuotesUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+quotesChar+quotesChar)
		addTwoQuotesResp, err := client.Make(addTwoQuotesUrl, httpReqConfig)
		if err != nil {
			return fmt.Errorf("failed to make request: %s", err)
		}

		sameStatus := addTwoQuotesResp.Status == baseResp.Status
		diffInWordCount := len(strings.Fields(string(addTwoQuotesResp.Body))) - baseResp.WordsCount
		if sameStatus && diffInWordCount == 0 {
			addThreeQuotesUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+quotesChar+quotesChar+quotesChar)
			addFourQuotesUrl := strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue+quotesChar+quotesChar+quotesChar+quotesChar)

			addThreeQuotesResp, err3 := client.Make(addThreeQuotesUrl, httpReqConfig)

			addFourQuotesResp, err4 := client.Make(addFourQuotesUrl, httpReqConfig)

			if err3 == nil && err4 == nil {
				diffInStatusThree := addThreeQuotesResp.Status != baseResp.Status
				diffInWordCountThree := len(strings.Fields(string(addThreeQuotesResp.Body))) - baseResp.WordsCount
				sameStatusFour := addFourQuotesResp.Status == baseResp.Status
				diffInWordCountFour := len(strings.Fields(string(addFourQuotesResp.Body))) - baseResp.WordsCount

				if (diffInStatusThree || diffInWordCountThree > 0) && (sameStatusFour && diffInWordCountFour == 0) {
					sqliInfo += "Double verification with three and four quotes. \n"

					PrintSQLiResult(t.Url, t.Type, t.ParamKey, t.OriginalValue, quotesName, sqliInfo)

				}
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

	if strings.HasPrefix(Resp.Status, "5") {
		RespOriginal, err := client.Make(strings.ReplaceAll(t.Url, ReplaceFuss, t.OriginalValue), httpReqConfig)
		if err != nil {
			return fmt.Errorf("failed to make request: %s", err)
		}

		if RespOriginal.Status != Resp.Status {
			// server error confirmed to be caused by the payload
			fmt.Printf("Server Error - %s - %s - payload: %s \n", t.Url, Resp.Status, payload)
		}
	}

	return nil
}

func PrintXssResult(url string, typeDetection TargetType, param string, originalValue string, xssRefs []string, addInfo string) {
	info := ""
	switch typeDetection {
	case PARAM:
		info = "query param"
	case PATH_BIT:
		info = "path bit"
	case PARAM_DISCOVERY:
		info = "param discovery"
	}

	if param != "" {
		info += fmt.Sprintf(" - param %s=%s", param, originalValue)
	}

	if typeDetection == PATH_BIT {
		info += fmt.Sprintf(" - original value %s", originalValue)
	}

	if addInfo != "" {
		info += fmt.Sprintf(" - %s ", addInfo)
	}

	fmt.Printf("XSS - %s - %s - %s \n", url, info, strings.Join(xssRefs, ", "))
}

func PrintSQLiResult(url string, typeDetection TargetType, param string, originalValue string, sqliType string, addInfo string) {
	info := ""
	switch typeDetection {
	case PARAM:
		info = "query param"
	case PATH_BIT:
		info = "path bit"
	case PARAM_DISCOVERY:
		info = "param discovery"
	}

	if param != "" {
		info += fmt.Sprintf(" - param %s=%s", param, originalValue)
	}

	if typeDetection == PATH_BIT {
		info += fmt.Sprintf(" - original value %s", originalValue)
	}

	if addInfo != "" {
		info += fmt.Sprintf("\nFinding info: %s ", addInfo)
	}

	fmt.Printf("SQLi - %s - %s \n", url, info)
}
