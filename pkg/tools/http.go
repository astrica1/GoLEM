// Package tools provides the HTTP tool implementation.
package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
)

type HTTPTool struct {
	*BaseTool
	httpClient *http.Client
}

type HTTPResponse struct {
	Status     int                 `json:"status"`
	StatusText string              `json:"status_text"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body,omitempty"`
	Size       int64               `json:"size"`
	Duration   time.Duration       `json:"duration"`
	URL        string              `json:"url"`
	Method     string              `json:"method"`
}

// NewHTTPTool creates a new HTTP tool
func NewHTTPTool() *HTTPTool {
	schema := golem.ToolSchema{
		Type:        "object",
		Description: "Performs HTTP requests (GET, POST, PUT, DELETE, etc.) with full control over headers, body, and parameters",
		Properties: map[string]golem.ToolSchemaProperty{
			"url": {
				Type:        "string",
				Description: "The URL to request",
			},
			"method": {
				Type:        "string",
				Description: "HTTP method to use",
				Enum:        []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
				Default:     "GET",
			},
			"headers": {
				Type:        "object",
				Description: "HTTP headers to include in the request",
			},
			"body": {
				Type:        "string",
				Description: "Request body content (for POST, PUT, PATCH)",
			},
			"json": {
				Type:        "object",
				Description: "JSON data to send as request body (automatically sets Content-Type)",
			},
			"params": {
				Type:        "object",
				Description: "URL parameters to append to the request",
			},
			"timeout": {
				Type:        "integer",
				Description: "Request timeout in seconds (default: 30)",
				Default:     30,
			},
			"follow_redirects": {
				Type:        "boolean",
				Description: "Whether to follow HTTP redirects (default: true)",
				Default:     true,
			},
			"verify_ssl": {
				Type:        "boolean",
				Description: "Whether to verify SSL certificates (default: true)",
				Default:     true,
			},
			"max_size": {
				Type:        "integer",
				Description: "Maximum response size in bytes (default: 10MB)",
				Default:     10485760,
			},
		},
		Required: []string{"url"},
	}

	return &HTTPTool{
		BaseTool: NewBaseTool(
			"http",
			"Performs HTTP requests with support for all common methods, headers, authentication, and response handling",
			schema,
		),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Execute performs the HTTP request
func (ht *HTTPTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if err := ht.ValidateParams(params); err != nil {
		return nil, err
	}

	url := params["url"].(string)
	method := "GET"
	timeout := 30
	followRedirects := true
	maxSize := int64(10485760)

	if m, exists := params["method"]; exists {
		if mStr, ok := m.(string); ok {
			method = strings.ToUpper(mStr)
		}
	}

	if t, exists := params["timeout"]; exists {
		if tInt, ok := t.(int); ok {
			timeout = tInt
		} else if tFloat, ok := t.(float64); ok {
			timeout = int(tFloat)
		}
	}

	if fr, exists := params["follow_redirects"]; exists {
		if frBool, ok := fr.(bool); ok {
			followRedirects = frBool
		}
	}

	if ms, exists := params["max_size"]; exists {
		if msInt, ok := ms.(int); ok {
			maxSize = int64(msInt)
		} else if msFloat, ok := ms.(float64); ok {
			maxSize = int64(msFloat)
		}
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	finalURL, err := ht.buildURL(url, params)
	if err != nil {
		return nil, fmt.Errorf("failed to build URL: %w", err)
	}

	body, contentType, err := ht.prepareRequestBody(params)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, finalURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil && contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	req.Header.Set("User-Agent", "GoLEM/1.0 HTTP Tool")
	if headers, exists := params["headers"]; exists {
		if headersMap, ok := headers.(map[string]interface{}); ok {
			for key, value := range headersMap {
				req.Header.Set(key, fmt.Sprintf("%v", value))
			}
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	limitedReader := io.LimitReader(resp.Body, maxSize)
	respBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	httpResp := &HTTPResponse{
		Status:     resp.StatusCode,
		StatusText: resp.Status,
		Headers:    resp.Header,
		Body:       string(respBody),
		Size:       int64(len(respBody)),
		Duration:   duration,
		URL:        finalURL,
		Method:     method,
	}

	return httpResp, nil
}

// buildURL builds the final URL with parameters
func (ht *HTTPTool) buildURL(baseURL string, params map[string]interface{}) (string, error) {
	if urlParams, exists := params["params"]; exists {
		if paramsMap, ok := urlParams.(map[string]interface{}); ok {
			if len(paramsMap) > 0 {
				separator := "?"
				if strings.Contains(baseURL, "?") {
					separator = "&"
				}

				var paramPairs []string
				for key, value := range paramsMap {
					paramPairs = append(paramPairs, fmt.Sprintf("%s=%s", key, fmt.Sprintf("%v", value)))
				}

				baseURL += separator + strings.Join(paramPairs, "&")
			}
		}
	}

	return baseURL, nil
}

// prepareRequestBody prepares the request body
func (ht *HTTPTool) prepareRequestBody(params map[string]interface{}) (io.Reader, string, error) {
	if jsonData, exists := params["json"]; exists {
		jsonBytes, err := json.Marshal(jsonData)
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal JSON: %w", err)
		}
		return bytes.NewReader(jsonBytes), "application/json", nil
	}

	if bodyStr, exists := params["body"]; exists {
		if body, ok := bodyStr.(string); ok {
			return strings.NewReader(body), "text/plain", nil
		}
	}

	return nil, "", nil
}

// ValidateParams validates the HTTP parameters
func (ht *HTTPTool) ValidateParams(params map[string]interface{}) error {
	if err := ht.BaseTool.ValidateParams(params); err != nil {
		return err
	}

	url := params["url"].(string)
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("URL must start with http:// or https://")
	}

	if t, exists := params["timeout"]; exists {
		var timeout int
		if tInt, ok := t.(int); ok {
			timeout = tInt
		} else if tFloat, ok := t.(float64); ok {
			timeout = int(tFloat)
		} else {
			return fmt.Errorf("timeout must be an integer")
		}

		if timeout < 1 || timeout > 300 {
			return fmt.Errorf("timeout must be between 1 and 300 seconds")
		}
	}

	if ms, exists := params["max_size"]; exists {
		var maxSize int
		if msInt, ok := ms.(int); ok {
			maxSize = msInt
		} else if msFloat, ok := ms.(float64); ok {
			maxSize = int(msFloat)
		} else {
			return fmt.Errorf("max_size must be an integer")
		}

		if maxSize < 1 || maxSize > 100*1024*1024 {
			return fmt.Errorf("max_size must be between 1 byte and 100MB")
		}
	}

	return nil
}

type DateTimeTool struct {
	*BaseTool
}

// NewDateTimeTool creates a new datetime tool
func NewDateTimeTool() *DateTimeTool {
	schema := golem.ToolSchema{
		Type:        "object",
		Description: "Provides date and time operations including formatting, parsing, arithmetic, and timezone conversions",
		Properties: map[string]golem.ToolSchemaProperty{
			"action": {
				Type:        "string",
				Description: "Action to perform",
				Enum:        []string{"now", "format", "parse", "add", "subtract", "timezone", "compare"},
			},
			"date": {
				Type:        "string",
				Description: "Date/time string to work with",
			},
			"format": {
				Type:        "string",
				Description: "Format string (Go time format or common formats like 'RFC3339', 'ISO8601')",
				Default:     "2006-01-02 15:04:05",
			},
			"timezone": {
				Type:        "string",
				Description: "Timezone (e.g., 'UTC', 'America/New_York', 'Europe/London')",
				Default:     "UTC",
			},
			"amount": {
				Type:        "integer",
				Description: "Amount to add/subtract",
			},
			"unit": {
				Type:        "string",
				Description: "Time unit for arithmetic operations",
				Enum:        []string{"nanoseconds", "microseconds", "milliseconds", "seconds", "minutes", "hours", "days", "weeks", "months", "years"},
			},
			"date2": {
				Type:        "string",
				Description: "Second date for comparison operations",
			},
		},
		Required: []string{"action"},
	}

	return &DateTimeTool{
		BaseTool: NewBaseTool(
			"datetime",
			"Performs comprehensive date and time operations including current time, formatting, parsing, arithmetic, timezone conversions, and comparisons",
			schema,
		),
	}
}

// Execute performs the datetime operation
func (dt *DateTimeTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if err := dt.ValidateParams(params); err != nil {
		return nil, err
	}

	action := params["action"].(string)

	switch action {
	case "now":
		return dt.getCurrentTime(params)
	case "format":
		return dt.formatTime(params)
	case "parse":
		return dt.parseTime(params)
	case "add":
		return dt.addTime(params)
	case "subtract":
		return dt.subtractTime(params)
	case "timezone":
		return dt.convertTimezone(params)
	case "compare":
		return dt.compareTime(params)
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
}

// getCurrentTime returns the current time
func (dt *DateTimeTool) getCurrentTime(params map[string]interface{}) (map[string]interface{}, error) {
	timezone := "UTC"
	format := "2006-01-02 15:04:05"

	if tz, exists := params["timezone"]; exists {
		if tzStr, ok := tz.(string); ok {
			timezone = tzStr
		}
	}

	if fmt, exists := params["format"]; exists {
		if fmtStr, ok := fmt.(string); ok {
			format = dt.normalizeFormat(fmtStr)
		}
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("invalid timezone: %w", err)
	}

	now := time.Now().In(loc)

	return map[string]interface{}{
		"timestamp": now.Unix(),
		"iso8601":   now.Format(time.RFC3339),
		"formatted": now.Format(format),
		"timezone":  timezone,
		"utc":       now.UTC().Format(time.RFC3339),
		"weekday":   now.Weekday().String(),
		"year":      now.Year(),
		"month":     int(now.Month()),
		"day":       now.Day(),
		"hour":      now.Hour(),
		"minute":    now.Minute(),
		"second":    now.Second(),
	}, nil
}

// formatTime formats a given time
func (dt *DateTimeTool) formatTime(params map[string]interface{}) (map[string]interface{}, error) {
	dateStr, exists := params["date"].(string)
	if !exists {
		return nil, fmt.Errorf("date parameter is required for format action")
	}

	format := "2006-01-02 15:04:05"
	if fmt, exists := params["format"]; exists {
		if fmtStr, ok := fmt.(string); ok {
			format = dt.normalizeFormat(fmtStr)
		}
	}

	parsedTime, err := dt.parseTimeString(dateStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse date: %w", err)
	}

	return map[string]interface{}{
		"original":  dateStr,
		"formatted": parsedTime.Format(format),
		"timestamp": parsedTime.Unix(),
	}, nil
}

// parseTime parses a time string
func (dt *DateTimeTool) parseTime(params map[string]interface{}) (map[string]interface{}, error) {
	dateStr, exists := params["date"].(string)
	if !exists {
		return nil, fmt.Errorf("date parameter is required for parse action")
	}

	parsedTime, err := dt.parseTimeString(dateStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse date: %w", err)
	}

	return map[string]interface{}{
		"original":  dateStr,
		"timestamp": parsedTime.Unix(),
		"iso8601":   parsedTime.Format(time.RFC3339),
		"utc":       parsedTime.UTC().Format(time.RFC3339),
		"year":      parsedTime.Year(),
		"month":     int(parsedTime.Month()),
		"day":       parsedTime.Day(),
		"hour":      parsedTime.Hour(),
		"minute":    parsedTime.Minute(),
		"second":    parsedTime.Second(),
		"weekday":   parsedTime.Weekday().String(),
		"timezone":  parsedTime.Location().String(),
	}, nil
}

// addTime adds time to a given date
func (dt *DateTimeTool) addTime(params map[string]interface{}) (map[string]interface{}, error) {
	return dt.performTimeArithmetic(params, true)
}

// subtractTime subtracts time from a given date
func (dt *DateTimeTool) subtractTime(params map[string]interface{}) (map[string]interface{}, error) {
	return dt.performTimeArithmetic(params, false)
}

// performTimeArithmetic performs time arithmetic
func (dt *DateTimeTool) performTimeArithmetic(params map[string]interface{}, add bool) (map[string]interface{}, error) {
	dateStr, exists := params["date"].(string)
	if !exists {
		return nil, fmt.Errorf("date parameter is required")
	}

	amount, exists := params["amount"]
	if !exists {
		return nil, fmt.Errorf("amount parameter is required")
	}

	unit, exists := params["unit"].(string)
	if !exists {
		return nil, fmt.Errorf("unit parameter is required")
	}

	var amountInt int
	if aInt, ok := amount.(int); ok {
		amountInt = aInt
	} else if aFloat, ok := amount.(float64); ok {
		amountInt = int(aFloat)
	} else {
		return nil, fmt.Errorf("amount must be an integer")
	}

	if !add {
		amountInt = -amountInt
	}

	parsedTime, err := dt.parseTimeString(dateStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse date: %w", err)
	}

	var result time.Time
	switch unit {
	case "nanoseconds":
		result = parsedTime.Add(time.Duration(amountInt) * time.Nanosecond)
	case "microseconds":
		result = parsedTime.Add(time.Duration(amountInt) * time.Microsecond)
	case "milliseconds":
		result = parsedTime.Add(time.Duration(amountInt) * time.Millisecond)
	case "seconds":
		result = parsedTime.Add(time.Duration(amountInt) * time.Second)
	case "minutes":
		result = parsedTime.Add(time.Duration(amountInt) * time.Minute)
	case "hours":
		result = parsedTime.Add(time.Duration(amountInt) * time.Hour)
	case "days":
		result = parsedTime.AddDate(0, 0, amountInt)
	case "weeks":
		result = parsedTime.AddDate(0, 0, amountInt*7)
	case "months":
		result = parsedTime.AddDate(0, amountInt, 0)
	case "years":
		result = parsedTime.AddDate(amountInt, 0, 0)
	default:
		return nil, fmt.Errorf("unsupported time unit: %s", unit)
	}

	operation := "add"
	if !add {
		operation = "subtract"
	}

	return map[string]interface{}{
		"original":  dateStr,
		"operation": operation,
		"amount":    amountInt,
		"unit":      unit,
		"result":    result.Format(time.RFC3339),
		"timestamp": result.Unix(),
	}, nil
}

// convertTimezone converts time between timezones
func (dt *DateTimeTool) convertTimezone(params map[string]interface{}) (map[string]interface{}, error) {
	dateStr, exists := params["date"].(string)
	if !exists {
		return nil, fmt.Errorf("date parameter is required for timezone conversion")
	}

	timezone, exists := params["timezone"].(string)
	if !exists {
		return nil, fmt.Errorf("timezone parameter is required for timezone conversion")
	}

	parsedTime, err := dt.parseTimeString(dateStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse date: %w", err)
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("invalid timezone: %w", err)
	}

	converted := parsedTime.In(loc)

	return map[string]interface{}{
		"original":        dateStr,
		"original_tz":     parsedTime.Location().String(),
		"target_tz":       timezone,
		"converted":       converted.Format(time.RFC3339),
		"converted_local": converted.Format("2006-01-02 15:04:05"),
		"timestamp":       converted.Unix(),
	}, nil
}

// compareTime compares two times
func (dt *DateTimeTool) compareTime(params map[string]interface{}) (map[string]interface{}, error) {
	date1Str, exists := params["date"].(string)
	if !exists {
		return nil, fmt.Errorf("date parameter is required for comparison")
	}

	date2Str, exists := params["date2"].(string)
	if !exists {
		return nil, fmt.Errorf("date2 parameter is required for comparison")
	}

	time1, err := dt.parseTimeString(date1Str)
	if err != nil {
		return nil, fmt.Errorf("failed to parse first date: %w", err)
	}

	time2, err := dt.parseTimeString(date2Str)
	if err != nil {
		return nil, fmt.Errorf("failed to parse second date: %w", err)
	}

	diff := time2.Sub(time1)

	var comparison string
	if time1.Before(time2) {
		comparison = "before"
	} else if time1.After(time2) {
		comparison = "after"
	} else {
		comparison = "equal"
	}

	return map[string]interface{}{
		"date1":        date1Str,
		"date2":        date2Str,
		"comparison":   comparison,
		"difference":   diff.String(),
		"diff_seconds": diff.Seconds(),
		"diff_hours":   diff.Hours(),
		"diff_days":    diff.Hours() / 24,
	}, nil
}

// parseTimeString parses various time string formats
func (dt *DateTimeTool) parseTimeString(dateStr string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05.000Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02",
		"01/02/2006",
		"01/02/2006 15:04:05",
		"02-01-2006",
		"02-01-2006 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date string: %s", dateStr)
}

// normalizeFormat normalizes format strings
func (dt *DateTimeTool) normalizeFormat(format string) string {
	switch strings.ToUpper(format) {
	case "RFC3339", "ISO8601":
		return time.RFC3339
	case "RFC822":
		return time.RFC822
	case "RFC850":
		return time.RFC850
	case "RFC1123":
		return time.RFC1123
	case "UNIX":
		return "1136239445"
	default:
		return format
	}
}

// ValidateParams validates the datetime parameters
func (dt *DateTimeTool) ValidateParams(params map[string]interface{}) error {
	if err := dt.BaseTool.ValidateParams(params); err != nil {
		return err
	}

	action := params["action"].(string)

	switch action {
	case "format", "parse":
		if _, exists := params["date"]; !exists {
			return fmt.Errorf("date parameter is required for %s action", action)
		}
	case "add", "subtract":
		if _, exists := params["date"]; !exists {
			return fmt.Errorf("date parameter is required for %s action", action)
		}
		if _, exists := params["amount"]; !exists {
			return fmt.Errorf("amount parameter is required for %s action", action)
		}
		if _, exists := params["unit"]; !exists {
			return fmt.Errorf("unit parameter is required for %s action", action)
		}
	case "timezone":
		if _, exists := params["date"]; !exists {
			return fmt.Errorf("date parameter is required for timezone action")
		}
		if _, exists := params["timezone"]; !exists {
			return fmt.Errorf("timezone parameter is required for timezone action")
		}
	case "compare":
		if _, exists := params["date"]; !exists {
			return fmt.Errorf("date parameter is required for compare action")
		}
		if _, exists := params["date2"]; !exists {
			return fmt.Errorf("date2 parameter is required for compare action")
		}
	}

	return nil
}
