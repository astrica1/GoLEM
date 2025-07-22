// Package tools provides text processing and system info tool implementations.
package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/astrica1/GoLEM/pkg/golem"
)

type TextProcessingTool struct {
	*BaseTool
}

type TextStats struct {
	Characters        int `json:"characters"`
	CharactersNoSpace int `json:"characters_no_space"`
	Words             int `json:"words"`
	Lines             int `json:"lines"`
	Paragraphs        int `json:"paragraphs"`
	Sentences         int `json:"sentences"`
}

// NewTextProcessingTool creates a new text processing tool
func NewTextProcessingTool() *TextProcessingTool {
	schema := golem.ToolSchema{
		Type:        "object",
		Description: "Provides comprehensive text processing operations including analysis, transformation, encoding, and manipulation",
		Properties: map[string]golem.ToolSchemaProperty{
			"action": {
				Type:        "string",
				Description: "Action to perform on the text",
				Enum:        []string{"stats", "transform", "search", "replace", "split", "join", "encode", "decode", "hash", "validate", "extract"},
			},
			"text": {
				Type:        "string",
				Description: "The text to process",
			},
			"operation": {
				Type:        "string",
				Description: "Specific operation for transform action",
				Enum:        []string{"uppercase", "lowercase", "title", "capitalize", "reverse", "trim", "ltrim", "rtrim", "normalize"},
			},
			"pattern": {
				Type:        "string",
				Description: "Pattern to search for (regex supported)",
			},
			"replacement": {
				Type:        "string",
				Description: "Replacement text for replace action",
			},
			"separator": {
				Type:        "string",
				Description: "Separator for split/join operations",
				Default:     " ",
			},
			"encoding": {
				Type:        "string",
				Description: "Encoding type for encode/decode operations",
				Enum:        []string{"base64", "url", "html", "json"},
			},
			"hash_type": {
				Type:        "string",
				Description: "Hash algorithm for hash action",
				Enum:        []string{"crc32", "fnv32", "fnv64"},
				Default:     "fnv32",
			},
			"validation_type": {
				Type:        "string",
				Description: "Validation type for validate action",
				Enum:        []string{"email", "url", "ip", "json", "number", "phone"},
			},
			"extract_type": {
				Type:        "string",
				Description: "Extraction type for extract action",
				Enum:        []string{"emails", "urls", "numbers", "words", "sentences", "phone_numbers"},
			},
			"case_sensitive": {
				Type:        "boolean",
				Description: "Whether operations should be case sensitive (default: false)",
				Default:     false,
			},
			"lines": {
				Type:        "array",
				Description: "Array of strings to join (for join action)",
			},
		},
		Required: []string{"action", "text"},
	}

	return &TextProcessingTool{
		BaseTool: NewBaseTool(
			"text",
			"Comprehensive text processing tool with analysis, transformation, encoding, validation, and extraction capabilities",
			schema,
		),
	}
}

// Execute performs the text processing operation
func (tpt *TextProcessingTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if err := tpt.ValidateParams(params); err != nil {
		return nil, err
	}

	action := params["action"].(string)
	text := params["text"].(string)

	switch action {
	case "stats":
		return tpt.analyzeText(text), nil
	case "transform":
		return tpt.transformText(text, params)
	case "search":
		return tpt.searchText(text, params)
	case "replace":
		return tpt.replaceText(text, params)
	case "split":
		return tpt.splitText(text, params)
	case "join":
		return tpt.joinText(params)
	case "encode":
		return tpt.encodeText(text, params)
	case "decode":
		return tpt.decodeText(text, params)
	case "hash":
		return tpt.hashText(text, params)
	case "validate":
		return tpt.validateText(text, params)
	case "extract":
		return tpt.extractFromText(text, params)
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
}

// analyzeText analyzes text and returns statistics
func (tpt *TextProcessingTool) analyzeText(text string) map[string]interface{} {
	stats := TextStats{
		Characters:        len(text),
		CharactersNoSpace: len(strings.ReplaceAll(text, " ", "")),
		Lines:             strings.Count(text, "\n") + 1,
		Paragraphs:        len(strings.Split(strings.TrimSpace(text), "\n\n")),
	}

	words := strings.Fields(text)
	stats.Words = len(words)

	sentenceEnders := []string{".", "!", "?"}
	sentences := 0
	for _, ender := range sentenceEnders {
		sentences += strings.Count(text, ender)
	}
	stats.Sentences = sentences

	charFreq := make(map[rune]int)
	for _, char := range text {
		charFreq[char]++
	}

	wordFreq := make(map[string]int)
	for _, word := range words {
		cleanWord := strings.ToLower(strings.Trim(word, ".,!?;:\"'"))
		if cleanWord != "" {
			wordFreq[cleanWord]++
		}
	}

	type wordCount struct {
		Word  string `json:"word"`
		Count int    `json:"count"`
	}
	var sortedWords []wordCount
	for word, count := range wordFreq {
		sortedWords = append(sortedWords, wordCount{Word: word, Count: count})
	}
	sort.Slice(sortedWords, func(i, j int) bool {
		return sortedWords[i].Count > sortedWords[j].Count
	})

	if len(sortedWords) > 10 {
		sortedWords = sortedWords[:10]
	}

	return map[string]interface{}{
		"stats":          stats,
		"word_frequency": sortedWords,
		"avg_word_length": func() float64 {
			if len(words) == 0 {
				return 0
			}
			totalLen := 0
			for _, word := range words {
				totalLen += len(word)
			}
			return float64(totalLen) / float64(len(words))
		}(),
		"reading_time_minutes": func() int {
			return stats.Words / 200
		}(),
	}
}

// transformText transforms text based on operation
func (tpt *TextProcessingTool) transformText(text string, params map[string]interface{}) (map[string]interface{}, error) {
	operation, exists := params["operation"].(string)
	if !exists {
		return nil, fmt.Errorf("operation parameter is required for transform action")
	}

	var result string
	switch operation {
	case "uppercase":
		result = strings.ToUpper(text)
	case "lowercase":
		result = strings.ToLower(text)
	case "title":
		result = strings.Title(strings.ToLower(text))
	case "capitalize":
		if len(text) > 0 {
			result = strings.ToUpper(text[:1]) + strings.ToLower(text[1:])
		} else {
			result = text
		}
	case "reverse":
		runes := []rune(text)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		result = string(runes)
	case "trim":
		result = strings.TrimSpace(text)
	case "ltrim":
		result = strings.TrimLeftFunc(text, unicode.IsSpace)
	case "rtrim":
		result = strings.TrimRightFunc(text, unicode.IsSpace)
	case "normalize":
		re := regexp.MustCompile(`\s+`)
		result = strings.TrimSpace(re.ReplaceAllString(text, " "))
	default:
		return nil, fmt.Errorf("unsupported operation: %s", operation)
	}

	return map[string]interface{}{
		"original":      text,
		"operation":     operation,
		"result":        result,
		"length_change": len(result) - len(text),
	}, nil
}

// searchText searches for patterns in text
func (tpt *TextProcessingTool) searchText(text string, params map[string]interface{}) (map[string]interface{}, error) {
	pattern, exists := params["pattern"].(string)
	if !exists {
		return nil, fmt.Errorf("pattern parameter is required for search action")
	}

	caseSensitive := false
	if cs, exists := params["case_sensitive"]; exists {
		if csBool, ok := cs.(bool); ok {
			caseSensitive = csBool
		}
	}

	searchText := text
	searchPattern := pattern
	if !caseSensitive {
		searchText = strings.ToLower(text)
		searchPattern = strings.ToLower(pattern)
	}

	var matches []map[string]interface{}

	if re, err := regexp.Compile(searchPattern); err == nil {
		allMatches := re.FindAllStringIndex(searchText, -1)
		for i, match := range allMatches {
			matches = append(matches, map[string]interface{}{
				"match":    text[match[0]:match[1]],
				"start":    match[0],
				"end":      match[1],
				"position": i + 1,
			})
		}
	} else {
		start := 0
		position := 1
		for {
			index := strings.Index(searchText[start:], searchPattern)
			if index == -1 {
				break
			}
			actualStart := start + index
			actualEnd := actualStart + len(pattern)
			matches = append(matches, map[string]interface{}{
				"match":    text[actualStart:actualEnd],
				"start":    actualStart,
				"end":      actualEnd,
				"position": position,
			})
			start = actualStart + 1
			position++
		}
	}

	return map[string]interface{}{
		"text":           text,
		"pattern":        pattern,
		"case_sensitive": caseSensitive,
		"matches":        matches,
		"count":          len(matches),
	}, nil
}

// replaceText replaces patterns in text
func (tpt *TextProcessingTool) replaceText(text string, params map[string]interface{}) (map[string]interface{}, error) {
	pattern, exists := params["pattern"].(string)
	if !exists {
		return nil, fmt.Errorf("pattern parameter is required for replace action")
	}

	replacement, exists := params["replacement"].(string)
	if !exists {
		return nil, fmt.Errorf("replacement parameter is required for replace action")
	}

	caseSensitive := false
	if cs, exists := params["case_sensitive"]; exists {
		if csBool, ok := cs.(bool); ok {
			caseSensitive = csBool
		}
	}

	var result string
	var count int

	if re, err := regexp.Compile(pattern); err == nil {
		matches := re.FindAllString(text, -1)
		count = len(matches)
		result = re.ReplaceAllString(text, replacement)
	} else {
		if caseSensitive {
			count = strings.Count(text, pattern)
			result = strings.ReplaceAll(text, pattern, replacement)
		} else {
			lowerText := strings.ToLower(text)
			lowerPattern := strings.ToLower(pattern)
			count = strings.Count(lowerText, lowerPattern)

			result = text
			for count > 0 {
				index := strings.Index(strings.ToLower(result), lowerPattern)
				if index == -1 {
					break
				}
				result = result[:index] + replacement + result[index+len(pattern):]
				count--
			}
			count = strings.Count(lowerText, lowerPattern)
		}
	}

	return map[string]interface{}{
		"original":       text,
		"pattern":        pattern,
		"replacement":    replacement,
		"result":         result,
		"replacements":   count,
		"case_sensitive": caseSensitive,
	}, nil
}

// splitText splits text by separator
func (tpt *TextProcessingTool) splitText(text string, params map[string]interface{}) (map[string]interface{}, error) {
	separator := " "
	if sep, exists := params["separator"]; exists {
		if sepStr, ok := sep.(string); ok {
			separator = sepStr
		}
	}

	parts := strings.Split(text, separator)

	return map[string]interface{}{
		"original":  text,
		"separator": separator,
		"parts":     parts,
		"count":     len(parts),
	}, nil
}

// joinText joins array of strings
func (tpt *TextProcessingTool) joinText(params map[string]interface{}) (map[string]interface{}, error) {
	lines, exists := params["lines"]
	if !exists {
		return nil, fmt.Errorf("lines parameter is required for join action")
	}

	separator := " "
	if sep, exists := params["separator"]; exists {
		if sepStr, ok := sep.(string); ok {
			separator = sepStr
		}
	}

	var stringLines []string
	if linesArray, ok := lines.([]interface{}); ok {
		for _, line := range linesArray {
			stringLines = append(stringLines, fmt.Sprintf("%v", line))
		}
	} else {
		return nil, fmt.Errorf("lines must be an array")
	}

	result := strings.Join(stringLines, separator)

	return map[string]interface{}{
		"lines":     stringLines,
		"separator": separator,
		"result":    result,
		"length":    len(result),
	}, nil
}

// encodeText encodes text using specified encoding
func (tpt *TextProcessingTool) encodeText(text string, params map[string]interface{}) (map[string]interface{}, error) {
	encoding, exists := params["encoding"].(string)
	if !exists {
		return nil, fmt.Errorf("encoding parameter is required for encode action")
	}

	var result string
	var err error

	switch encoding {
	case "base64":
		result = base64.StdEncoding.EncodeToString([]byte(text))
	case "url":
		result = url.QueryEscape(text)
	case "html":
		result = strings.ReplaceAll(text, "&", "&amp;")
		result = strings.ReplaceAll(result, "<", "&lt;")
		result = strings.ReplaceAll(result, ">", "&gt;")
		result = strings.ReplaceAll(result, "\"", "&quot;")
		result = strings.ReplaceAll(result, "'", "&#39;")
	case "json":
		jsonBytes, jsonErr := json.Marshal(text)
		if jsonErr != nil {
			err = jsonErr
		} else {
			result = string(jsonBytes)
		}
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}

	if err != nil {
		return nil, fmt.Errorf("encoding failed: %w", err)
	}

	return map[string]interface{}{
		"original": text,
		"encoding": encoding,
		"result":   result,
	}, nil
}

// decodeText decodes text using specified encoding
func (tpt *TextProcessingTool) decodeText(text string, params map[string]interface{}) (map[string]interface{}, error) {
	encoding, exists := params["encoding"].(string)
	if !exists {
		return nil, fmt.Errorf("encoding parameter is required for decode action")
	}

	var result string
	var err error

	switch encoding {
	case "base64":
		decoded, decodeErr := base64.StdEncoding.DecodeString(text)
		if decodeErr != nil {
			err = decodeErr
		} else {
			result = string(decoded)
		}
	case "url":
		result, err = url.QueryUnescape(text)
	case "html":
		result = strings.ReplaceAll(text, "&amp;", "&")
		result = strings.ReplaceAll(result, "&lt;", "<")
		result = strings.ReplaceAll(result, "&gt;", ">")
		result = strings.ReplaceAll(result, "&quot;", "\"")
		result = strings.ReplaceAll(result, "&#39;", "'")
	case "json":
		var decoded string
		if jsonErr := json.Unmarshal([]byte(text), &decoded); jsonErr != nil {
			err = jsonErr
		} else {
			result = decoded
		}
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}

	if err != nil {
		return nil, fmt.Errorf("decoding failed: %w", err)
	}

	return map[string]interface{}{
		"original": text,
		"encoding": encoding,
		"result":   result,
	}, nil
}

// hashText generates hash of text
func (tpt *TextProcessingTool) hashText(text string, params map[string]interface{}) (map[string]interface{}, error) {
	hashType := "fnv32"
	if ht, exists := params["hash_type"]; exists {
		if htStr, ok := ht.(string); ok {
			hashType = htStr
		}
	}

	var hashValue string
	switch hashType {
	case "crc32":
		hash := crc32.ChecksumIEEE([]byte(text))
		hashValue = fmt.Sprintf("%x", hash)
	case "fnv32":
		hash := fnv.New32()
		hash.Write([]byte(text))
		hashValue = fmt.Sprintf("%x", hash.Sum32())
	case "fnv64":
		hash := fnv.New64()
		hash.Write([]byte(text))
		hashValue = fmt.Sprintf("%x", hash.Sum64())
	default:
		return nil, fmt.Errorf("unsupported hash type: %s", hashType)
	}

	return map[string]interface{}{
		"text":      text,
		"hash_type": hashType,
		"hash":      hashValue,
	}, nil
}

// validateText validates text based on type
func (tpt *TextProcessingTool) validateText(text string, params map[string]interface{}) (map[string]interface{}, error) {
	validationType, exists := params["validation_type"].(string)
	if !exists {
		return nil, fmt.Errorf("validation_type parameter is required for validate action")
	}

	var isValid bool
	var details string

	switch validationType {
	case "email":
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		isValid = emailRegex.MatchString(text)
		if !isValid {
			details = "Email format is invalid"
		}
	case "url":
		urlRegex := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
		isValid = urlRegex.MatchString(text)
		if !isValid {
			details = "URL format is invalid"
		}
	case "ip":
		ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
		isValid = ipRegex.MatchString(text)
		if isValid {
			parts := strings.Split(text, ".")
			for _, part := range parts {
				num, err := strconv.Atoi(part)
				if err != nil || num < 0 || num > 255 {
					isValid = false
					details = "IP address octets must be between 0 and 255"
					break
				}
			}
		} else {
			details = "IP address format is invalid"
		}
	case "json":
		var temp interface{}
		err := json.Unmarshal([]byte(text), &temp)
		isValid = err == nil
		if !isValid {
			details = fmt.Sprintf("JSON is invalid: %v", err)
		}
	case "number":
		_, err := strconv.ParseFloat(text, 64)
		isValid = err == nil
		if !isValid {
			details = "Not a valid number"
		}
	case "phone":
		phoneRegex := regexp.MustCompile(`^\+?1?[-.\s]?(\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})$`)
		isValid = phoneRegex.MatchString(text)
		if !isValid {
			details = "Phone number format is invalid"
		}
	default:
		return nil, fmt.Errorf("unsupported validation type: %s", validationType)
	}

	return map[string]interface{}{
		"text":            text,
		"validation_type": validationType,
		"is_valid":        isValid,
		"details":         details,
	}, nil
}

// extractFromText extracts specific patterns from text
func (tpt *TextProcessingTool) extractFromText(text string, params map[string]interface{}) (map[string]interface{}, error) {
	extractType, exists := params["extract_type"].(string)
	if !exists {
		return nil, fmt.Errorf("extract_type parameter is required for extract action")
	}

	var results []string
	var pattern *regexp.Regexp

	switch extractType {
	case "emails":
		pattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	case "urls":
		pattern = regexp.MustCompile(`https?://[^\s/$.?#].[^\s]*`)
	case "numbers":
		pattern = regexp.MustCompile(`-?\d+(?:\.\d+)?`)
	case "words":
		pattern = regexp.MustCompile(`\b\w+\b`)
	case "sentences":
		pattern = regexp.MustCompile(`[^.!?]*[.!?]`)
	case "phone_numbers":
		pattern = regexp.MustCompile(`\+?1?[-.\s]?(\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})`)
	default:
		return nil, fmt.Errorf("unsupported extract type: %s", extractType)
	}

	if pattern != nil {
		matches := pattern.FindAllString(text, -1)
		for _, match := range matches {
			trimmed := strings.TrimSpace(match)
			if trimmed != "" {
				results = append(results, trimmed)
			}
		}
	}

	return map[string]interface{}{
		"text":         text,
		"extract_type": extractType,
		"results":      results,
		"count":        len(results),
	}, nil
}

// ValidateParams validates the text processing parameters
func (tpt *TextProcessingTool) ValidateParams(params map[string]interface{}) error {
	if err := tpt.BaseTool.ValidateParams(params); err != nil {
		return err
	}

	action := params["action"].(string)

	switch action {
	case "transform":
		if _, exists := params["operation"]; !exists {
			return fmt.Errorf("operation parameter is required for transform action")
		}
	case "search":
		if _, exists := params["pattern"]; !exists {
			return fmt.Errorf("pattern parameter is required for search action")
		}
	case "replace":
		if _, exists := params["pattern"]; !exists {
			return fmt.Errorf("pattern parameter is required for replace action")
		}
		if _, exists := params["replacement"]; !exists {
			return fmt.Errorf("replacement parameter is required for replace action")
		}
	case "join":
		if _, exists := params["lines"]; !exists {
			return fmt.Errorf("lines parameter is required for join action")
		}
	case "encode", "decode":
		if _, exists := params["encoding"]; !exists {
			return fmt.Errorf("encoding parameter is required for %s action", action)
		}
	case "validate":
		if _, exists := params["validation_type"]; !exists {
			return fmt.Errorf("validation_type parameter is required for validate action")
		}
	case "extract":
		if _, exists := params["extract_type"]; !exists {
			return fmt.Errorf("extract_type parameter is required for extract action")
		}
	}

	return nil
}

type SystemInfoTool struct {
	*BaseTool
}

type SystemInfo struct {
	OS           string            `json:"os"`
	Architecture string            `json:"architecture"`
	CPUs         int               `json:"cpus"`
	GoVersion    string            `json:"go_version"`
	Hostname     string            `json:"hostname"`
	Environment  map[string]string `json:"environment,omitempty"`
	Memory       *MemoryInfo       `json:"memory,omitempty"`
	Uptime       time.Duration     `json:"uptime,omitempty"`
}

type MemoryInfo struct {
	AllocMB      uint64 `json:"alloc_mb"`
	TotalAllocMB uint64 `json:"total_alloc_mb"`
	SysMB        uint64 `json:"sys_mb"`
	NumGC        uint32 `json:"num_gc"`
}

// NewSystemInfoTool creates a new system info tool
func NewSystemInfoTool() *SystemInfoTool {
	schema := golem.ToolSchema{
		Type:        "object",
		Description: "Provides system information, environment details, and basic diagnostics",
		Properties: map[string]golem.ToolSchemaProperty{
			"info_type": {
				Type:        "string",
				Description: "Type of information to retrieve",
				Enum:        []string{"all", "basic", "memory", "environment", "runtime"},
				Default:     "basic",
			},
			"include_env": {
				Type:        "boolean",
				Description: "Include environment variables (default: false for security)",
				Default:     false,
			},
			"env_filter": {
				Type:        "string",
				Description: "Filter environment variables by prefix (e.g., 'GO', 'PATH')",
			},
		},
		Required: []string{},
	}

	return &SystemInfoTool{
		BaseTool: NewBaseTool(
			"system",
			"Retrieves system information including OS details, memory usage, runtime information, and environment variables",
			schema,
		),
	}
}

// Execute retrieves system information
func (sit *SystemInfoTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if err := sit.ValidateParams(params); err != nil {
		return nil, err
	}

	infoType := "basic"
	includeEnv := false
	envFilter := ""

	if it, exists := params["info_type"]; exists {
		if itStr, ok := it.(string); ok {
			infoType = itStr
		}
	}

	if ie, exists := params["include_env"]; exists {
		if ieBool, ok := ie.(bool); ok {
			includeEnv = ieBool
		}
	}

	if ef, exists := params["env_filter"]; exists {
		if efStr, ok := ef.(string); ok {
			envFilter = efStr
		}
	}

	info := &SystemInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPUs:         runtime.NumCPU(),
		GoVersion:    runtime.Version(),
	}

	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	switch infoType {
	case "all":
		sit.addMemoryInfo(info)
		if includeEnv {
			sit.addEnvironmentInfo(info, envFilter)
		}
		sit.addRuntimeInfo(info)
	case "memory":
		sit.addMemoryInfo(info)
	case "environment":
		if includeEnv {
			sit.addEnvironmentInfo(info, envFilter)
		}
	case "runtime":
		sit.addRuntimeInfo(info)
	}

	return info, nil
}

// addMemoryInfo adds memory usage information
func (sit *SystemInfoTool) addMemoryInfo(info *SystemInfo) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	info.Memory = &MemoryInfo{
		AllocMB:      bToMb(m.Alloc),
		TotalAllocMB: bToMb(m.TotalAlloc),
		SysMB:        bToMb(m.Sys),
		NumGC:        m.NumGC,
	}
}

// addEnvironmentInfo adds environment variables
func (sit *SystemInfoTool) addEnvironmentInfo(info *SystemInfo, filter string) {
	info.Environment = make(map[string]string)

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			key, value := parts[0], parts[1]

			if filter == "" || strings.HasPrefix(key, filter) {
				if sit.isSensitiveEnvVar(key) {
					info.Environment[key] = "***masked***"
				} else {
					info.Environment[key] = value
				}
			}
		}
	}
}

// addRuntimeInfo adds runtime-specific information
func (sit *SystemInfoTool) addRuntimeInfo(info *SystemInfo) {
	numGoroutines := runtime.NumGoroutine()

	// TODO: Add more runtime information as needed
	if info.Environment == nil {
		info.Environment = make(map[string]string)
	}

	info.Environment["GOROUTINES"] = fmt.Sprintf("%d", numGoroutines)
	info.Environment["GOMAXPROCS"] = fmt.Sprintf("%d", runtime.GOMAXPROCS(0))
}

// isSensitiveEnvVar checks if an environment variable is sensitive
func (sit *SystemInfoTool) isSensitiveEnvVar(key string) bool {
	sensitiveKeys := []string{
		"PASSWORD", "SECRET", "TOKEN", "KEY", "PRIVATE",
		"API_KEY", "AUTH", "CREDENTIAL", "CERT", "SSL",
		"DATABASE_URL", "DB_PASSWORD", "OPENAI_API_KEY",
		"ANTHROPIC_API_KEY", "OLLAMA_API_KEY",
	}

	upperKey := strings.ToUpper(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(upperKey, sensitive) {
			return true
		}
	}

	return false
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

// ValidateParams validates the system info parameters
func (sit *SystemInfoTool) ValidateParams(params map[string]interface{}) error {
	return sit.BaseTool.ValidateParams(params)
}
