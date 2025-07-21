// Package tools provides the search tool implementation.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
)

type SearchTool struct {
	*BaseTool
	apiKey       string
	searchEngine string
	httpClient   *http.Client
}

type SearchResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
	Source  string `json:"source"`
}

type SearchResponse struct {
	Query        string         `json:"query"`
	TotalResults int            `json:"total_results"`
	Results      []SearchResult `json:"results"`
	SearchTime   time.Duration  `json:"search_time"`
}

// NewSearchTool creates a new search tool
func NewSearchTool() *SearchTool {
	schema := golem.ToolSchema{
		Type:        "object",
		Description: "Searches the web for information using various search engines",
		Properties: map[string]golem.ToolSchemaProperty{
			"query": {
				Type:        "string",
				Description: "The search query to execute",
			},
			"max_results": {
				Type:        "integer",
				Description: "Maximum number of results to return (default: 5, max: 20)",
				Default:     5,
			},
			"engine": {
				Type:        "string",
				Description: "Search engine to use",
				Enum:        []string{"duckduckgo", "google", "bing"},
				Default:     "duckduckgo",
			},
			"safe_search": {
				Type:        "boolean",
				Description: "Enable safe search filtering (default: true)",
				Default:     true,
			},
			"region": {
				Type:        "string",
				Description: "Region/country code for localized results (e.g., 'us', 'uk', 'de', 'ir')",
				Default:     "us",
			},
		},
		Required: []string{"query"},
	}

	return &SearchTool{
		BaseTool: NewBaseTool(
			"search",
			"Performs web searches using various search engines (DuckDuckGo, Google, Bing) and returns relevant results",
			schema,
		),
		searchEngine: "duckduckgo",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Execute performs the web search
func (st *SearchTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if err := st.ValidateParams(params); err != nil {
		return nil, err
	}

	query := params["query"].(string)
	maxResults := 5
	engine := "duckduckgo"
	safeSearch := true
	region := "us"

	if mr, exists := params["max_results"]; exists {
		if mrInt, ok := mr.(int); ok {
			maxResults = mrInt
		} else if mrFloat, ok := mr.(float64); ok {
			maxResults = int(mrFloat)
		}
	}

	if e, exists := params["engine"]; exists {
		if eStr, ok := e.(string); ok {
			engine = eStr
		}
	}

	if ss, exists := params["safe_search"]; exists {
		if ssBool, ok := ss.(bool); ok {
			safeSearch = ssBool
		}
	}

	if r, exists := params["region"]; exists {
		if rStr, ok := r.(string); ok {
			region = rStr
		}
	}

	if maxResults > 20 {
		maxResults = 20
	}
	if maxResults < 1 {
		maxResults = 1
	}

	start := time.Now()
	results, err := st.performSearch(ctx, query, engine, maxResults, safeSearch, region)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	response := &SearchResponse{
		Query:        query,
		TotalResults: len(results),
		Results:      results,
		SearchTime:   time.Since(start),
	}

	return response, nil
}

// performSearch executes the actual search based on the selected engine
func (st *SearchTool) performSearch(ctx context.Context, query, engine string, maxResults int, safeSearch bool, region string) ([]SearchResult, error) {
	switch strings.ToLower(engine) {
	case "duckduckgo":
		return st.searchDuckDuckGo(ctx, query, maxResults, safeSearch, region)
	case "google":
		return st.searchGoogle(ctx, query, maxResults, safeSearch, region)
	case "bing":
		return st.searchBing(ctx, query, maxResults, safeSearch, region)
	default:
		return nil, fmt.Errorf("unsupported search engine: %s", engine)
	}
}

// searchDuckDuckGo performs search using DuckDuckGo Instant Answer API
func (st *SearchTool) searchDuckDuckGo(ctx context.Context, query string, maxResults int, safeSearch bool, region string) ([]SearchResult, error) {
	// DuckDuckGo Instant Answer API
	baseURL := "https://api.duckduckgo.com/"
	params := url.Values{}
	params.Set("q", query)
	params.Set("format", "json")
	params.Set("no_redirect", "1")
	params.Set("no_html", "1")
	params.Set("skip_disambig", "1")

	if safeSearch {
		params.Set("safe_search", "strict")
	}

	reqURL := baseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "GoLEM/1.0 (https://github.com/astrica1/GoLEM)")

	resp, err := st.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DuckDuckGo API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ddgResp struct {
		Abstract       string `json:"Abstract"`
		AbstractSource string `json:"AbstractSource"`
		AbstractURL    string `json:"AbstractURL"`
		Answer         string `json:"Answer"`
		AnswerType     string `json:"AnswerType"`
		Definition     string `json:"Definition"`
		DefinitionURL  string `json:"DefinitionURL"`
		Heading        string `json:"Heading"`
		Results        []struct {
			FirstURL string `json:"FirstURL"`
			Icon     struct {
				URL string `json:"URL"`
			} `json:"Icon"`
			Result string `json:"Result"`
			Text   string `json:"Text"`
		} `json:"Results"`
		RelatedTopics []struct {
			FirstURL string `json:"FirstURL"`
			Result   string `json:"Result"`
			Text     string `json:"Text"`
		} `json:"RelatedTopics"`
	}

	if err := json.Unmarshal(body, &ddgResp); err != nil {
		return nil, err
	}

	var results []SearchResult

	if ddgResp.Answer != "" {
		results = append(results, SearchResult{
			Title:   ddgResp.Heading,
			URL:     ddgResp.AbstractURL,
			Snippet: ddgResp.Answer,
			Source:  "DuckDuckGo Instant Answer",
		})
	}

	if ddgResp.Abstract != "" && len(results) < maxResults {
		results = append(results, SearchResult{
			Title:   ddgResp.Heading,
			URL:     ddgResp.AbstractURL,
			Snippet: ddgResp.Abstract,
			Source:  ddgResp.AbstractSource,
		})
	}

	if ddgResp.Definition != "" && len(results) < maxResults {
		results = append(results, SearchResult{
			Title:   "Definition",
			URL:     ddgResp.DefinitionURL,
			Snippet: ddgResp.Definition,
			Source:  "DuckDuckGo Definition",
		})
	}

	for _, result := range ddgResp.Results {
		if len(results) >= maxResults {
			break
		}
		if result.FirstURL != "" && result.Text != "" {
			results = append(results, SearchResult{
				Title:   extractTitle(result.Result),
				URL:     result.FirstURL,
				Snippet: result.Text,
				Source:  "DuckDuckGo",
			})
		}
	}

	// Add related topics
	for _, topic := range ddgResp.RelatedTopics {
		if len(results) >= maxResults {
			break
		}
		if topic.FirstURL != "" && topic.Text != "" {
			results = append(results, SearchResult{
				Title:   extractTitle(topic.Result),
				URL:     topic.FirstURL,
				Snippet: topic.Text,
				Source:  "DuckDuckGo Related",
			})
		}
	}

	// If we have few results, try to get more from web search
	if len(results) < maxResults {
		webResults, err := st.searchDuckDuckGoWeb(ctx, query, maxResults-len(results))
		if err == nil {
			results = append(results, webResults...)
		}
	}

	return results, nil
}

// searchDuckDuckGoWeb performs web search using DuckDuckGo HTML scraping (fallback)
func (st *SearchTool) searchDuckDuckGoWeb(ctx context.Context, query string, maxResults int) ([]SearchResult, error) {
	// TODO: implement web search using DuckDuckGo HTML scraping

	baseURL := "https://duckduckgo.com/html/"
	params := url.Values{}
	params.Set("q", query)

	reqURL := baseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := st.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return []SearchResult{}, nil
}

// searchGoogle performs search using Google Custom Search API (requires API key)
func (st *SearchTool) searchGoogle(ctx context.Context, query string, maxResults int, safeSearch bool, region string) ([]SearchResult, error) {
	if st.apiKey == "" {
		return nil, fmt.Errorf("Google search requires API key")
	}

	baseURL := "https://www.googleapis.com/customsearch/v1"
	params := url.Values{}
	params.Set("key", st.apiKey)
	params.Set("cx", "017576662512468239146:omuauf_lfve") // TODO: replace with your own Custom Search Engine ID
	params.Set("q", query)
	params.Set("num", fmt.Sprintf("%d", maxResults))
	params.Set("gl", region)

	if safeSearch {
		params.Set("safe", "active")
	}

	reqURL := baseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := st.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var googleResp struct {
		Items []struct {
			Title   string `json:"title"`
			Link    string `json:"link"`
			Snippet string `json:"snippet"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &googleResp); err != nil {
		return nil, err
	}

	var results []SearchResult
	for _, item := range googleResp.Items {
		results = append(results, SearchResult{
			Title:   item.Title,
			URL:     item.Link,
			Snippet: item.Snippet,
			Source:  "Google",
		})
	}

	return results, nil
}

// searchBing performs search using Bing Search API (requires API key)
func (st *SearchTool) searchBing(ctx context.Context, query string, maxResults int, safeSearch bool, region string) ([]SearchResult, error) {
	if st.apiKey == "" {
		return nil, fmt.Errorf("Bing search requires API key")
	}

	baseURL := "https://api.bing.microsoft.com/v7.0/search"
	params := url.Values{}
	params.Set("q", query)
	params.Set("count", fmt.Sprintf("%d", maxResults))
	params.Set("mkt", region+"-"+strings.ToUpper(region))

	if safeSearch {
		params.Set("safeSearch", "Strict")
	}

	reqURL := baseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Ocp-Apim-Subscription-Key", st.apiKey)

	resp, err := st.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Bing API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var bingResp struct {
		WebPages struct {
			Value []struct {
				Name    string `json:"name"`
				URL     string `json:"url"`
				Snippet string `json:"snippet"`
			} `json:"value"`
		} `json:"webPages"`
	}

	if err := json.Unmarshal(body, &bingResp); err != nil {
		return nil, err
	}

	var results []SearchResult
	for _, item := range bingResp.WebPages.Value {
		results = append(results, SearchResult{
			Title:   item.Name,
			URL:     item.URL,
			Snippet: item.Snippet,
			Source:  "Bing",
		})
	}

	return results, nil
}

// extractTitle extracts title from HTML result
func extractTitle(htmlResult string) string {
	title := strings.ReplaceAll(htmlResult, "<b>", "")
	title = strings.ReplaceAll(title, "</b>", "")
	title = strings.ReplaceAll(title, "<em>", "")
	title = strings.ReplaceAll(title, "</em>", "")

	if idx := strings.Index(title, " - "); idx > 0 {
		title = title[:idx]
	}

	if len(title) > 100 {
		title = title[:97] + "..."
	}

	return strings.TrimSpace(title)
}

// SetAPIKey sets the API key for search engines that require it
func (st *SearchTool) SetAPIKey(apiKey string) {
	st.apiKey = apiKey
}

// ValidateParams validates the search parameters
func (st *SearchTool) ValidateParams(params map[string]interface{}) error {
	if err := st.BaseTool.ValidateParams(params); err != nil {
		return err
	}

	query := params["query"].(string)
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("search query cannot be empty")
	}

	if mr, exists := params["max_results"]; exists {
		var maxResults int
		if mrInt, ok := mr.(int); ok {
			maxResults = mrInt
		} else if mrFloat, ok := mr.(float64); ok {
			maxResults = int(mrFloat)
		} else {
			return fmt.Errorf("max_results must be an integer")
		}

		if maxResults < 1 || maxResults > 20 {
			return fmt.Errorf("max_results must be between 1 and 20")
		}
	}

	return nil
}
