// Package tools provides the Wikipedia tool implementation.
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

type WikipediaTool struct {
	*BaseTool
	httpClient *http.Client
}

type WikipediaPage struct {
	Title        string           `json:"title"`
	PageID       int              `json:"page_id"`
	URL          string           `json:"url"`
	Summary      string           `json:"summary"`
	Content      string           `json:"content,omitempty"`
	Images       []WikipediaImage `json:"images,omitempty"`
	Categories   []string         `json:"categories,omitempty"`
	Languages    []WikipediaLang  `json:"languages,omitempty"`
	Coordinates  *WikipediaCoords `json:"coordinates,omitempty"`
	LastModified time.Time        `json:"last_modified"`
}

type WikipediaImage struct {
	URL         string `json:"url"`
	Description string `json:"description"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
}

type WikipediaLang struct {
	Language string `json:"language"`
	Title    string `json:"title"`
	URL      string `json:"url"`
}

type WikipediaCoords struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type WikipediaSearchResult struct {
	Query   string          `json:"query"`
	Results []WikipediaPage `json:"results"`
	Count   int             `json:"count"`
}

// NewWikipediaTool creates a new Wikipedia tool
func NewWikipediaTool() *WikipediaTool {
	schema := golem.ToolSchema{
		Type:        "object",
		Description: "Searches Wikipedia and retrieves article content",
		Properties: map[string]golem.ToolSchemaProperty{
			"action": {
				Type:        "string",
				Description: "Action to perform",
				Enum:        []string{"search", "get_page", "get_summary"},
				Default:     "search",
			},
			"query": {
				Type:        "string",
				Description: "Search query or page title",
			},
			"language": {
				Type:        "string",
				Description: "Wikipedia language code (default: en)",
				Default:     "en",
			},
			"limit": {
				Type:        "integer",
				Description: "Maximum number of search results (default: 5, max: 20)",
				Default:     5,
			},
			"include_images": {
				Type:        "boolean",
				Description: "Include images in the result (default: false)",
				Default:     false,
			},
			"include_content": {
				Type:        "boolean",
				Description: "Include full content for get_page action (default: false)",
				Default:     false,
			},
			"summary_length": {
				Type:        "integer",
				Description: "Length of summary in characters (default: 500)",
				Default:     500,
			},
		},
		Required: []string{"query"},
	}

	return &WikipediaTool{
		BaseTool: NewBaseTool(
			"wikipedia",
			"Searches Wikipedia articles, retrieves page content, and provides summaries with support for multiple languages",
			schema,
		),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Execute performs the Wikipedia operation
func (wt *WikipediaTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if err := wt.ValidateParams(params); err != nil {
		return nil, err
	}

	query := params["query"].(string)
	action := "search"
	language := "en"
	limit := 5
	includeImages := false
	includeContent := false
	summaryLength := 500

	if a, exists := params["action"]; exists {
		if aStr, ok := a.(string); ok {
			action = aStr
		}
	}

	if l, exists := params["language"]; exists {
		if lStr, ok := l.(string); ok {
			language = lStr
		}
	}

	if lim, exists := params["limit"]; exists {
		if limInt, ok := lim.(int); ok {
			limit = limInt
		} else if limFloat, ok := lim.(float64); ok {
			limit = int(limFloat)
		}
	}

	if ii, exists := params["include_images"]; exists {
		if iiBool, ok := ii.(bool); ok {
			includeImages = iiBool
		}
	}

	if ic, exists := params["include_content"]; exists {
		if icBool, ok := ic.(bool); ok {
			includeContent = icBool
		}
	}

	if sl, exists := params["summary_length"]; exists {
		if slInt, ok := sl.(int); ok {
			summaryLength = slInt
		} else if slFloat, ok := sl.(float64); ok {
			summaryLength = int(slFloat)
		}
	}

	if limit > 20 {
		limit = 20
	}
	if limit < 1 {
		limit = 1
	}

	if summaryLength > 2000 {
		summaryLength = 2000
	}
	if summaryLength < 100 {
		summaryLength = 100
	}

	switch action {
	case "search":
		return wt.searchWikipedia(ctx, query, language, limit, includeImages)
	case "get_page":
		return wt.getWikipediaPage(ctx, query, language, includeImages, includeContent)
	case "get_summary":
		return wt.getWikipediaSummary(ctx, query, language, summaryLength)
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
}

// searchWikipedia searches for Wikipedia articles
func (wt *WikipediaTool) searchWikipedia(ctx context.Context, query, language string, limit int, includeImages bool) (*WikipediaSearchResult, error) {
	baseURL := fmt.Sprintf("https://%s.wikipedia.org/w/api.php", language)
	params := url.Values{}
	params.Set("action", "opensearch")
	params.Set("search", query)
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("format", "json")
	params.Set("redirects", "resolve")

	reqURL := baseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "GoLEM/1.0 (https://github.com/astrica1/GoLEM)")

	resp, err := wt.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Wikipedia API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var searchResp []interface{}
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return nil, err
	}

	if len(searchResp) < 4 {
		return &WikipediaSearchResult{
			Query:   query,
			Results: []WikipediaPage{},
			Count:   0,
		}, nil
	}

	titles, _ := searchResp[1].([]interface{})
	descriptions, _ := searchResp[2].([]interface{})
	urls, _ := searchResp[3].([]interface{})

	var results []WikipediaPage
	for i := 0; i < len(titles) && i < limit; i++ {
		title := fmt.Sprintf("%v", titles[i])
		description := ""
		pageURL := ""

		if i < len(descriptions) {
			description = fmt.Sprintf("%v", descriptions[i])
		}
		if i < len(urls) {
			pageURL = fmt.Sprintf("%v", urls[i])
		}

		page := WikipediaPage{
			Title:   title,
			URL:     pageURL,
			Summary: description,
		}

		if includeImages {
			pageDetails, err := wt.getPageDetails(ctx, title, language)
			if err == nil {
				page.Images = pageDetails.Images
				page.Categories = pageDetails.Categories
			}
		}

		results = append(results, page)
	}

	return &WikipediaSearchResult{
		Query:   query,
		Results: results,
		Count:   len(results),
	}, nil
}

// getWikipediaPage retrieves a specific Wikipedia page
func (wt *WikipediaTool) getWikipediaPage(ctx context.Context, title, language string, includeImages, includeContent bool) (*WikipediaPage, error) {
	baseURL := fmt.Sprintf("https://%s.wikipedia.org/w/api.php", language)
	params := url.Values{}
	params.Set("action", "query")
	params.Set("format", "json")
	params.Set("titles", title)
	params.Set("prop", "extracts|info|pageimages")
	params.Set("exintro", "1")
	params.Set("explaintext", "1")
	params.Set("inprop", "url")

	if includeContent {
		params.Set("exintro", "0")
	}

	reqURL := baseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "GoLEM/1.0 (https://github.com/astrica1/GoLEM)")

	resp, err := wt.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Wikipedia API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp struct {
		Query struct {
			Pages map[string]struct {
				PageID    int    `json:"pageid"`
				Title     string `json:"title"`
				Extract   string `json:"extract"`
				FullURL   string `json:"fullurl"`
				Missing   bool   `json:"missing"`
				Thumbnail struct {
					Source string `json:"source"`
					Width  int    `json:"width"`
					Height int    `json:"height"`
				} `json:"thumbnail"`
			} `json:"pages"`
		} `json:"query"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	for pageID, pageData := range apiResp.Query.Pages {
		if pageData.Missing {
			return nil, fmt.Errorf("Wikipedia page not found: %s", title)
		}

		page := &WikipediaPage{
			PageID:  pageData.PageID,
			Title:   pageData.Title,
			URL:     pageData.FullURL,
			Summary: pageData.Extract,
		}

		if includeContent {
			page.Content = pageData.Extract
		}

		if includeImages && pageData.Thumbnail.Source != "" {
			page.Images = append(page.Images, WikipediaImage{
				URL:    pageData.Thumbnail.Source,
				Width:  pageData.Thumbnail.Width,
				Height: pageData.Thumbnail.Height,
			})
		}

		if includeImages {
			details, err := wt.getPageDetails(ctx, title, language)
			if err == nil {
				page.Images = append(page.Images, details.Images...)
				page.Categories = details.Categories
				page.Languages = details.Languages
				page.Coordinates = details.Coordinates
			}
		}

		if pageID == "-1" {
			return nil, fmt.Errorf("invalid page ID")
		}

		return page, nil
	}

	return nil, fmt.Errorf("no page data found")
}

// getWikipediaSummary retrieves a summary of a Wikipedia page
func (wt *WikipediaTool) getWikipediaSummary(ctx context.Context, title, language string, maxLength int) (*WikipediaPage, error) {
	page, err := wt.getWikipediaPage(ctx, title, language, false, false)
	if err != nil {
		return nil, err
	}

	if len(page.Summary) > maxLength {
		page.Summary = page.Summary[:maxLength-3] + "..."
	}

	return page, nil
}

// getPageDetails retrieves additional page details
func (wt *WikipediaTool) getPageDetails(ctx context.Context, title, language string) (*WikipediaPage, error) {
	baseURL := fmt.Sprintf("https://%s.wikipedia.org/w/api.php", language)
	params := url.Values{}
	params.Set("action", "query")
	params.Set("format", "json")
	params.Set("titles", title)
	params.Set("prop", "categories|images|langlinks|coordinates")
	params.Set("cllimit", "10")
	params.Set("imlimit", "5")
	params.Set("lllimit", "10")

	reqURL := baseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "GoLEM/1.0 (https://github.com/astrica1/GoLEM)")

	resp, err := wt.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Wikipedia API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp struct {
		Query struct {
			Pages map[string]struct {
				Categories []struct {
					Title string `json:"title"`
				} `json:"categories"`
				Images []struct {
					Title string `json:"title"`
				} `json:"images"`
				Langlinks []struct {
					Lang  string `json:"lang"`
					Title string `json:"*"`
					URL   string `json:"url"`
				} `json:"langlinks"`
				Coordinates []struct {
					Lat float64 `json:"lat"`
					Lon float64 `json:"lon"`
				} `json:"coordinates"`
			} `json:"pages"`
		} `json:"query"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	page := &WikipediaPage{}

	for _, pageData := range apiResp.Query.Pages {
		for _, cat := range pageData.Categories {
			categoryName := strings.TrimPrefix(cat.Title, "Category:")
			page.Categories = append(page.Categories, categoryName)
		}

		for _, img := range pageData.Images {
			if strings.HasSuffix(strings.ToLower(img.Title), ".jpg") ||
				strings.HasSuffix(strings.ToLower(img.Title), ".png") ||
				strings.HasSuffix(strings.ToLower(img.Title), ".gif") ||
				strings.HasSuffix(strings.ToLower(img.Title), ".svg") {

				imageURL := fmt.Sprintf("https://%s.wikipedia.org/wiki/%s", language, url.QueryEscape(img.Title))
				page.Images = append(page.Images, WikipediaImage{
					URL:         imageURL,
					Description: img.Title,
				})
			}
		}

		for _, lang := range pageData.Langlinks {
			page.Languages = append(page.Languages, WikipediaLang{
				Language: lang.Lang,
				Title:    lang.Title,
				URL:      lang.URL,
			})
		}

		if len(pageData.Coordinates) > 0 {
			coord := pageData.Coordinates[0]
			page.Coordinates = &WikipediaCoords{
				Latitude:  coord.Lat,
				Longitude: coord.Lon,
			}
		}

		break
	}

	return page, nil
}

// ValidateParams validates the Wikipedia parameters
func (wt *WikipediaTool) ValidateParams(params map[string]interface{}) error {
	if err := wt.BaseTool.ValidateParams(params); err != nil {
		return err
	}

	query := params["query"].(string)
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("query cannot be empty")
	}

	if l, exists := params["language"]; exists {
		if lStr, ok := l.(string); ok {
			if len(lStr) < 2 || len(lStr) > 5 {
				return fmt.Errorf("invalid language code: %s", lStr)
			}
		}
	}

	if lim, exists := params["limit"]; exists {
		var limit int
		if limInt, ok := lim.(int); ok {
			limit = limInt
		} else if limFloat, ok := lim.(float64); ok {
			limit = int(limFloat)
		} else {
			return fmt.Errorf("limit must be an integer")
		}

		if limit < 1 || limit > 20 {
			return fmt.Errorf("limit must be between 1 and 20")
		}
	}

	return nil
}
