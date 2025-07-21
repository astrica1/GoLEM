// Package tools provides the filesystem tool implementation.
package tools

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/astrica1/GoLEM/pkg/golem"
)

type FileSystemTool struct {
	*BaseTool
	allowedPaths []string
	restrictive  bool
}

type FileInfo struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	IsDirectory bool      `json:"is_directory"`
	ModTime     time.Time `json:"mod_time"`
	Permissions string    `json:"permissions"`
	Owner       string    `json:"owner,omitempty"`
	Group       string    `json:"group,omitempty"`
}

type DirectoryListing struct {
	Path        string     `json:"path"`
	Files       []FileInfo `json:"files"`
	Directories []FileInfo `json:"directories"`
	TotalFiles  int        `json:"total_files"`
	TotalSize   int64      `json:"total_size"`
}

type FileContent struct {
	Path     string `json:"path"`
	Content  string `json:"content"`
	Size     int64  `json:"size"`
	MimeType string `json:"mime_type,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type FileSearchResult struct {
	Query   string     `json:"query"`
	Results []FileInfo `json:"results"`
	Count   int        `json:"count"`
}

// NewFileSystemTool creates a new filesystem tool
func NewFileSystemTool() *FileSystemTool {
	schema := golem.ToolSchema{
		Type:        "object",
		Description: "Performs file system operations like reading, writing, listing directories, and searching files",
		Properties: map[string]golem.ToolSchemaProperty{
			"action": {
				Type:        "string",
				Description: "Action to perform",
				Enum:        []string{"read", "write", "list", "search", "stat", "exists", "mkdir", "delete", "copy", "move"},
			},
			"path": {
				Type:        "string",
				Description: "File or directory path",
			},
			"content": {
				Type:        "string",
				Description: "Content to write (for write action)",
			},
			"destination": {
				Type:        "string",
				Description: "Destination path (for copy/move actions)",
			},
			"pattern": {
				Type:        "string",
				Description: "Search pattern or glob pattern",
			},
			"recursive": {
				Type:        "boolean",
				Description: "Perform recursive operation (default: false)",
				Default:     false,
			},
			"max_size": {
				Type:        "integer",
				Description: "Maximum file size to read in bytes (default: 1MB)",
				Default:     1048576,
			},
			"encoding": {
				Type:        "string",
				Description: "Text encoding for read/write operations (default: utf-8)",
				Default:     "utf-8",
			},
			"create_dirs": {
				Type:        "boolean",
				Description: "Create parent directories if they don't exist (default: false)",
				Default:     false,
			},
		},
		Required: []string{"action", "path"},
	}

	return &FileSystemTool{
		BaseTool: NewBaseTool(
			"filesystem",
			"Provides safe file system operations including reading, writing, listing directories, searching files, and basic file management",
			schema,
		),
		allowedPaths: []string{},
		restrictive:  false,
	}
}

// SetAllowedPaths sets the allowed paths for file operations (security feature)
func (fst *FileSystemTool) SetAllowedPaths(paths []string) {
	fst.allowedPaths = paths
	fst.restrictive = len(paths) > 0
}

// Execute performs the file system operation
func (fst *FileSystemTool) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	if err := fst.ValidateParams(params); err != nil {
		return nil, err
	}

	action := params["action"].(string)
	path := params["path"].(string)

	if err := fst.checkPathPermission(path); err != nil {
		return nil, err
	}

	switch action {
	case "read":
		return fst.readFile(ctx, params)
	case "write":
		return fst.writeFile(ctx, params)
	case "list":
		return fst.listDirectory(ctx, params)
	case "search":
		return fst.searchFiles(ctx, params)
	case "stat":
		return fst.getFileInfo(ctx, path)
	case "exists":
		return fst.fileExists(ctx, path)
	case "mkdir":
		return fst.createDirectory(ctx, params)
	case "delete":
		return fst.deleteFile(ctx, params)
	case "copy":
		return fst.copyFile(ctx, params)
	case "move":
		return fst.moveFile(ctx, params)
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
}

// readFile reads a file's content
func (fst *FileSystemTool) readFile(ctx context.Context, params map[string]interface{}) (*FileContent, error) {
	path := params["path"].(string)
	maxSize := int64(1048576)
	encoding := "utf-8"

	if ms, exists := params["max_size"]; exists {
		if msInt, ok := ms.(int); ok {
			maxSize = int64(msInt)
		} else if msFloat, ok := ms.(float64); ok {
			maxSize = int64(msFloat)
		}
	}

	if enc, exists := params["encoding"]; exists {
		if encStr, ok := enc.(string); ok {
			encoding = encStr
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a file")
	}

	if info.Size() > maxSize {
		return nil, fmt.Errorf("file size (%d bytes) exceeds maximum allowed size (%d bytes)", info.Size(), maxSize)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	mimeType := fst.detectMimeType(path)

	return &FileContent{
		Path:     path,
		Content:  string(content),
		Size:     info.Size(),
		MimeType: mimeType,
		Encoding: encoding,
	}, nil
}

// writeFile writes content to a file
func (fst *FileSystemTool) writeFile(ctx context.Context, params map[string]interface{}) (*FileInfo, error) {
	path := params["path"].(string)
	content, exists := params["content"].(string)
	if !exists {
		return nil, fmt.Errorf("content parameter is required for write action")
	}

	createDirs := false
	if cd, exists := params["create_dirs"]; exists {
		if cdBool, ok := cd.(bool); ok {
			createDirs = cdBool
		}
	}

	if createDirs {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create parent directories: %w", err)
		}
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	return fst.getFileInfo(ctx, path)
}

// listDirectory lists directory contents
func (fst *FileSystemTool) listDirectory(ctx context.Context, params map[string]interface{}) (*DirectoryListing, error) {
	path := params["path"].(string)
	recursive := false

	if r, exists := params["recursive"]; exists {
		if rBool, ok := r.(bool); ok {
			recursive = rBool
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory")
	}

	listing := &DirectoryListing{
		Path:        path,
		Files:       []FileInfo{},
		Directories: []FileInfo{},
	}

	if recursive {
		err = fst.walkDirectory(path, listing)
	} else {
		err = fst.listSingleDirectory(path, listing)
	}

	if err != nil {
		return nil, err
	}

	listing.TotalFiles = len(listing.Files) + len(listing.Directories)

	return listing, nil
}

// listSingleDirectory lists a single directory
func (fst *FileSystemTool) listSingleDirectory(path string, listing *DirectoryListing) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		fullPath := filepath.Join(path, entry.Name())

		if err := fst.checkPathPermission(fullPath); err != nil {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		fileInfo := FileInfo{
			Name:        entry.Name(),
			Path:        fullPath,
			Size:        info.Size(),
			IsDirectory: info.IsDir(),
			ModTime:     info.ModTime(),
			Permissions: info.Mode().String(),
		}

		if info.IsDir() {
			listing.Directories = append(listing.Directories, fileInfo)
		} else {
			listing.Files = append(listing.Files, fileInfo)
			listing.TotalSize += info.Size()
		}
	}

	return nil
}

// walkDirectory recursively walks a directory
func (fst *FileSystemTool) walkDirectory(path string, listing *DirectoryListing) error {
	return filepath.WalkDir(path, func(fullPath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if err := fst.checkPathPermission(fullPath); err != nil {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if fullPath == path {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return nil
		}

		fileInfo := FileInfo{
			Name:        filepath.Base(fullPath),
			Path:        fullPath,
			Size:        info.Size(),
			IsDirectory: info.IsDir(),
			ModTime:     info.ModTime(),
			Permissions: info.Mode().String(),
		}

		if info.IsDir() {
			listing.Directories = append(listing.Directories, fileInfo)
		} else {
			listing.Files = append(listing.Files, fileInfo)
			listing.TotalSize += info.Size()
		}

		return nil
	})
}

// searchFiles searches for files matching a pattern
func (fst *FileSystemTool) searchFiles(ctx context.Context, params map[string]interface{}) (*FileSearchResult, error) {
	path := params["path"].(string)
	pattern, exists := params["pattern"].(string)
	if !exists {
		return nil, fmt.Errorf("pattern parameter is required for search action")
	}

	recursive := true
	if r, exists := params["recursive"]; exists {
		if rBool, ok := r.(bool); ok {
			recursive = rBool
		}
	}

	results := []FileInfo{}

	searchFunc := func(fullPath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if err := fst.checkPathPermission(fullPath); err != nil {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if entry.IsDir() {
			return nil
		}

		matched, err := filepath.Match(pattern, filepath.Base(fullPath))
		if err != nil {
			return nil
		}

		if matched {
			info, err := entry.Info()
			if err != nil {
				return nil
			}

			results = append(results, FileInfo{
				Name:        filepath.Base(fullPath),
				Path:        fullPath,
				Size:        info.Size(),
				IsDirectory: false,
				ModTime:     info.ModTime(),
				Permissions: info.Mode().String(),
			})
		}

		return nil
	}

	if recursive {
		filepath.WalkDir(path, searchFunc)
	} else {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}

		for _, entry := range entries {
			fullPath := filepath.Join(path, entry.Name())
			searchFunc(fullPath, entry, nil)
		}
	}

	return &FileSearchResult{
		Query:   pattern,
		Results: results,
		Count:   len(results),
	}, nil
}

// getFileInfo gets information about a file or directory
func (fst *FileSystemTool) getFileInfo(ctx context.Context, path string) (*FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	return &FileInfo{
		Name:        filepath.Base(path),
		Path:        path,
		Size:        info.Size(),
		IsDirectory: info.IsDir(),
		ModTime:     info.ModTime(),
		Permissions: info.Mode().String(),
	}, nil
}

// fileExists checks if a file or directory exists
func (fst *FileSystemTool) fileExists(ctx context.Context, path string) (map[string]interface{}, error) {
	_, err := os.Stat(path)
	exists := !os.IsNotExist(err)

	return map[string]interface{}{
		"path":   path,
		"exists": exists,
	}, nil
}

// createDirectory creates a directory
func (fst *FileSystemTool) createDirectory(ctx context.Context, params map[string]interface{}) (*FileInfo, error) {
	path := params["path"].(string)
	recursive := false

	if r, exists := params["recursive"]; exists {
		if rBool, ok := r.(bool); ok {
			recursive = rBool
		}
	}

	var err error
	if recursive {
		err = os.MkdirAll(path, 0755)
	} else {
		err = os.Mkdir(path, 0755)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	return fst.getFileInfo(ctx, path)
}

// deleteFile deletes a file or directory
func (fst *FileSystemTool) deleteFile(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	path := params["path"].(string)
	recursive := false

	if r, exists := params["recursive"]; exists {
		if rBool, ok := r.(bool); ok {
			recursive = rBool
		}
	}

	var err error
	if recursive {
		err = os.RemoveAll(path)
	} else {
		err = os.Remove(path)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to delete: %w", err)
	}

	return map[string]interface{}{
		"path":    path,
		"deleted": true,
	}, nil
}

// copyFile copies a file
func (fst *FileSystemTool) copyFile(ctx context.Context, params map[string]interface{}) (*FileInfo, error) {
	srcPath := params["path"].(string)
	dstPath, exists := params["destination"].(string)
	if !exists {
		return nil, fmt.Errorf("destination parameter is required for copy action")
	}

	if err := fst.checkPathPermission(dstPath); err != nil {
		return nil, err
	}

	createDirs := false
	if cd, exists := params["create_dirs"]; exists {
		if cdBool, ok := cd.(bool); ok {
			createDirs = cdBool
		}
	}

	if createDirs {
		dir := filepath.Dir(dstPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create parent directories: %w", err)
		}
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file content: %w", err)
	}

	srcInfo, err := src.Stat()
	if err == nil {
		dst.Chmod(srcInfo.Mode())
	}

	return fst.getFileInfo(ctx, dstPath)
}

// moveFile moves/renames a file
func (fst *FileSystemTool) moveFile(ctx context.Context, params map[string]interface{}) (*FileInfo, error) {
	srcPath := params["path"].(string)
	dstPath, exists := params["destination"].(string)
	if !exists {
		return nil, fmt.Errorf("destination parameter is required for move action")
	}

	if err := fst.checkPathPermission(dstPath); err != nil {
		return nil, err
	}

	createDirs := false
	if cd, exists := params["create_dirs"]; exists {
		if cdBool, ok := cd.(bool); ok {
			createDirs = cdBool
		}
	}

	if createDirs {
		dir := filepath.Dir(dstPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create parent directories: %w", err)
		}
	}

	if err := os.Rename(srcPath, dstPath); err != nil {
		return nil, fmt.Errorf("failed to move file: %w", err)
	}

	return fst.getFileInfo(ctx, dstPath)
}

// checkPathPermission checks if a path is allowed
func (fst *FileSystemTool) checkPathPermission(path string) error {
	if !fst.restrictive {
		return nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	for _, allowedPath := range fst.allowedPaths {
		absAllowed, err := filepath.Abs(allowedPath)
		if err != nil {
			continue
		}

		if strings.HasPrefix(absPath, absAllowed) {
			return nil
		}
	}

	return fmt.Errorf("access denied: path %s is not in allowed paths", path)
}

// detectMimeType detects MIME type based on file extension
func (fst *FileSystemTool) detectMimeType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".txt", ".log":
		return "text/plain"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".html", ".htm":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".go":
		return "text/x-go"
	case ".py":
		return "text/x-python"
	case ".java":
		return "text/x-java"
	case ".c":
		return "text/x-c"
	case ".cpp", ".cc", ".cxx":
		return "text/x-c++"
	case ".md":
		return "text/markdown"
	case ".yml", ".yaml":
		return "application/x-yaml"
	case ".toml":
		return "application/toml"
	case ".csv":
		return "text/csv"
	case ".pdf":
		return "application/pdf"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".zip":
		return "application/zip"
	case ".tar":
		return "application/x-tar"
	case ".gz":
		return "application/gzip"
	default:
		return "application/octet-stream"
	}
}

// ValidateParams validates the filesystem parameters
func (fst *FileSystemTool) ValidateParams(params map[string]interface{}) error {
	if err := fst.BaseTool.ValidateParams(params); err != nil {
		return err
	}

	action := params["action"].(string)
	path := params["path"].(string)

	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("path cannot be empty")
	}

	switch action {
	case "write":
		if _, exists := params["content"]; !exists {
			return fmt.Errorf("content parameter is required for write action")
		}
	case "search":
		if _, exists := params["pattern"]; !exists {
			return fmt.Errorf("pattern parameter is required for search action")
		}
	case "copy", "move":
		if _, exists := params["destination"]; !exists {
			return fmt.Errorf("destination parameter is required for %s action", action)
		}
	}

	if strings.Contains(path, "..") {
		return fmt.Errorf("path cannot contain '..' for security reasons")
	}

	return nil
}
