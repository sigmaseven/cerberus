package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type FileCoverage struct {
	Filename string
	Covered  int
	Total    int
}

func main() {
	file, err := os.Open("coverage.out")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening coverage.out: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	fileData := make(map[string]*FileCoverage)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "mode:") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		fileFuncRange := parts[0]
		if !strings.Contains(fileFuncRange, ":") {
			continue
		}

		filename := strings.Split(fileFuncRange, ":")[0]
		if !strings.HasPrefix(filename, "cerberus/storage/") {
			continue
		}

		// Skip subdirectories
		relPath := strings.TrimPrefix(filename, "cerberus/storage/")
		if strings.Contains(relPath, "/") {
			continue
		}

		rangeParts := strings.Split(parts[1], ",")
		if len(rangeParts) < 2 {
			continue
		}

		stmtsPart := strings.Fields(rangeParts[1])
		if len(stmtsPart) < 1 {
			continue
		}

		stmts, err := strconv.Atoi(stmtsPart[0])
		if err != nil {
			continue
		}

		count, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}

		if _, exists := fileData[filename]; !exists {
			fileData[filename] = &FileCoverage{Filename: filename}
		}

		fileData[filename].Total += stmts
		if count > 0 {
			fileData[filename].Covered += stmts
		}
	}

	// Convert to slice and sort
	var files []FileCoverage
	for _, fc := range fileData {
		if fc.Total > 0 {
			files = append(files, *fc)
		}
	}

	sort.Slice(files, func(i, j int) bool {
		pctI := 100.0 * float64(files[i].Covered) / float64(files[i].Total)
		pctJ := 100.0 * float64(files[j].Covered) / float64(files[j].Total)
		return pctI < pctJ
	})

	fmt.Printf("%-50s %10s\n", "File", "Coverage")
	fmt.Println(strings.Repeat("=", 65))

	for _, fc := range files {
		pct := 100.0 * float64(fc.Covered) / float64(fc.Total)
		fmt.Printf("%-50s %9.1f%%\n", fc.Filename, pct)
	}
}
