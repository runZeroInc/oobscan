package report

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var advisoryStateRow = regexp.MustCompile(`^\|\s*[1-5]\s*\|\s*([^|]+?)\s*\|[^|]*\|\s*([0-9]+)\s*\|$`)

var advisoryRisks = map[string]int{
	"CRITICAL": 5,
	"HIGH":     4,
	"MEDIUM":   3,
	"LOW":      2,
	"INFO":     1,
}

func LoadAdvisoryInventory(root string) (AdvisoryView, error) {
	view := AdvisoryView{}
	riskCounts := newCounter()
	surfaceCounts := newCounter()
	vendorCounts := newCounter()
	vendors := map[string]struct{}{}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".md" {
			return nil
		}
		if entry.Name() == "README.md" || strings.HasPrefix(entry.Name(), "_") {
			return nil
		}
		item, ok, err := parseAdvisoryFile(path)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}

		view.Total++
		riskCounts.add(item.Risk)
		surfaceCounts.add(item.Surface)
		vendorCounts.add(item.Vendor)
		vendors[item.Vendor] = struct{}{}
		if protocolAdvisory(item) {
			view.Highlights = append(view.Highlights, item)
		}
		return nil
	})
	if err != nil {
		return AdvisoryView{}, fmt.Errorf("read advisory inventory: %w", err)
	}
	if view.Total == 0 {
		return AdvisoryView{}, fmt.Errorf("no advisory files found under %s", root)
	}

	view.Vendors = len(vendors)
	view.Risks = riskCounts.top(0)
	view.Surfaces = surfaceCounts.top(0)
	view.ByVendor = vendorCounts.top(0)
	view.States, err = loadAdvisoryStates(filepath.Join(root, "README.md"))
	if err != nil {
		return AdvisoryView{}, err
	}

	sort.Slice(view.Highlights, func(i, j int) bool {
		left, right := view.Highlights[i], view.Highlights[j]
		if advisoryRisks[left.Risk] != advisoryRisks[right.Risk] {
			return advisoryRisks[left.Risk] > advisoryRisks[right.Risk]
		}
		if left.Surface != right.Surface {
			return left.Surface == "UNAUTH"
		}
		return left.ID < right.ID
	})
	if len(view.Highlights) > 8 {
		view.Highlights = view.Highlights[:8]
	}
	return view, nil
}

func parseAdvisoryFile(path string) (AdvisoryItem, bool, error) {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	parts := strings.Split(base, "-")
	riskAt := -1
	for i := 1; i < len(parts); i++ {
		if _, ok := advisoryRisks[parts[i]]; ok {
			riskAt = i
			break
		}
	}
	if riskAt < 1 || riskAt+2 >= len(parts) {
		return AdvisoryItem{}, false, nil
	}

	title, err := advisoryTitle(path)
	if err != nil {
		return AdvisoryItem{}, false, err
	}
	vendor := strings.ToUpper(filepath.Base(filepath.Dir(path)))
	return AdvisoryItem{
		ID:        strings.Join(parts[:riskAt], "-"),
		Vendor:    vendor,
		Risk:      parts[riskAt],
		Surface:   parts[riskAt+1],
		Component: parts[len(parts)-1],
		Title:     title,
	}, true, nil
}

func advisoryTitle(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", nil
	}
	line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "#"))
	if _, title, ok := strings.Cut(line, " - "); ok {
		return strings.TrimSpace(title), nil
	}
	return line, nil
}

func protocolAdvisory(item AdvisoryItem) bool {
	component := strings.ToUpper(item.Component)
	title := strings.ToUpper(item.Title)
	return component == "IPMI" || component == "RAKP" ||
		strings.Contains(title, "IPMI") || strings.Contains(title, "RAKP") || strings.Contains(title, "RMCP+")
}

func loadAdvisoryStates(path string) ([]Pair, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read advisory state summary: %w", err)
	}
	defer f.Close()

	var states []Pair
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		match := advisoryStateRow.FindStringSubmatch(scanner.Text())
		if len(match) != 3 {
			continue
		}
		count, err := strconv.Atoi(match[2])
		if err != nil {
			return nil, fmt.Errorf("parse advisory state count %q: %w", match[2], err)
		}
		if count > 0 {
			states = append(states, Pair{Value: strings.TrimSpace(match[1]), Count: count})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read advisory state summary: %w", err)
	}
	return states, nil
}
