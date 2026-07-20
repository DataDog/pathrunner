package resources

import (
	"fmt"
	"sort"
	"strings"
)

// normalizeSource maps internal source strings to display labels.
func normalizeSource(source string) string {
	switch source {
	case "discover":
		return "pathrunner"
	case "", "cloudfox":
		return "cloudfox"
	default:
		return source
	}
}

// FormatResourceTable formats resources as table rows for display.
// Returns headers and rows suitable for ui.Table.
func FormatResourceTable(resources []Resource) ([]string, [][]string) {
	headers := []string{"Source", "Service", "ARN"}

	sorted := make([]Resource, len(resources))
	copy(sorted, resources)
	sort.Slice(sorted, func(i, j int) bool {
		ai, aj := sorted[i].ARN, sorted[j].ARN
		if ai == "" {
			ai = sorted[i].Name
		}
		if aj == "" {
			aj = sorted[j].Name
		}
		return ai < aj
	})

	rows := make([][]string, 0, len(sorted))
	for _, r := range sorted {
		arn := r.ARN
		if arn == "" {
			arn = r.Name
		}
		rows = append(rows, []string{
			normalizeSource(r.Source),
			r.Service,
			arn,
		})
	}

	return headers, rows
}

// FormatResourceTableWide formats resources with type and name columns for wider display.
func FormatResourceTableWide(resources []Resource) ([]string, [][]string) {
	headers := []string{"Source", "Service", "Type", "Name", "ARN"}

	sorted := make([]Resource, len(resources))
	copy(sorted, resources)
	sort.Slice(sorted, func(i, j int) bool {
		ai, aj := sorted[i].ARN, sorted[j].ARN
		if ai == "" {
			ai = sorted[i].Name
		}
		if aj == "" {
			aj = sorted[j].Name
		}
		return ai < aj
	})

	rows := make([][]string, 0, len(sorted))
	for _, r := range sorted {
		rows = append(rows, []string{
			normalizeSource(r.Source),
			r.Service,
			r.ResourceType,
			r.Name,
			r.ARN,
		})
	}

	return headers, rows
}

// FormatSummaryTable formats resource summaries as a pivot table.
// Rows = services, columns = regions. Returns headers and rows for ui.Table.
func FormatSummaryTable(summaries []ResourceSummary) ([]string, [][]string) {
	if len(summaries) == 0 {
		return nil, nil
	}

	// Collect unique services and regions
	serviceSet := make(map[string]bool)
	regionSet := make(map[string]bool)
	countMap := make(map[string]int) // "service:region" -> count

	for _, s := range summaries {
		serviceSet[s.Service] = true
		regionSet[s.Region] = true
		countMap[s.Service+":"+s.Region] = s.Count
	}

	// Sort services and regions
	var services []string
	for s := range serviceSet {
		services = append(services, s)
	}
	sort.Strings(services)

	var regions []string
	for r := range regionSet {
		regions = append(regions, r)
	}
	sort.Strings(regions)

	// Build headers: "Service" + each region
	headers := make([]string, 0, len(regions)+2)
	headers = append(headers, "Service")
	headers = append(headers, regions...)
	headers = append(headers, "Total")

	// Build rows
	rows := make([][]string, 0, len(services)+1)
	regionTotals := make([]int, len(regions))
	grandTotal := 0

	for _, service := range services {
		row := make([]string, 0, len(regions)+2)
		row = append(row, service)
		serviceTotal := 0
		for i, region := range regions {
			count := countMap[service+":"+region]
			if count > 0 {
				row = append(row, fmt.Sprintf("%d", count))
				serviceTotal += count
				regionTotals[i] += count
			} else {
				row = append(row, "-")
			}
		}
		row = append(row, fmt.Sprintf("%d", serviceTotal))
		grandTotal += serviceTotal
		rows = append(rows, row)
	}

	// Add totals row
	totalsRow := make([]string, 0, len(regions)+2)
	totalsRow = append(totalsRow, "Total")
	for _, total := range regionTotals {
		if total > 0 {
			totalsRow = append(totalsRow, fmt.Sprintf("%d", total))
		} else {
			totalsRow = append(totalsRow, "-")
		}
	}
	totalsRow = append(totalsRow, fmt.Sprintf("%d", grandTotal))
	rows = append(rows, totalsRow)

	return headers, rows
}

// FormatStatusReport formats import status for display.
func FormatStatusReport(statuses []ImportStatus) string {
	if len(statuses) == 0 {
		return "No resources imported. Use 'cloudfox import' to import cloudfox output data."
	}

	var sb strings.Builder

	for _, status := range statuses {
		sb.WriteString(fmt.Sprintf("Account: %s\n", status.AccountID))
		sb.WriteString(fmt.Sprintf("  Resources: %d total\n", status.ResourceCount))

		// Service breakdown
		if len(status.ServiceCounts) > 0 {
			var services []string
			for s := range status.ServiceCounts {
				services = append(services, s)
			}
			sort.Strings(services)

			sb.WriteString("  By service: ")
			parts := make([]string, 0, len(services))
			for _, s := range services {
				parts = append(parts, fmt.Sprintf("%s(%d)", s, status.ServiceCounts[s]))
			}
			sb.WriteString(strings.Join(parts, ", "))
			sb.WriteString("\n")
		}

		// Import history
		sb.WriteString(fmt.Sprintf("  Imports: %d\n", len(status.Imports)))
		for i, imp := range status.Imports {
			sourceType := imp.SourceType
			if sourceType == "" {
				sourceType = "cloudfox"
			}
			switch sourceType {
			case "discover":
				sb.WriteString(fmt.Sprintf("    %d. [discover] %s at=%s\n",
					i+1, imp.SourceInfo,
					imp.ImportedAt.Format("2006-01-02 15:04:05")))
			default:
				profile := imp.Profile
				if profile == "" {
					profile = "unknown"
				}
				sb.WriteString(fmt.Sprintf("    %d. [cloudfox] profile=%s dir=%s at=%s files=%d\n",
					i+1, profile, imp.SourceDir,
					imp.ImportedAt.Format("2006-01-02 15:04:05"),
					len(imp.FilesParsed)))
			}
		}
	}

	return sb.String()
}
