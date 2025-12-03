package selector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	csclient "github.com/xenov-x/csrest"
)

// BeaconFilter represents filtering criteria for beacons
type BeaconFilter struct {
	User       string // Filter by username (partial match)
	Hostname   string // Filter by hostname (partial match)
	AdminOnly  bool   // Only show admin beacons
	AliveOnly  bool   // Only show alive beacons
	MinutesAgo int    // Only show beacons that checked in within this many minutes (0 = no filter)
}

// ListBeacons displays a non-interactive table of beacons and exits
func ListBeacons(ctx context.Context, client *csclient.Client, filter *BeaconFilter) error {
	// Fetch beacons
	allBeacons, err := client.ListBeacons(ctx)
	if err != nil {
		return fmt.Errorf("failed to list beacons: %w", err)
	}

	// Apply filters
	beacons := filterBeacons(allBeacons, filter)

	if len(beacons) == 0 {
		if filter != nil {
			return fmt.Errorf("no beacons match the filter criteria")
		}
		return fmt.Errorf("no beacons available")
	}

	// Sort beacons by most recent check-in first
	sort.Slice(beacons, func(i, j int) bool {
		return beacons[i].LastCheckinTime.After(beacons[j].LastCheckinTime)
	})

	// Display filter info if applied
	if filter != nil && (filter.User != "" || filter.Hostname != "" || filter.AdminOnly || filter.AliveOnly || filter.MinutesAgo > 0) {
		fmt.Println("\n🔍 Active Filters:")
		if filter.User != "" {
			fmt.Printf("  - User contains: %s\n", filter.User)
		}
		if filter.Hostname != "" {
			fmt.Printf("  - Hostname contains: %s\n", filter.Hostname)
		}
		if filter.AdminOnly {
			fmt.Println("  - Admin only: yes")
		}
		if filter.AliveOnly {
			fmt.Println("  - Alive only: yes")
		}
		if filter.MinutesAgo > 0 {
			fmt.Printf("  - Last check-in within: %d minutes\n", filter.MinutesAgo)
		}
		fmt.Printf("  - Results: %d/%d beacons\n", len(beacons), len(allBeacons))
	}

	// Display beacons in a table
	fmt.Println("\nAvailable Beacons:")
	fmt.Println(strings.Repeat("=", 130))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "#\tBeacon ID\tUser\tHostname\tPID\tInternal IP\tLast Check-in\tSleep\tJitter\tAdmin\tAlive")
	fmt.Fprintln(w, strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 20)+"\t"+
		strings.Repeat("-", 15)+"\t"+strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 15)+"\t"+strings.Repeat("-", 20)+"\t"+
		strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 6)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 5))

	for i, beacon := range beacons {
		adminStatus := ""
		if beacon.IsAdmin {
			adminStatus = "✓"
		}

		aliveStatus := ""
		if beacon.Alive {
			aliveStatus = "✓"
		}

		sleepInfo := fmt.Sprintf("%ds", beacon.Sleep.Sleep)
		jitterInfo := fmt.Sprintf("%d%%", beacon.Sleep.Jitter)

		// Format last checkin time
		timeAgo := formatTimeAgo(time.Since(beacon.LastCheckinTime))

		// Truncate long values
		user := truncate(beacon.User, 20)
		hostname := truncate(beacon.Computer, 15)
		bid := truncate(beacon.BID, 10)

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			i+1, bid, user, hostname, beacon.PID, beacon.Internal, timeAgo, sleepInfo, jitterInfo, adminStatus, aliveStatus)
	}
	w.Flush()

	fmt.Println(strings.Repeat("=", 130))
	fmt.Printf("\nTotal: %d beacons\n", len(beacons))

	return nil
}

// SelectBeacon displays an interactive table of beacons and lets the user select one
func SelectBeacon(ctx context.Context, client *csclient.Client) (string, error) {
	return SelectBeaconWithFilter(ctx, client, nil)
}

// SelectBeaconWithFilter displays filtered beacons and lets the user select one
func SelectBeaconWithFilter(ctx context.Context, client *csclient.Client, filter *BeaconFilter) (string, error) {
	// Fetch beacons
	allBeacons, err := client.ListBeacons(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list beacons: %w", err)
	}

	// Apply filters
	beacons := filterBeacons(allBeacons, filter)

	if len(beacons) == 0 {
		if filter != nil {
			return "", fmt.Errorf("no beacons match the filter criteria")
		}
		return "", fmt.Errorf("no beacons available")
	}

	// Sort beacons by most recent check-in first
	sort.Slice(beacons, func(i, j int) bool {
		return beacons[i].LastCheckinTime.After(beacons[j].LastCheckinTime)
	})

	// Display filter info if applied
	if filter != nil && (filter.User != "" || filter.Hostname != "" || filter.AdminOnly || filter.AliveOnly || filter.MinutesAgo > 0) {
		fmt.Println("\n🔍 Active Filters:")
		if filter.User != "" {
			fmt.Printf("  - User contains: %s\n", filter.User)
		}
		if filter.Hostname != "" {
			fmt.Printf("  - Hostname contains: %s\n", filter.Hostname)
		}
		if filter.AdminOnly {
			fmt.Println("  - Admin only: yes")
		}
		if filter.AliveOnly {
			fmt.Println("  - Alive only: yes")
		}
		if filter.MinutesAgo > 0 {
			fmt.Printf("  - Last check-in within: %d minutes\n", filter.MinutesAgo)
		}
		fmt.Printf("  - Results: %d/%d beacons\n", len(beacons), len(allBeacons))
	}

	// Display beacons in a table
	fmt.Println("\nAvailable Beacons:")
	fmt.Println(strings.Repeat("=", 130))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "#\tBeacon ID\tUser\tHostname\tPID\tInternal IP\tLast Check-in\tSleep\tJitter\tAdmin\tAlive")
	fmt.Fprintln(w, strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 20)+"\t"+
		strings.Repeat("-", 15)+"\t"+strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 15)+"\t"+strings.Repeat("-", 20)+"\t"+
		strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 6)+"\t"+strings.Repeat("-", 5)+"\t"+strings.Repeat("-", 5))

	for i, beacon := range beacons {
		adminStatus := ""
		if beacon.IsAdmin {
			adminStatus = "✓"
		}

		aliveStatus := ""
		if beacon.Alive {
			aliveStatus = "✓"
		}

		sleepInfo := fmt.Sprintf("%ds", beacon.Sleep.Sleep)
		jitterInfo := fmt.Sprintf("%d%%", beacon.Sleep.Jitter)

		// Format last checkin time
		timeAgo := formatTimeAgo(time.Since(beacon.LastCheckinTime))

		// Truncate long values
		user := truncate(beacon.User, 20)
		hostname := truncate(beacon.Computer, 15)
		bid := truncate(beacon.BID, 10)

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			i+1, bid, user, hostname, beacon.PID, beacon.Internal, timeAgo, sleepInfo, jitterInfo, adminStatus, aliveStatus)
	}
	w.Flush()

	fmt.Println(strings.Repeat("=", 130))

	// Prompt for selection
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\nSelect beacon number (or 'q' to quit): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}

		input = strings.TrimSpace(input)
		if input == "q" || input == "Q" {
			return "", fmt.Errorf("selection cancelled by user")
		}

		selection, err := strconv.Atoi(input)
		if err != nil || selection < 1 || selection > len(beacons) {
			fmt.Printf("Invalid selection. Please enter a number between 1 and %d.\n", len(beacons))
			continue
		}

		selectedBeacon := beacons[selection-1]
		fmt.Printf("\n✓ Selected beacon: %s (%s@%s)\n\n", selectedBeacon.BID, selectedBeacon.User, selectedBeacon.Computer)
		return selectedBeacon.BID, nil
	}
}

// filterBeacons applies filter criteria to beacon list
func filterBeacons(beacons []csclient.BeaconDto, filter *BeaconFilter) []csclient.BeaconDto {
	if filter == nil {
		return beacons
	}

	var filtered []csclient.BeaconDto
	for _, beacon := range beacons {
		// User filter
		if filter.User != "" && !strings.Contains(strings.ToLower(beacon.User), strings.ToLower(filter.User)) {
			continue
		}

		// Hostname filter
		if filter.Hostname != "" && !strings.Contains(strings.ToLower(beacon.Computer), strings.ToLower(filter.Hostname)) {
			continue
		}

		// Admin filter
		if filter.AdminOnly && !beacon.IsAdmin {
			continue
		}

		// Alive filter
		if filter.AliveOnly && !beacon.Alive {
			continue
		}

		// Time filter
		if filter.MinutesAgo > 0 {
			sinceLastCheckin := time.Since(beacon.LastCheckinTime)
			if sinceLastCheckin > time.Duration(filter.MinutesAgo)*time.Minute {
				continue
			}
		}

		filtered = append(filtered, beacon)
	}

	return filtered
}

// formatTimeAgo formats a duration into a human-readable "time ago" string
func formatTimeAgo(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	} else {
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// truncate truncates a string to a maximum length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-2] + ".."
}

// DisplayBeaconDetails shows detailed information about a selected beacon
func DisplayBeaconDetails(ctx context.Context, client *csclient.Client, bid string) error {
	beacon, err := client.GetBeacon(ctx, bid)
	if err != nil {
		return fmt.Errorf("failed to get beacon details: %w", err)
	}

	fmt.Println("\nBeacon Details:")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Beacon ID:      %s\n", beacon.BID)
	fmt.Printf("User:           %s\n", beacon.User)
	if beacon.Impersonated != "" {
		fmt.Printf("Impersonated:   %s\n", beacon.Impersonated)
	}
	fmt.Printf("Hostname:       %s\n", beacon.Computer)
	fmt.Printf("Internal IP:    %s\n", beacon.Internal)
	fmt.Printf("External IP:    %s\n", beacon.External)
	fmt.Printf("Process:        %s (PID: %d)\n", beacon.Process, beacon.PID)
	fmt.Printf("OS:             %s %s (Build %d)\n", beacon.OS, beacon.Version, beacon.Build)
	fmt.Printf("Architecture:   %s (Beacon: %s)\n", beacon.SystemArch, beacon.BeaconArch)
	fmt.Printf("Admin:          %v\n", beacon.IsAdmin)
	fmt.Printf("Listener:       %s\n", beacon.Listener)
	fmt.Printf("Session Type:   %s\n", beacon.Session)
	fmt.Printf("Sleep:          %ds (Jitter: %d%%)\n", beacon.Sleep.Sleep, beacon.Sleep.Jitter)
	fmt.Printf("Last Check-in:  %s (%s)\n", beacon.LastCheckinTime.Format("2006-01-02 15:04:05"), beacon.LastCheckinFormatted)
	fmt.Printf("Alive:          %v\n", beacon.Alive)
	if beacon.Note != "" {
		fmt.Printf("Note:           %s\n", beacon.Note)
	}
	fmt.Println(strings.Repeat("=", 60))

	return nil
}
