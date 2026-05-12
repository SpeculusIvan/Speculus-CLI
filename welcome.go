package main

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

const version = "v1.0.0"

const speculusLogo = ` 
                                                                                                                      
███████╗██████╗ ███████╗ ██████╗██╗   ██╗██╗     ██╗   ██╗███████╗       ██████╗██╗     ██╗
██╔════╝██╔══██╗██╔════╝██╔════╝██║   ██║██║     ██║   ██║██╔════╝      ██╔════╝██║     ██║
███████╗██████╔╝█████╗  ██║     ██║   ██║██║     ██║   ██║███████╗█████╗██║     ██║     ██║
╚════██║██╔═══╝ ██╔══╝  ██║     ██║   ██║██║     ██║   ██║╚════██║╚════╝██║     ██║     ██║
███████║██║     ███████╗╚██████╗╚██████╔╝███████╗╚██████╔╝███████║      ╚██████╗███████╗██║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝       ╚═════╝╚══════╝╚═╝
                               `
const speculusArt = speculusLogo

var (
	artDarkOrange  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff7208"))
	artLightOrange = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff8520"))
)

func colorizeArtLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ' ':
			b.WriteRune(r)
		case '█':
			b.WriteString(artDarkOrange.Render(string(r)))
		default:
			b.WriteString(artLightOrange.Render(string(r)))
		}
	}
	return b.String()
}

var (
	welcomeAccent = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff7208"))
	welcomeTitle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff7208")).Bold(true)
	welcomeLabel  = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Bold(true)
	welcomeOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	welcomeWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffd700"))
	welcomeBad    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	welcomeMuted  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	welcomeText   = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
)

func renderWelcome(token string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	healthErr := FetchHealth(client)
	quota, quotaErr := FetchQuota(client, token)
	return renderWelcomeFromCache(token, healthErr, quota, quotaErr)
}

func renderWelcomeFromCache(token string, healthErr error, quota Quota, quotaErr error) string {
	return renderHeader(token, healthErr, quota, quotaErr)
}

// renderHeader builds the top section: ASCII art followed by title + API
// status + quota stacked underneath.
func renderHeader(token string, healthErr error, quota Quota, quotaErr error) string {
	var b strings.Builder
	for _, l := range strings.Split(speculusLogo, "\n") {
		if strings.TrimSpace(l) == "" {
			b.WriteString(l + "\n")
			continue
		}
		b.WriteString(colorizeArtLine(l) + "\n")
	}
	b.WriteString("\n")

	b.WriteString(" " + welcomeTitle.Render("Speculus CLI ") + welcomeMuted.Render(version) + "\n")

	if healthErr == nil {
		b.WriteString(" Status: " + welcomeOK.Render("✓ API online") + "\n")
	} else {
		b.WriteString(" Status: " + welcomeBad.Render("✗ API unreachable") + "\n")
	}

	switch {
	case token == "":
		b.WriteString(" " + welcomeMuted.Render("API key not configured"))
	case quotaErr != nil:
		b.WriteString(" " + welcomeMuted.Render("Quota unavailable"))
	default:
		count := fmt.Sprintf("%s / %s",
			humanInt(quota.Remaining), humanInt(quota.Limit))
		if quota.InGrace {
			count += " · in grace"
		}
		colored := quotaStyle(quota.Remaining, quota.Limit, quota.InGrace).Render(count)
		b.WriteString(" " + welcomeText.Render("Quota: ") + colored)
	}
	b.WriteString("\n " + welcomeText.Render("Platform: ") +
		welcomeText.Render(prettyOS()) +
		welcomeMuted.Render(fmt.Sprintf(" · %s/%s", runtime.GOOS, runtime.GOARCH)))
	return b.String()
}

func prettyOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS"
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	case "freebsd":
		return "FreeBSD"
	case "openbsd":
		return "OpenBSD"
	case "netbsd":
		return "NetBSD"
	default:
		return runtime.GOOS
	}
}

// quotaStyle returns the color tier for a given quota state.
//   - grace mode → red
//   - <25% remaining → red
//   - <50% remaining → yellow
//   - else → green
func quotaStyle(remaining, limit int, inGrace bool) lipgloss.Style {
	if inGrace {
		return welcomeBad
	}
	if limit <= 0 {
		return welcomeMuted
	}
	pct := float64(remaining) / float64(limit)
	switch {
	case pct < 0.25:
		return welcomeBad
	case pct < 0.50:
		return welcomeWarn
	default:
		return welcomeOK
	}
}

func padTo(lines []string, width int) {
	for i, l := range lines {
		pad := width - lipgloss.Width(l)
		if pad > 0 {
			lines[i] = l + strings.Repeat(" ", pad)
		}
	}
}

func humanInt(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func boxWithTitle(title, content string) string {
	lines := strings.Split(content, "\n")
	width := 0
	for _, l := range lines {
		if w := lipgloss.Width(l); w > width {
			width = w
		}
	}
	innerWidth := width + 2

	titleRendered := welcomeTitle.Render(title)
	titleVisible := lipgloss.Width(titleRendered)
	dashes := innerWidth - titleVisible - 5
	if dashes < 1 {
		dashes = 1
	}
	top := welcomeAccent.Render("╭─── ") + titleRendered + welcomeAccent.Render(" "+strings.Repeat("─", dashes)+"╮")
	bottom := welcomeAccent.Render("╰" + strings.Repeat("─", innerWidth) + "╯")

	leftBar := welcomeAccent.Render("│ ")
	rightBar := welcomeAccent.Render(" │")

	var b strings.Builder
	b.WriteString(top + "\n")
	for _, l := range lines {
		pad := width - lipgloss.Width(l)
		b.WriteString(leftBar + l + strings.Repeat(" ", pad) + rightBar + "\n")
	}
	b.WriteString(bottom)
	return b.String()
}
