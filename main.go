package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/joho/godotenv"
)

func renderHelp() string {
	heading := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff7208")).Bold(true).Underline(true)
	cmd := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff8520")).Bold(true)
	desc := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	title := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff7208")).Bold(true)

	const col = 36
	row := func(left, right string, rightStyle lipgloss.Style) string {
		rendered := cmd.Render(left)
		pad := col - lipgloss.Width(rendered)
		if pad < 1 {
			pad = 1
		}
		return "  " + rendered + strings.Repeat(" ", pad) + rightStyle.Render(right) + "\n"
	}

	var b strings.Builder
	b.WriteString(title.Render("Speculus CLI ") + muted.Render("v1.0.0") + "\n")
	b.WriteString(muted.Render("IP threat intelligence at the command line.") + "\n\n")

	b.WriteString(heading.Render("Usage") + "\n")
	b.WriteString(row("speculus-cli", "Launch the guided interactive shell", desc))
	b.WriteString(row("speculus-cli <input_file>", "Bulk-query IPs and write CSV", desc))
	b.WriteString(row("speculus-cli <input_file> <out>", "Same, with a custom output path", desc))
	b.WriteString(row("speculus-cli -s, --setup", "Configure your API key (.env)", desc))
	b.WriteString(row("speculus-cli -h, --help", "Show this help", desc))
	b.WriteString("\n")

	b.WriteString(heading.Render("Setup") + "\n")
	b.WriteString("  " + desc.Render("Drop a ") + cmd.Render("SPECULUS_TOKEN") +
		desc.Render(" into a .env file in the current directory,") + "\n")
	b.WriteString("  " + desc.Render("export it as an environment variable, or run with ") +
		cmd.Render("--setup") + desc.Render(" to be") + "\n")
	b.WriteString("  " + desc.Render("walked through it interactively.") + "\n\n")

	b.WriteString(heading.Render("Examples") + "\n")
	b.WriteString(row("speculus-cli", "# interactive menu", muted))
	b.WriteString(row("speculus-cli ips.txt", "# writes results_YYYY-MM-DD.csv", muted))
	b.WriteString(row("speculus-cli ips.txt out.csv", "# writes to out.csv", muted))
	b.WriteString(row("speculus-cli --setup", "# store your API key in .env", muted))
	return b.String()
}

func main() {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		log.Fatalf("load .env: %v", err)
	}

	app := newApp()
	args := os.Args[1:]
	for len(args) > 0 {
		switch args[0] {
		case "-h", "--help":
			fmt.Print(renderHelp())
			return
		case "-s", "--setup":
			app.forceSetup = true
			args = args[1:]
		default:
			if app.initialInput == "" {
				app.initialInput = args[0]
			} else if app.initialOutput == "" {
				app.initialOutput = args[0]
			} else {
				fmt.Fprintf(os.Stderr, "Unexpected argument: %s\n\n", args[0])
				fmt.Fprint(os.Stderr, renderHelp())
				os.Exit(2)
			}
			args = args[1:]
		}
	}

	prog := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := prog.Run(); err != nil {
		log.Fatalf("tui: %v", err)
	}
}
