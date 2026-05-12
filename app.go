package main

import (
	"encoding/csv"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type appState int

const (
	stateSetup appState = iota
	stateMenu
	stateFilePicker
	stateNoFilesPrompt
	stateEditor
	stateConfirmRun
	stateFetching
	stateSingleInput
	stateSingleResult
	stateHealthResult
	stateQuotaResult
	stateDone
	stateInfo
)

var (
	promptStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff7208")).Bold(true)
	hintStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
	headingStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff7208")).Bold(true)
	dividerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	statusKeyStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

type menuItem struct {
	label string
	hint  string
	key   string
}

func (i menuItem) Title() string       { return i.label }
func (i menuItem) Description() string { return i.hint }
func (i menuItem) FilterValue() string { return i.label }

type App struct {
	state    appState
	prevState appState

	token     string
	cwd       string
	quota     Quota
	quotaErr  error
	healthErr error

	width, height int

	info string // transient message to show in stateInfo

	apiInput    textinput.Model
	singleInput textinput.Model
	menuList    list.Model
	fileList    list.Model
	yesNoList   list.Model
	editor      textarea.Model
	spinner     spinner.Model

	fetcher    *fetcher
	csvFile    *os.File
	csvWriter  *csv.Writer
	outputFile string

	pendingFile string // file the user just created — confirm to run

	// CLI argument overrides — when set, Init() auto-starts the fetch on
	// initialInput and (if non-empty) writes to initialOutput instead of the
	// dated default.
	initialInput  string
	initialOutput string
	forceSetup    bool // -s/--setup: drop straight into the API-key entry

	single  *Response
	summary *fetchSummary
}

type countByLabel struct {
	label string
	count int
}

type threatEntry struct {
	ip          string
	asn         int
	isp         string
	country     string
	risk        string
	score       uint32
	activity    string
	attribution string
}

type fetchSummary struct {
	completed  int
	failed     int
	outputFile string

	topCountries  []countByLabel
	rareCountries []countByLabel
	topASNs       []countByLabel
	rareASNs      []countByLabel

	vpn       []threatEntry
	proxy     []threatEntry
	malicious []threatEntry
	activity  []threatEntry // IPs with non-empty Activity or Attribution
}

func newApp() *App {
	cwd, _ := os.Getwd()

	api := textinput.New()
	api.Placeholder = "spec_live_..."
	api.CharLimit = 80
	api.Width = 60
	api.Prompt = ""

	si := textinput.New()
	si.Placeholder = "e.g. 8.8.8.8"
	si.CharLimit = 45
	si.Width = 40
	si.Prompt = ""

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("63"))

	menu := buildList([]list.Item{
		menuItem{"Query an IP list", "Bulk lookup from a file", "list"},
		menuItem{"Check a single IP", "One-off lookup", "single"},
		menuItem{"Health check", "Verify the API is reachable", "health"},
		menuItem{"View quota", "Calls remaining this month", "quota"},
		menuItem{"Quit", "Bye!", "quit"},
	})

	ta := textarea.New()
	ta.Placeholder = "Paste IPs, one per line (e.g. 8.8.8.8)"
	ta.SetWidth(60)
	ta.SetHeight(10)
	ta.ShowLineNumbers = true

	return &App{
		cwd:         cwd,
		apiInput:    api,
		singleInput: si,
		menuList:    menu,
		editor:      ta,
		spinner:     sp,
	}
}

func buildList(items []list.Item) list.Model {
	d := list.NewDefaultDelegate()
	hoverOrange := lipgloss.Color("#ffb06b")
	d.Styles.SelectedTitle = d.Styles.SelectedTitle.Foreground(hoverOrange).BorderForeground(hoverOrange)
	d.Styles.SelectedDesc = d.Styles.SelectedDesc.Foreground(hoverOrange).BorderForeground(hoverOrange)
	l := list.New(items, d, 70, 12)
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)
	l.SetShowPagination(false)
	return l
}

func (a *App) Init() tea.Cmd {
	token := os.Getenv("SPECULUS_TOKEN")
	a.token = token
	a.refreshStatus()

	if token == "" || a.forceSetup {
		a.state = stateSetup
		a.apiInput.Focus()
		return tea.Batch(a.spinner.Tick, textinput.Blink)
	}
	a.state = stateMenu

	cmds := []tea.Cmd{a.spinner.Tick}
	if a.initialInput != "" {
		if cmd := a.startFetch(a.initialInput); cmd != nil {
			cmds = append(cmds, cmd)
		}
	}
	return tea.Batch(cmds...)
}

func (a *App) refreshStatus() {
	client := &http.Client{Timeout: 5 * time.Second}
	a.healthErr = FetchHealth(client)
	if a.token != "" {
		a.quota, a.quotaErr = FetchQuota(client, a.token)
	}
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.Type == tea.KeyCtrlC {
		a.closeCSV()
		return a, tea.Quit
	}

	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		a.width = ws.Width
		a.height = ws.Height
		listW := ws.Width - 6
		if listW < 40 {
			listW = 40
		}
		a.menuList.SetSize(listW, 10)
		if len(a.fileList.Items()) > 0 {
			a.fileList.SetSize(listW, 10)
		}
		if len(a.yesNoList.Items()) > 0 {
			a.yesNoList.SetSize(listW, 6)
		}
		w := ws.Width - 6
		if w > 80 {
			w = 80
		}
		a.editor.SetWidth(w)
	}

	var cmds []tea.Cmd
	var spCmd tea.Cmd
	a.spinner, spCmd = a.spinner.Update(msg)
	cmds = append(cmds, spCmd)

	var stateCmd tea.Cmd
	switch a.state {
	case stateSetup:
		stateCmd = a.updateSetup(msg)
	case stateMenu:
		stateCmd = a.updateMenu(msg)
	case stateFilePicker:
		stateCmd = a.updateFilePicker(msg)
	case stateNoFilesPrompt, stateConfirmRun:
		stateCmd = a.updateYesNo(msg)
	case stateEditor:
		stateCmd = a.updateEditor(msg)
	case stateFetching:
		stateCmd = a.updateFetching(msg)
	case stateSingleInput:
		stateCmd = a.updateSingleInput(msg)
	case stateSingleResult, stateHealthResult, stateQuotaResult, stateDone, stateInfo:
		stateCmd = a.updateAcknowledge(msg)
	}
	cmds = append(cmds, stateCmd)
	return a, tea.Batch(cmds...)
}

func (a *App) closeCSV() {
	if a.csvWriter != nil {
		a.csvWriter.Flush()
		a.csvWriter = nil
	}
	if a.csvFile != nil {
		a.csvFile.Close()
		a.csvFile = nil
	}
}

// ---- Setup ---------------------------------------------------------------

func (a *App) updateSetup(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.Type {
		case tea.KeyEnter:
			token := strings.TrimSpace(a.apiInput.Value())
			if token == "" {
				return nil
			}
			if err := writeEnvFile(token); err != nil {
				a.info = "Failed to write .env: " + err.Error()
				a.state = stateInfo
				return nil
			}
			a.token = token
			os.Setenv("SPECULUS_TOKEN", token)
			a.refreshStatus()
			a.state = stateMenu
			return nil
		case tea.KeyEsc:
			return tea.Quit
		}
	}
	var cmd tea.Cmd
	a.apiInput, cmd = a.apiInput.Update(msg)
	return cmd
}

func writeEnvFile(token string) error {
	content := fmt.Sprintf("SPECULUS_TOKEN=%s\n", token)
	return os.WriteFile(".env", []byte(content), 0600)
}

// ---- Menu ----------------------------------------------------------------

func (a *App) updateMenu(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyMsg); ok && k.Type == tea.KeyEnter {
		if it, ok := a.menuList.SelectedItem().(menuItem); ok {
			switch it.key {
			case "list":
				a.enterFilePicker()
				return nil
			case "single":
				a.singleInput.SetValue("")
				a.singleInput.Focus()
				a.state = stateSingleInput
				return textinput.Blink
			case "health":
				a.refreshStatus()
				a.state = stateHealthResult
				return nil
			case "quota":
				a.refreshStatus()
				a.state = stateQuotaResult
				return nil
			case "quit":
				return tea.Quit
			}
		}
	}
	var cmd tea.Cmd
	a.menuList, cmd = a.menuList.Update(msg)
	return cmd
}

// ---- File picker ---------------------------------------------------------

func (a *App) enterFilePicker() {
	files := scanIPFiles(a.cwd)
	if len(files) == 0 {
		a.yesNoList = buildList([]list.Item{
			menuItem{"Yes, open the editor", "Create ips.txt and add IPs", "yes"},
			menuItem{"No, back to menu", "", "no"},
		})
		a.state = stateNoFilesPrompt
		return
	}
	var items []list.Item
	for _, f := range files {
		items = append(items, menuItem{label: f.name, hint: f.summary, key: f.name})
	}
	items = append(items,
		menuItem{"Create a new ips.txt", "Open editor", "__create"},
		menuItem{"Back to menu", "", "__back"},
	)
	a.fileList = buildList(items)
	if a.width > 0 {
		a.fileList.SetSize(a.width-6, 10)
	}
	a.state = stateFilePicker
}

func (a *App) updateFilePicker(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.Type {
		case tea.KeyEnter:
			if it, ok := a.fileList.SelectedItem().(menuItem); ok {
				switch it.key {
				case "__back":
					a.state = stateMenu
				case "__create":
					a.editor.SetValue("")
					a.editor.Focus()
					a.state = stateEditor
				default:
					return a.startFetch(it.key)
				}
			}
			return nil
		case tea.KeyEsc:
			a.state = stateMenu
			return nil
		}
	}
	var cmd tea.Cmd
	a.fileList, cmd = a.fileList.Update(msg)
	return cmd
}

// ---- Yes/No prompt -------------------------------------------------------

func (a *App) updateYesNo(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.Type {
		case tea.KeyEnter:
			if it, ok := a.yesNoList.SelectedItem().(menuItem); ok {
				switch a.state {
				case stateNoFilesPrompt:
					if it.key == "yes" {
						a.editor.SetValue("")
						a.editor.Focus()
						a.state = stateEditor
					} else {
						a.state = stateMenu
					}
				case stateConfirmRun:
					if it.key == "yes" {
						return a.startFetch(a.pendingFile)
					}
					a.state = stateMenu
				}
			}
			return nil
		case tea.KeyEsc:
			a.state = stateMenu
			return nil
		}
	}
	var cmd tea.Cmd
	a.yesNoList, cmd = a.yesNoList.Update(msg)
	return cmd
}

// ---- Editor --------------------------------------------------------------

func (a *App) updateEditor(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.Type {
		case tea.KeyCtrlS:
			content := a.editor.Value()
			if strings.TrimSpace(content) == "" {
				a.info = "Editor is empty — nothing to save."
				return nil
			}
			if err := os.WriteFile("ips.txt", []byte(content), 0644); err != nil {
				a.info = "Failed to write ips.txt: " + err.Error()
				a.state = stateInfo
				return nil
			}
			a.pendingFile = "ips.txt"
			a.yesNoList = buildList([]list.Item{
				menuItem{"Yes, query ips.txt now", "Start the lookup", "yes"},
				menuItem{"No, back to menu", "", "no"},
			})
			a.state = stateConfirmRun
			return nil
		case tea.KeyEsc:
			a.state = stateMenu
			return nil
		}
	}
	var cmd tea.Cmd
	a.editor, cmd = a.editor.Update(msg)
	return cmd
}

// ---- Single IP -----------------------------------------------------------

func (a *App) updateSingleInput(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.Type {
		case tea.KeyEnter:
			ipStr := strings.TrimSpace(a.singleInput.Value())
			ip := net.ParseIP(ipStr)
			if ip == nil {
				a.info = "That doesn't look like a valid IP address."
				return nil
			}
			client := &http.Client{Timeout: 15 * time.Second}
			r, err := FetchSpeculus(client, a.token, ip)
			if err != nil {
				a.info = "Lookup failed: " + err.Error()
				a.state = stateInfo
				return nil
			}
			a.single = &r
			a.state = stateSingleResult
			return nil
		case tea.KeyEsc:
			a.state = stateMenu
			return nil
		}
	}
	var cmd tea.Cmd
	a.singleInput, cmd = a.singleInput.Update(msg)
	return cmd
}

// ---- Fetching ------------------------------------------------------------

func (a *App) startFetch(path string) tea.Cmd {
	ips, err := readIPs(path)
	if err != nil {
		a.info = "Could not read file: " + err.Error()
		a.state = stateInfo
		return nil
	}
	if len(ips) == 0 {
		a.info = "No valid public IPv4 addresses found in " + path
		a.state = stateInfo
		return nil
	}

	outputFile := a.initialOutput
	if outputFile == "" {
		outputFile = fmt.Sprintf("results_%s.csv", time.Now().Format("2006-01-02"))
	}
	a.initialOutput = ""
	out, err := os.Create(outputFile)
	if err != nil {
		a.info = "Could not create CSV: " + err.Error()
		a.state = stateInfo
		return nil
	}
	w := csv.NewWriter(out)
	if err := w.Write(csvHeader); err != nil {
		out.Close()
		a.info = "Could not write CSV header: " + err.Error()
		a.state = stateInfo
		return nil
	}
	a.csvFile = out
	a.csvWriter = w
	a.outputFile = outputFile

	client := &http.Client{Timeout: 15 * time.Second}
	a.fetcher = newFetcher(ips, client, a.token, w, outputFile)
	a.state = stateFetching
	return a.fetcher.Init()
}

func (a *App) updateFetching(msg tea.Msg) tea.Cmd {
	if done, ok := msg.(fetchDoneMsg); ok {
		a.closeCSV()
		a.summary = computeSummary(done.results, done.completed, done.failed, done.outputFile)
		a.refreshStatus()
		a.state = stateDone
		return nil
	}
	if a.fetcher != nil {
		return a.fetcher.Update(msg)
	}
	return nil
}

// ---- Acknowledge (info/result screens) -----------------------------------

func (a *App) updateAcknowledge(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.Type {
		case tea.KeyEnter, tea.KeyEsc, tea.KeySpace:
			a.info = ""
			a.state = stateMenu
		}
	}
	return nil
}

// ---- View ---------------------------------------------------------------

func (a *App) View() string {
	width := a.width
	if width <= 0 {
		width = 120
	}
	if width > 200 {
		width = 200
	}

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(renderHeader(a.token, a.healthErr, a.quota, a.quotaErr))
	b.WriteString("\n\n")

	// Right-aligned tip
	tip := welcomeMuted.Render("? for shortcuts · ctrl+c to quit")
	tipW := lipgloss.Width(tip)
	if width > tipW {
		b.WriteString(strings.Repeat(" ", width-tipW))
	}
	b.WriteString(tip + "\n")

	div := dividerStyle.Render(strings.Repeat("─", width))

	// Top divider · modifier hint · mid divider
	b.WriteString(div + "\n")
	b.WriteString(" " + a.stateHint() + "\n")
	b.WriteString(div + "\n")

	// Main content (per state)
	content := a.stateContent()
	for _, l := range strings.Split(content, "\n") {
		b.WriteString(" " + l + "\n")
	}

	// Bottom divider
	b.WriteString(div + "\n")

	// Status bar
	b.WriteString(a.renderStatusBar(width))
	return b.String()
}

func (a *App) stateHint() string {
	switch a.state {
	case stateSetup:
		return hintStyle.Render("Paste your Speculus API key · enter to save · esc to quit")
	case stateMenu:
		return hintStyle.Render("↑/↓ navigate · enter select")
	case stateFilePicker:
		return hintStyle.Render("↑/↓ navigate · enter select · esc back")
	case stateNoFilesPrompt, stateConfirmRun:
		return hintStyle.Render("↑/↓ · enter · esc")
	case stateEditor:
		return hintStyle.Render("ctrl+s save · esc cancel")
	case stateFetching:
		return hintStyle.Render("querying the Speculus API — please wait")
	case stateSingleInput:
		return hintStyle.Render("enter to lookup · esc back")
	case stateSingleResult, stateHealthResult, stateQuotaResult, stateDone, stateInfo:
		return hintStyle.Render("press enter to return to menu")
	}
	return " "
}

func (a *App) stateContent() string {
	switch a.state {
	case stateSetup:
		return promptStyle.Render(">") + "  " + a.apiInput.View()
	case stateMenu:
		return a.menuList.View()
	case stateFilePicker:
		return welcomeText.Render("Pick an IP file in "+humanCwd(a.cwd)) + "\n\n" + a.fileList.View()
	case stateNoFilesPrompt:
		return welcomeText.Render("No files matching \"ip\" found. Create ips.txt?") + "\n\n" + a.yesNoList.View()
	case stateConfirmRun:
		return welcomeOK.Render("✓ Saved "+a.pendingFile+". ") + welcomeText.Render("Query it now?") + "\n\n" + a.yesNoList.View()
	case stateEditor:
		out := welcomeText.Render("Editing ips.txt — one IP per line") + "\n\n" + a.editor.View()
		if a.info != "" {
			out += "\n" + welcomeBad.Render(a.info)
		}
		return out
	case stateFetching:
		if a.fetcher == nil {
			return ""
		}
		return a.fetcher.View()
	case stateSingleInput:
		out := welcomeText.Render("Enter an IP address:") + "\n\n" + promptStyle.Render(">") + "  " + a.singleInput.View()
		if a.info != "" {
			out += "\n" + welcomeBad.Render(a.info)
		}
		return out
	case stateSingleResult:
		return a.viewSingleResultContent()
	case stateHealthResult:
		if a.healthErr == nil {
			return welcomeOK.Render("✓ The Speculus API is online.")
		}
		return welcomeBad.Render("✗ Unreachable: " + a.healthErr.Error())
	case stateQuotaResult:
		return a.viewQuotaContent()
	case stateDone:
		return a.viewSummaryContent()
	case stateInfo:
		return welcomeText.Render(a.info)
	}
	return ""
}

func (a *App) viewSingleResultContent() string {
	if a.single == nil {
		return ""
	}
	r := a.single
	rs, ok := riskStyles[r.Intel.Risk]
	if !ok {
		rs = mutedStyle
	}
	var b strings.Builder
	b.WriteString(headingStyle.Render(r.Identity.IP) + " — " + rs.Render(r.Intel.Risk) +
		welcomeMuted.Render(fmt.Sprintf(" (score %d)", r.Intel.Score)) + "\n\n")

	b.WriteString(labelLine("Verdict", r.Verdict))

	// Identity
	if r.Identity.ConnectionType != "" {
		b.WriteString(labelLine("Connection", r.Identity.ConnectionType))
	}
	if r.Identity.ISP != "" {
		b.WriteString(labelLine("ISP", r.Identity.ISP))
	}
	if r.Identity.Org != "" {
		b.WriteString(labelLine("Org", r.Identity.Org))
	}
	if r.Identity.ASN != 0 {
		b.WriteString(labelLine("ASN", fmt.Sprintf("AS%d", r.Identity.ASN)))
	}

	// Location
	loc := fmt.Sprintf("%s, %s", r.Location.City, r.Location.Country)
	if r.Location.CountryCode != "" {
		loc += fmt.Sprintf(" (%s)", r.Location.CountryCode)
	}
	b.WriteString(labelLine("Location", loc))
	if r.Location.Coordinates.Lat != 0 || r.Location.Coordinates.Lon != 0 {
		b.WriteString(labelLine("Coordinates",
			fmt.Sprintf("%.4f, %.4f", r.Location.Coordinates.Lat, r.Location.Coordinates.Lon)))
	}

	// Cloud provider — only include non-empty parts
	if r.Intel.CloudProvider != nil {
		parts := []string{r.Intel.CloudProvider.Provider}
		if r.Intel.CloudProvider.Region != "" {
			parts = append(parts, r.Intel.CloudProvider.Region)
		}
		if r.Intel.CloudProvider.Service != "" {
			parts = append(parts, r.Intel.CloudProvider.Service)
		}
		b.WriteString(labelLine("Cloud", strings.Join(parts, " · ")))
	}

	// Residential proxy
	if rp := r.Intel.ResidentialProxy; rp != nil {
		b.WriteString(labelLine("Proxy", fmt.Sprintf("%s — %s", rp.Type, rp.Provider)))
		if rp.Score > 0 {
			b.WriteString(labelLine("Proxy score", fmt.Sprintf("%d / 100", rp.Score)))
		}
		if rp.DaysSeen > 0 {
			b.WriteString(labelLine("Days seen", fmt.Sprintf("%d", rp.DaysSeen)))
		}
		if seenLine := dateRange(rp.FirstSeen, rp.LastSeen); seenLine != "" {
			b.WriteString(labelLine("Proxy seen", seenLine))
		}
	}

	// Threat-intel detail
	if r.Intel.Attribution != "" {
		b.WriteString(labelLine("Attribution", r.Intel.Attribution))
	}
	if r.Intel.Activity != "" {
		b.WriteString(labelLine("Activity", r.Intel.Activity))
	}
	if seenLine := dateRange(r.Intel.FirstSeen, r.Intel.LastSeen); seenLine != "" {
		b.WriteString(labelLine("Threat seen", seenLine))
	}

	// Boolean flags
	var flags []string
	if r.Intel.TorNode {
		flags = append(flags, welcomeBad.Render("Tor"))
	}
	if r.Intel.VPNProxy {
		flags = append(flags, welcomeBad.Render("VPN/Proxy"))
	}
	if r.Intel.IsBlacklisted {
		flags = append(flags, welcomeBad.Render("Blacklisted"))
	}
	if r.Intel.IsDatacenter {
		flags = append(flags, welcomeMuted.Render("Datacenter"))
	}
	if r.Intel.IsScanner {
		flags = append(flags, welcomeBad.Render("Scanner"))
	}
	if len(flags) > 0 {
		b.WriteString(labelLine("Flags", strings.Join(flags, " · ")))
	}

	return strings.TrimRight(b.String(), "\n")
}

// dateRange formats two RFC3339 timestamps as a short date range. Empty
// strings are skipped and a single date is returned alone.
func dateRange(first, last string) string {
	short := func(s string) string {
		if s == "" {
			return ""
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.Format("2006-01-02")
		}
		return s
	}
	f, l := short(first), short(last)
	switch {
	case f != "" && l != "" && f != l:
		return f + " → " + l
	case f != "":
		return f
	case l != "":
		return l
	}
	return ""
}

func (a *App) viewQuotaContent() string {
	if a.quotaErr != nil {
		return welcomeBad.Render("Could not fetch quota: " + a.quotaErr.Error())
	}
	var b strings.Builder
	b.WriteString(labelLine("Used", humanInt(a.quota.Used)))
	b.WriteString(labelLine("Remaining", humanInt(a.quota.Remaining)))
	b.WriteString(labelLine("Limit", humanInt(a.quota.Limit)))
	b.WriteString(labelLine("Grace left", humanInt(a.quota.GraceRemaining)))
	if t, err := time.Parse(time.RFC3339, a.quota.ResetsAt); err == nil {
		b.WriteString(labelLine("Resets", t.Format("2006-01-02")))
	}
	if a.quota.InGrace {
		b.WriteString("\n" + welcomeBad.Render("⚠ You are in grace mode."))
	}
	return strings.TrimRight(b.String(), "\n")
}

func (a *App) renderStatusBar(width int) string {
	workspace := humanCwd(a.cwd)

	api := welcomeOK.Render("✓ online")
	if a.healthErr != nil {
		api = welcomeBad.Render("✗ unreachable")
	}

	quotaVal := welcomeMuted.Render("—")
	if a.token != "" && a.quotaErr == nil && a.quota.Limit > 0 {
		quotaVal = quotaStyle(a.quota.Remaining, a.quota.Limit, a.quota.InGrace).
			Render(fmt.Sprintf("%s / %s",
				humanInt(a.quota.Remaining), humanInt(a.quota.Limit)))
	}

	avail := width - 2
	col1 := avail * 45 / 100
	col2 := avail * 25 / 100
	col3 := avail - col1 - col2

	line1 := " " +
		padToWidth(statusKeyStyle.Render("directory"), col1) +
		padToWidth(statusKeyStyle.Render("api status"), col2) +
		rightAlignWithin(statusKeyStyle.Render("quota"), col3)
	line2 := " " +
		padToWidth(welcomeText.Render(workspace), col1) +
		padToWidth(api, col2) +
		rightAlignWithin(quotaVal, col3)

	return line1 + "\n" + line2
}

func padToWidth(s string, w int) string {
	pad := w - lipgloss.Width(s)
	if pad < 0 {
		pad = 0
	}
	return s + strings.Repeat(" ", pad)
}

func rightAlignWithin(s string, w int) string {
	pad := w - lipgloss.Width(s)
	if pad < 0 {
		pad = 0
	}
	return strings.Repeat(" ", pad) + s
}

func labelLine(label, value string) string {
	return welcomeLabel.Render(fmt.Sprintf("%-12s", label)) + " " + welcomeText.Render(value) + "\n"
}

// ---- File scanning -------------------------------------------------------

type ipFile struct {
	name    string
	summary string
}

func scanIPFiles(dir string) []ipFile {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []ipFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.Contains(strings.ToLower(name), "ip") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(name))
		if ext != "" && ext != ".txt" && ext != ".list" {
			continue
		}
		info, _ := e.Info()
		count := countIPsInFile(filepath.Join(dir, name))
		summary := fmt.Sprintf("%d IPs · %d bytes", count, info.Size())
		out = append(out, ipFile{name: name, summary: summary})
	}
	return out
}

func countIPsInFile(path string) int {
	ips, err := readIPs(path)
	if err != nil {
		return 0
	}
	return len(ips)
}

// ---- Summary -------------------------------------------------------------

func (a *App) viewSummaryContent() string {
	if a.summary == nil {
		return welcomeOK.Render("✓ Done.")
	}
	s := a.summary
	var b strings.Builder

	b.WriteString(welcomeOK.Render(fmt.Sprintf("✓ Queried %d IPs", s.completed)))
	if s.failed > 0 {
		b.WriteString(welcomeMuted.Render(fmt.Sprintf("  ·  %d failed", s.failed)))
	}
	b.WriteString("\n\n")

	if len(s.topCountries) > 0 {
		b.WriteString(headingStyle.Render("Top countries") + "\n")
		for _, c := range s.topCountries {
			b.WriteString(countRow(c.label, c.count, 24))
		}
		b.WriteString("\n")
	}

	if len(s.rareCountries) > 0 {
		b.WriteString(headingStyle.Render("Outlier countries") + "\n")
		for _, c := range s.rareCountries {
			b.WriteString(countRow(c.label, c.count, 24))
		}
		b.WriteString("\n")
	}

	if len(s.topASNs) > 0 {
		b.WriteString(headingStyle.Render("Top ASNs") + "\n")
		for _, c := range s.topASNs {
			b.WriteString(countRow(c.label, c.count, 48))
		}
		b.WriteString("\n")
	}

	if len(s.rareASNs) > 0 {
		b.WriteString(headingStyle.Render("Outlier ASNs") + "\n")
		for _, c := range s.rareASNs {
			b.WriteString(countRow(c.label, c.count, 48))
		}
		b.WriteString("\n")
	}

	renderThreatSection(&b, "VPN / Proxy", s.vpn, welcomeBad)
	renderThreatSection(&b, "Residential proxy", s.proxy, welcomeBad)
	renderThreatSection(&b, "Risky IPs", s.malicious, welcomeBad)
	renderActivitySection(&b, s.activity)

	b.WriteString(welcomeOK.Render("Wrote ") +
		welcomeText.Render(fmt.Sprintf("%d", s.completed)) +
		welcomeOK.Render(" records to ") +
		welcomeTitle.Render(s.outputFile))

	return strings.TrimRight(b.String(), "\n")
}

func renderActivitySection(b *strings.Builder, entries []threatEntry) {
	if len(entries) == 0 {
		return
	}
	b.WriteString(headingStyle.Render("Malicious Activity") + " " +
		welcomeBad.Render(fmt.Sprintf("(%d)", len(entries))) + "\n")

	const maxShow = 6
	cols := []int{18, 32, 40}
	headers := []string{"IP", "Activity", "Attribution"}

	b.WriteString("  ")
	for i, h := range headers {
		b.WriteString(welcomeLabel.Render(h) + strings.Repeat(" ", cols[i]-lipgloss.Width(h)))
	}
	b.WriteString("\n")

	b.WriteString("  ")
	for i := range headers {
		b.WriteString(welcomeMuted.Render(strings.Repeat("─", cols[i]-2)) + "  ")
	}
	b.WriteString("\n")

	show := entries
	extra := 0
	if len(show) > maxShow {
		extra = len(show) - maxShow
		show = show[:maxShow]
	}
	truncate := func(s string, w int) string {
		if lipgloss.Width(s) <= w {
			return s
		}
		runes := []rune(s)
		if len(runes) > w-1 {
			return string(runes[:w-1]) + "…"
		}
		return s
	}
	for _, e := range show {
		activity := e.activity
		if activity == "" {
			activity = welcomeMuted.Render("—")
		}
		attribution := e.attribution
		if attribution == "" {
			attribution = welcomeMuted.Render("—")
		}
		cells := []string{
			welcomeTitle.Render(e.ip),
			welcomeText.Render(truncate(activity, cols[1]-2)),
			welcomeText.Render(truncate(attribution, cols[2]-2)),
		}
		b.WriteString("  ")
		for i, c := range cells {
			pad := cols[i] - lipgloss.Width(c)
			if pad < 1 {
				pad = 1
			}
			b.WriteString(c + strings.Repeat(" ", pad))
		}
		b.WriteString("\n")
	}
	if extra > 0 {
		b.WriteString("  " + welcomeMuted.Render(fmt.Sprintf("+ %d more", extra)) + "\n")
	}
	b.WriteString("\n")
}

func renderThreatSection(b *strings.Builder, label string, entries []threatEntry, countStyle lipgloss.Style) {
	if len(entries) == 0 {
		return
	}
	b.WriteString(headingStyle.Render(label) + " " +
		countStyle.Render(fmt.Sprintf("(%d)", len(entries))) + "\n")

	const maxShow = 6
	cols := []int{18, 12, 30, 10, 12, 7}
	headers := []string{"IP", "ASN", "ISP", "Country", "Risk", "Score"}

	// Header row
	b.WriteString("  ")
	for i, h := range headers {
		b.WriteString(welcomeLabel.Render(h) + strings.Repeat(" ", cols[i]-lipgloss.Width(h)))
	}
	b.WriteString("\n")

	// Separator row
	b.WriteString("  ")
	for i := range headers {
		b.WriteString(welcomeMuted.Render(strings.Repeat("─", cols[i]-2)) + "  ")
	}
	b.WriteString("\n")

	show := entries
	extra := 0
	if len(show) > maxShow {
		extra = len(show) - maxShow
		show = show[:maxShow]
	}
	for _, e := range show {
		isp := e.isp
		if lipgloss.Width(isp) > cols[2]-2 {
			runes := []rune(isp)
			if len(runes) > cols[2]-3 {
				isp = string(runes[:cols[2]-3]) + "…"
			}
		}
		asn := ""
		if e.asn != 0 {
			asn = fmt.Sprintf("AS%d", e.asn)
		}
		country := e.country
		if country == "" {
			country = "—"
		}
		risk := e.risk
		if risk == "" {
			risk = "—"
		}
		riskStyled := riskStyles[risk].Render(risk)
		if _, ok := riskStyles[risk]; !ok {
			riskStyled = welcomeMuted.Render(risk)
		}

		cells := []string{
			welcomeTitle.Render(e.ip),
			welcomeText.Render(asn),
			welcomeText.Render(isp),
			welcomeText.Render(country),
			riskStyled,
			scoreColor(e.score).Render(fmt.Sprintf("%d", e.score)),
		}
		b.WriteString("  ")
		for i, c := range cells {
			pad := cols[i] - lipgloss.Width(c)
			if pad < 1 {
				pad = 1
			}
			b.WriteString(c + strings.Repeat(" ", pad))
		}
		b.WriteString("\n")
	}
	if extra > 0 {
		b.WriteString("  " + welcomeMuted.Render(fmt.Sprintf("+ %d more", extra)) + "\n")
	}
	b.WriteString("\n")
}

// scoreColor returns a lipgloss style based on the threat score tier.
//   - 0–29 green · 30–69 yellow · 70+ red
func scoreColor(score uint32) lipgloss.Style {
	switch {
	case score >= 70:
		return welcomeBad
	case score >= 30:
		return welcomeWarn
	default:
		return welcomeOK
	}
}

func countRow(label string, count int, labelWidth int) string {
	pad := labelWidth - lipgloss.Width(label)
	if pad < 1 {
		pad = 1
	}
	return "  " + welcomeText.Render(label) + strings.Repeat(" ", pad) +
		welcomeMuted.Render(fmt.Sprintf("%d", count)) + "\n"
}

func computeSummary(results []Response, completed, failed int, outputFile string) *fetchSummary {
	s := &fetchSummary{completed: completed, failed: failed, outputFile: outputFile}

	countries := map[string]int{}
	asns := map[string]int{}

	for _, r := range results {
		if r.Location.Country != "" {
			countries[r.Location.Country]++
		}
		if r.Identity.ASN != 0 {
			label := fmt.Sprintf("AS%d", r.Identity.ASN)
			switch {
			case r.Identity.Org != "":
				label += " · " + r.Identity.Org
			case r.Identity.ISP != "":
				label += " · " + r.Identity.ISP
			}
			asns[label]++
		}

		country := r.Location.CountryCode
		if country == "" {
			country = r.Location.Country
		}
		entry := threatEntry{
			ip:          r.Identity.IP,
			asn:         r.Identity.ASN,
			isp:         r.Identity.ISP,
			country:     country,
			risk:        r.Intel.Risk,
			score:       r.Intel.Score,
			activity:    r.Intel.Activity,
			attribution: r.Intel.Attribution,
		}
		if r.Intel.VPNProxy {
			s.vpn = append(s.vpn, entry)
		}
		if r.Intel.ResidentialProxy != nil {
			s.proxy = append(s.proxy, entry)
		}
		if r.Intel.IsBlacklisted || r.Intel.IsScanner || r.Intel.TorNode ||
			r.Intel.Activity != "" || r.Intel.Risk == "high" || r.Intel.Risk == "critical" {
			s.malicious = append(s.malicious, entry)
		}
		if r.Intel.Activity != "" || r.Intel.Attribution != "" {
			s.activity = append(s.activity, entry)
		}
	}

	s.topCountries = topN(countries, 3, true, nil)
	excludeCountries := excludeSet(s.topCountries)
	s.rareCountries = topN(countries, 5, false, excludeCountries)

	s.topASNs = topN(asns, 5, true, nil)
	excludeASNs := excludeSet(s.topASNs)
	s.rareASNs = topN(asns, 5, false, excludeASNs)

	return s
}

func excludeSet(items []countByLabel) map[string]bool {
	out := map[string]bool{}
	for _, c := range items {
		out[c.label] = true
	}
	return out
}

func topN(m map[string]int, n int, desc bool, exclude map[string]bool) []countByLabel {
	var all []countByLabel
	for k, v := range m {
		if exclude != nil && exclude[k] {
			continue
		}
		all = append(all, countByLabel{label: k, count: v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].count != all[j].count {
			if desc {
				return all[i].count > all[j].count
			}
			return all[i].count < all[j].count
		}
		return all[i].label < all[j].label
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func humanCwd(cwd string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(cwd, home) {
		return "~" + strings.TrimPrefix(cwd, home)
	}
	return cwd
}
