package main

import (
	"encoding/csv"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const recentLines = 5

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	mutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

var riskStyles = map[string]lipgloss.Style{
	"low":      lipgloss.NewStyle().Foreground(lipgloss.Color("42")),
	"medium":   lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
	"high":     lipgloss.NewStyle().Foreground(lipgloss.Color("208")),
	"critical": lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")),
}

type resultLine struct {
	ip    string
	risk  string
	score uint32
	err   string
}

type fetchResultMsg struct {
	ip   net.IP
	resp Response
	err  error
}

type fetchDoneMsg struct {
	completed  int
	failed     int
	outputFile string
	results    []Response
}

type fetcher struct {
	ips        []net.IP
	idx        int
	completed  int
	failed     int
	recent     []resultLine
	results    []Response
	spinner    spinner.Model
	progress   progress.Model
	client     *http.Client
	token      string
	writer     *csv.Writer
	outputFile string
	done       bool
}

func newFetcher(ips []net.IP, client *http.Client, token string, w *csv.Writer, outputFile string) *fetcher {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff7208"))

	pr := progress.New(progress.WithDefaultGradient(), progress.WithWidth(40))

	return &fetcher{
		ips:        ips,
		spinner:    sp,
		progress:   pr,
		client:     client,
		token:      token,
		writer:     w,
		outputFile: outputFile,
	}
}

func (m *fetcher) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.fetchNext())
}

func (m *fetcher) fetchNext() tea.Cmd {
	if m.idx >= len(m.ips) {
		return nil
	}
	ip := m.ips[m.idx]
	client := m.client
	token := m.token
	return func() tea.Msg {
		r, err := FetchSpeculus(client, token, ip)
		return fetchResultMsg{ip: ip, resp: r, err: err}
	}
}

func (m *fetcher) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return cmd

	case progress.FrameMsg:
		newProgress, cmd := m.progress.Update(msg)
		m.progress = newProgress.(progress.Model)
		return cmd

	case fetchResultMsg:
		line := resultLine{ip: msg.ip.String()}
		if msg.err != nil {
			m.failed++
			line.err = msg.err.Error()
		} else {
			m.completed++
			m.results = append(m.results, msg.resp)
			line.risk = msg.resp.Intel.Risk
			line.score = msg.resp.Intel.Score
			if err := m.writer.Write(responseToRow(msg.resp)); err == nil {
				m.writer.Flush()
			}
		}
		m.recent = append(m.recent, line)
		if len(m.recent) > recentLines {
			m.recent = m.recent[len(m.recent)-recentLines:]
		}
		m.idx++

		pct := float64(m.idx) / float64(len(m.ips))
		progCmd := m.progress.SetPercent(pct)

		if m.idx >= len(m.ips) {
			m.done = true
			done := fetchDoneMsg{
				completed:  m.completed,
				failed:     m.failed,
				outputFile: m.outputFile,
				results:    m.results,
			}
			return tea.Sequence(progCmd, func() tea.Msg { return done })
		}
		return tea.Batch(progCmd, m.fetchNext())
	}
	return nil
}

func (m *fetcher) View() string {
	var b strings.Builder

	current := ""
	if m.idx < len(m.ips) {
		current = m.ips[m.idx].String()
	}
	b.WriteString(fmt.Sprintf("%s Querying %s\n", m.spinner.View(), current))
	b.WriteString(m.progress.View() + "\n")
	b.WriteString(mutedStyle.Render(fmt.Sprintf("%d / %d complete · %d failed", m.completed+m.failed, len(m.ips), m.failed)))
	b.WriteString("\n\n")

	if len(m.recent) > 0 {
		b.WriteString(mutedStyle.Render("Recent results:") + "\n")
		for _, r := range m.recent {
			if r.err != "" {
				b.WriteString(errorStyle.Render("✗ ") + r.ip + " " + mutedStyle.Render("— "+r.err) + "\n")
				continue
			}
			rs, ok := riskStyles[r.risk]
			if !ok {
				rs = mutedStyle
			}
			b.WriteString(successStyle.Render("✓ ") + r.ip + " — " + rs.Render(r.risk) + mutedStyle.Render(fmt.Sprintf(" (score %d)", r.score)) + "\n")
		}
	}
	return b.String()
}
