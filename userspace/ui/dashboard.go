package ui

import (
	"fmt"
	"net"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TelemetrySnapshot represents a single live frame update for the UI
type TelemetrySnapshot struct {
	TotalPackets uint64
	TotalDrops   uint64
	ActiveFlows  int
	RecentBans   []BanRecord
	LiveStream   []string
}

type BanRecord struct {
	IP        string
	RiskScore float64
	Reason    string
	BannedAt  time.Time
}

// TickMsg drives periodic UI refreshes
type TickMsg time.Time

// Model holds the state of the terminal interface
type Model struct {
	snapshot   TelemetrySnapshot
	dataSource func() TelemetrySnapshot
	width      int
	height     int
}

// Styling definitions with Lip Gloss
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	statBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#5A56E0")).
			Padding(0, 1).
			MarginRight(1)

	bannedBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#FF5F87")).
			Padding(0, 1).
			Width(48)

	liveLogStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#04B575")).
			Padding(0, 1).
			Width(60)

	accentStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#04B575"))
	alertStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5F87"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#626262"))
)

func NewModel(fetcher func() TelemetrySnapshot) Model {
	return Model{
		dataSource: fetcher,
		snapshot:   fetcher(),
	}
}

func (m Model) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*250, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case TickMsg:
		m.snapshot = m.dataSource()
		return m, tickCmd()
	}
	return m, nil
}

func (m Model) View() string {
	var b strings.Builder

	// Header Banner
	b.WriteString(headerStyle.Render(" GHOSTGATE // KERNEL-LEVEL XDP INTRUSION PREVENTER ") + "\n\n")

	// Top Metric Cards
	pktCard := statBoxStyle.Render(fmt.Sprintf("%s\n%s", dimStyle.Render("Total Ingested:"), accentStyle.Render(fmt.Sprintf("%d pkts", m.snapshot.TotalPackets))))
	dropCard := statBoxStyle.Render(fmt.Sprintf("%s\n%s", dimStyle.Render("Kernel Drops:"), alertStyle.Render(fmt.Sprintf("%d pkts", m.snapshot.TotalDrops))))
	flowsCard := statBoxStyle.Render(fmt.Sprintf("%s\n%s", dimStyle.Render("Active Flows:"), accentStyle.Render(fmt.Sprintf("%d nodes", m.snapshot.ActiveFlows))))
	metricsRow := lipgloss.JoinHorizontal(lipgloss.Top, pktCard, dropCard, flowsCard)
	b.WriteString(metricsRow + "\n\n")

	// Banned Devices Table Box
	var banContent strings.Builder
	banContent.WriteString(alertStyle.Render("ACTIVE KERNEL MITIGATIONS (XDP_DROP)") + "\n")
	banContent.WriteString(dimStyle.Render("IP ADDR          SCORE   REASON      TIME") + "\n")
	if len(m.snapshot.RecentBans) == 0 {
		banContent.WriteString(dimStyle.Render("No active IP bans applied yet."))
	} else {
		for _, ban := range m.snapshot.RecentBans {
			banContent.WriteString(fmt.Sprintf("%-15s %5.1f   %-10s  %s\n",
				ban.IP,
				ban.RiskScore,
				ban.Reason,
				ban.BannedAt.Format("15:04:05"),
			))
		}
	}
	bannedView := bannedBoxStyle.Render(banContent.String())

	// Live Ingestion Stream Box
	var liveContent strings.Builder
	liveContent.WriteString(accentStyle.Render("REAL-TIME RING BUFFER INGEST") + "\n")
	if len(m.snapshot.LiveStream) == 0 {
		liveContent.WriteString(dimStyle.Render("Waiting for incoming frames..."))
	} else {
		for _, line := range m.snapshot.LiveStream {
			liveContent.WriteString(line + "\n")
		}
	}
	liveView := liveLogStyle.Render(liveContent.String())

	// Join lower sections side by side
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, bannedView, liveView) + "\n\n")
	b.WriteString(dimStyle.Render("Press 'q' or Ctrl+C to stop GhostGate and detach XDP filter."))

	return b.String()
}

// LaunchTUI starts the bubbletea program in an alternate full-screen terminal buffer
func LaunchTUI(fetcher func() TelemetrySnapshot) error {
	p := tea.NewProgram(NewModel(fetcher), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func FormatIP(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}