package tui

import (
	"fmt"
	"guardiantui/internal/proxy"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240"))
	
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205")).
			Bold(true)
	
	alertStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			Bold(true)
	
	okStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10"))

	searchStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("86")).
			Bold(true)

	barSafeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	barAlertStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)

type tickMsg time.Time

type stats struct {
	safe   int
	alerts int
}

type model struct {
	table       table.Model
	logs        []proxy.LogEntry
	logChan     chan proxy.LogEntry
	width       int
	height      int
	lastAlert   string
	searching   bool
	searchInput textinput.Model
	
	// Stats for Chart
	history     []stats
	current     stats
	maxVal      int
}

func NewModel(logChan chan proxy.LogEntry) model {
	columns := []table.Column{
		{Title: "ID", Width: 8},
		{Title: "Time", Width: 10},
		{Title: "IP", Width: 16},
		{Title: "Status", Width: 35},
		{Title: "Path", Width: 30},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(15),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	ti := textinput.New()
	ti.Placeholder = "Search by ID, IP, Attack..."
	ti.CharLimit = 50
	ti.Width = 30

	return model{
		table:       t,
		logChan:     logChan,
		logs:        make([]proxy.LogEntry, 0),
		searchInput: ti,
		history:     make([]stats, 60), // Last 60 seconds
		maxVal:      10,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		waitForActivity(m.logChan),
		tickEverySecond(),
	)
}

func tickEverySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func waitForActivity(c chan proxy.LogEntry) tea.Cmd {
	return func() tea.Msg {
		return logMsg(<-c)
	}
}

type logMsg proxy.LogEntry

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table.SetHeight(m.height - 18) // Adjust for chart
		totalWidth := m.width - 6
		m.table.SetColumns([]table.Column{
			{Title: "ID", Width: 8},
			{Title: "Time", Width: 10},
			{Title: "IP", Width: 16},
			{Title: "Status", Width: 35},
			{Title: "Path", Width: totalWidth - 8 - 10 - 16 - 35 - 6},
		})

	case tickMsg:
		// Move history
		m.history = append(m.history[1:], m.current)
		m.current = stats{0, 0}
		
		// Update max for scaling
		m.maxVal = 5
		for _, s := range m.history {
			if s.safe+s.alerts > m.maxVal {
				m.maxVal = s.safe + s.alerts
			}
		}
		return m, tickEverySecond()

	case tea.KeyMsg:
		if m.searching {
			switch msg.String() {
			case "enter", "esc":
				m.searching = false
				m.searchInput.Blur()
				m.updateTable()
				return m, nil
			}
			var tiCmd tea.Cmd
			m.searchInput, tiCmd = m.searchInput.Update(msg)
			m.updateTable()
			return m, tiCmd
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "/":
			m.searching = true
			m.searchInput.Focus()
			return m, nil
		case "esc":
			m.searchInput.SetValue("")
			m.updateTable()
			return m, nil
		}

	case logMsg:
		entry := proxy.LogEntry(msg)
		if entry.Alert != nil || entry.Blocked {
			m.current.alerts++
		} else {
			m.current.safe++
		}
		
		m.logs = append(m.logs, entry)
		if len(m.logs) > 500 {
			m.logs = m.logs[1:]
		}
		m.updateTable()
		return m, waitForActivity(m.logChan)
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m *model) updateTable() {
	query := strings.ToLower(m.searchInput.Value())
	rows := make([]table.Row, 0)
	for _, entry := range m.logs {
		status := "OK"
		if entry.Alert != nil {
			status = fmt.Sprintf("!! %s !!", entry.Alert.Type)
			m.lastAlert = fmt.Sprintf("[%s] %s attempted %s on %s", 
				entry.Timestamp.Format("15:04:05"), entry.RemoteIP, entry.Alert.Type, entry.Path)
		}
		if entry.Blocked { status = "BLOCKED" }
		match := query == "" || strings.Contains(strings.ToLower(entry.ID), query) || 
				 strings.Contains(strings.ToLower(entry.RemoteIP), query) || 
				 strings.Contains(strings.ToLower(status), query) || 
				 strings.Contains(strings.ToLower(entry.Path), query)
		if match {
			rows = append(rows, table.Row{entry.ID, entry.Timestamp.Format("15:04:05"), entry.RemoteIP, status, entry.Path})
		}
	}
	m.table.SetRows(rows)
	if query == "" { m.table.GotoBottom() }
}

func (m model) renderChart() string {
	height := 5
	var b strings.Builder
	b.WriteString("   Threats per Minute (Live Activity)\n")
	
	for h := height; h > 0; h-- {
		b.WriteString(fmt.Sprintf("%2d ", h*(m.maxVal/height)))
		for _, s := range m.history {
			safeH := 0
			alertH := 0
			if m.maxVal > 0 {
				safeH = (s.safe * height) / m.maxVal
				alertH = (s.alerts * height) / m.maxVal
			}
			
			if h <= alertH {
				b.WriteString(barAlertStyle.Render("█"))
			} else if h <= (safeH + alertH) {
				b.WriteString(barSafeStyle.Render("█"))
			} else {
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("      " + strings.Repeat("-", 60) + "\n")
	b.WriteString("      60s ago" + strings.Repeat(" ", 40) + "Now\n")
	return b.String()
}

func (m model) View() string {
	var s strings.Builder
	s.WriteString(headerStyle.Render("🛡️ GUARDIAN TUI - Real-time IPS & Block Engine"))
	s.WriteString("\n\n")
	
	s.WriteString(m.renderChart())
	s.WriteString("\n")
	
	if m.searching {
		s.WriteString(searchStyle.Render("SEARCH: ") + m.searchInput.View())
	} else if m.searchInput.Value() != "" {
		s.WriteString(searchStyle.Render("FILTER ACTIVE: ") + m.searchInput.Value() + " (press esc to clear)")
	} else {
		s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("Press / to search incident ID, IP or Attack type..."))
	}
	s.WriteString("\n")
	s.WriteString(baseStyle.Render(m.table.View()))
	s.WriteString("\n")
	
	if m.lastAlert != "" {
		s.WriteString(alertStyle.Render("LATEST BLOCK: " + m.lastAlert))
	} else {
		s.WriteString(okStyle.Render("SYSTEM STATUS: MONITORING - NO THREATS DETECTED"))
	}
	s.WriteString("\n\n")
	s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("q: quit | /: search | esc: clear search | arrows: scroll"))
	return s.String()
}
