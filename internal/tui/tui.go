package tui

import (
	"fmt"
	"guardiantui/internal/proxy"
	"strings"

	"github.com/charmbracelet/bubbles/table"
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
)

type model struct {
	table     table.Model
	logs      []proxy.LogEntry
	logChan   chan proxy.LogEntry
	width     int
	height    int
	lastAlert string
}

func NewModel(logChan chan proxy.LogEntry) model {
	columns := []table.Column{
		{Title: "Time", Width: 10},
		{Title: "IP", Width: 15},
		{Title: "Method", Width: 8},
		{Title: "Path", Width: 30},
		{Title: "Status", Width: 15},
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

	return model{
		table:   t,
		logChan: logChan,
		logs:    make([]proxy.LogEntry, 0),
	}
}

func (m model) Init() tea.Cmd {
	return waitForActivity(m.logChan)
}

type logMsg proxy.LogEntry

func waitForActivity(c chan proxy.LogEntry) tea.Cmd {
	return func() tea.Msg {
		return logMsg(<-c)
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Adjust table height dynamically (leave space for header/footer)
		m.table.SetHeight(m.height - 12)

		// Proportional column resizing
		totalWidth := m.width - 10
		if totalWidth < 60 {
			totalWidth = 60
		}
		
		m.table.SetColumns([]table.Column{
			{Title: "Time", Width: 10},
			{Title: "IP", Width: 18},
			{Title: "Method", Width: 8},
			{Title: "Path", Width: totalWidth - 10 - 18 - 8 - 20},
			{Title: "Status", Width: 20},
		})

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "b":
			if len(m.logs) > 0 {
				selected := m.table.SelectedRow()
				m.lastAlert = fmt.Sprintf("Blocking IP: %s (Simulated)", selected[1])
			}
		}

	case logMsg:
		m.logs = append(m.logs, proxy.LogEntry(msg))
		if len(m.logs) > 100 {
			m.logs = m.logs[1:]
		}
		
		rows := make([]table.Row, len(m.logs))
		for i, entry := range m.logs {
			status := "OK"
			if entry.Alert != nil {
				status = fmt.Sprintf("!! %s !!", entry.Alert.Type)
				m.lastAlert = fmt.Sprintf("[%s] %s attempted %s on %s", 
					entry.Timestamp.Format("15:04:05"), 
					entry.RemoteIP, 
					entry.Alert.Type, 
					entry.Path)
			}
			if entry.Blocked {
				status = "BLOCKED"
			}
			
			rows[i] = table.Row{
				entry.Timestamp.Format("15:04:05"),
				entry.RemoteIP,
				entry.Method,
				entry.Path,
				status,
			}
		}
		m.table.SetRows(rows)
		m.table.GotoBottom()
		return m, waitForActivity(m.logChan)
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	var s strings.Builder
	
	s.WriteString(headerStyle.Render("🛡️ GUARDIAN TUI - Real-time L7 IPS Engine"))
	s.WriteString("\n\n")
	s.WriteString(baseStyle.Render(m.table.View()))
	s.WriteString("\n\n")
	
	if m.lastAlert != "" {
		s.WriteString(alertStyle.Render("LAST ALERT: " + m.lastAlert))
	} else {
		s.WriteString(okStyle.Render("SYSTEM STATUS: MONITORING - NO THREATS DETECTED"))
	}
	
	s.WriteString("\n\n")
	s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("q: quit | b: block selected ip | use arrows to scroll"))
	
	return s.String()
}
