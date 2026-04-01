package tui

import (
	"fmt"
	"guardiantui/internal/proxy"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Theme defines the color palette for the TUI
type Theme struct {
	Name         string
	Primary      lipgloss.Color
	Secondary    lipgloss.Color
	Accent       lipgloss.Color
	Alert        lipgloss.Color
	Success      lipgloss.Color
	Text         lipgloss.Color
	Dim          lipgloss.Color
	Background   lipgloss.Color
}

var themes = map[string]Theme{
	"cyber": {
		Name:      "Cyber",
		Primary:   lipgloss.Color("#00f2ff"),
		Secondary: lipgloss.Color("#252a34"),
		Accent:    lipgloss.Color("#08d9d6"),
		Alert:     lipgloss.Color("#ff2e63"),
		Success:   lipgloss.Color("#08ffc8"),
		Text:      lipgloss.Color("#eaeaea"),
		Dim:       lipgloss.Color("#393e46"),
		Background: lipgloss.Color("#1a1a1a"),
	},
	"forest": {
		Name:      "Forest",
		Primary:   lipgloss.Color("#a2d076"),
		Secondary: lipgloss.Color("#2d3319"),
		Accent:    lipgloss.Color("#6fb98f"),
		Alert:     lipgloss.Color("#e27d60"),
		Success:   lipgloss.Color("#85cdca"),
		Text:      lipgloss.Color("#f1f1f1"),
		Dim:       lipgloss.Color("#4d5d53"),
		Background: lipgloss.Color("#1e241e"),
	},
	"dracula": {
		Name:      "Dracula",
		Primary:   lipgloss.Color("#bd93f9"),
		Secondary: lipgloss.Color("#282a36"),
		Accent:    lipgloss.Color("#ff79c6"),
		Alert:     lipgloss.Color("#ff5555"),
		Success:   lipgloss.Color("#50fa7b"),
		Text:      lipgloss.Color("#f8f8f2"),
		Dim:       lipgloss.Color("#6272a4"),
		Background: lipgloss.Color("#282a36"),
	},
	"monochrome": {
		Name:      "Monochrome",
		Primary:   lipgloss.Color("#ffffff"),
		Secondary: lipgloss.Color("#111111"),
		Accent:    lipgloss.Color("#aaaaaa"),
		Alert:     lipgloss.Color("#cccccc"),
		Success:   lipgloss.Color("#eeeeee"),
		Text:      lipgloss.Color("#ffffff"),
		Dim:       lipgloss.Color("#333333"),
		Background: lipgloss.Color("#000000"),
	},
}

type tickMsg time.Time

type stats struct {
	safe   int
	alerts int
}

type model struct {
	table       table.Model
	logs        []proxy.LogEntry
	logChan     chan proxy.LogEntry
	engine      *proxy.Engine
	width       int
	height      int
	lastAlert   string
	searching   bool
	searchInput textinput.Model
	theme       Theme
	suggestion  string
	suggIdx     int

	// Dashboard Data
	history        []stats
	current        stats
	maxVal         int
	totalRequests  int
	totalBlocks    int
	threatTypes    map[string]int
	startTime      time.Time
	activeRequests int
}

func NewModel(logChan chan proxy.LogEntry, engine *proxy.Engine, themeName string) model {
	theme, ok := themes[strings.ToLower(themeName)]
	if !ok {
		theme = themes["cyber"]
	}

	columns := []table.Column{
		{Title: "ID", Width: 8},
		{Title: "TIME", Width: 10},
		{Title: "SOURCE IP", Width: 16},
		{Title: "SECURITY STATUS", Width: 35},
		{Title: "REQUEST PATH", Width: 30},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(15),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(theme.Dim).
		BorderBottom(true).
		Bold(true).
		Foreground(theme.Primary)
	s.Selected = s.Selected.
		Foreground(theme.Text).
		Background(theme.Accent).
		Bold(false)
	t.SetStyles(s)

	ti := textinput.New()
	ti.Placeholder = "Filter by Pattern/IP..."
	ti.CharLimit = 50
	ti.Width = 30
	ti.Prompt = " 🔍 "

	return model{
		table:       t,
		logChan:     logChan,
		engine:      engine,
		logs:        make([]proxy.LogEntry, 0),
		searchInput: ti,
		history:     make([]stats, 60),
		maxVal:      10,
		threatTypes: make(map[string]int),
		startTime:   time.Now(),
		theme:       theme,
		suggIdx:     -1,
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

		// Adaptive table height - reserved space for other UI components
		reservedHeight := 24
		if m.width < 110 {
			reservedHeight = 32 // More space if layout stacks vertically
		}
		newHeight := m.height - reservedHeight
		if newHeight < 5 {
			newHeight = 5
		}
		m.table.SetHeight(newHeight)

		totalWidth := m.width - 6
		pathWidth := totalWidth - 8 - 10 - 16 - 35 - 8
		if pathWidth < 10 {
			pathWidth = 10
		}

		m.table.SetColumns([]table.Column{
			{Title: "ID", Width: 8},
			{Title: "TIME", Width: 10},
			{Title: "SOURCE IP", Width: 16},
			{Title: "SECURITY STATUS", Width: 35},
			{Title: "REQUEST PATH", Width: pathWidth},
		})

	case tickMsg:
		m.history = append(m.history[1:], m.current)
		m.activeRequests = m.current.safe + m.current.alerts
		m.current = stats{0, 0}
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
			case "tab":
				val := strings.ToLower(m.searchInput.Value())
				if strings.HasPrefix("themes set ", val) && !strings.HasPrefix(val, "themes set ") {
					m.searchInput.SetValue("themes set ")
					m.searchInput.SetCursor(len("themes set "))
				} else if strings.HasPrefix(val, "themes set ") {
					themeList := []string{"cyber", "forest", "dracula", "monochrome"}
					m.suggIdx = (m.suggIdx + 1) % len(themeList)
					m.searchInput.SetValue("themes set " + themeList[m.suggIdx])
					m.searchInput.SetCursor(len(m.searchInput.Value()))
				} else if strings.HasPrefix("modes set ", val) && !strings.HasPrefix(val, "modes set ") {
					m.searchInput.SetValue("modes set ")
					m.searchInput.SetCursor(len("modes set "))
				} else if strings.HasPrefix(val, "modes set ") {
					modeList := []string{"ips", "ids", "strict"}
					m.suggIdx = (m.suggIdx + 1) % len(modeList)
					m.searchInput.SetValue("modes set " + modeList[m.suggIdx])
					m.searchInput.SetCursor(len(m.searchInput.Value()))
				}
				return m, nil
			case "enter":
				val := m.searchInput.Value()
				if strings.HasPrefix(strings.ToLower(val), "themes set ") {
					parts := strings.Split(val, " ")
					if len(parts) >= 3 {
						newThemeName := strings.ToLower(parts[2])
						if newTheme, ok := themes[newThemeName]; ok {
							m.theme = newTheme
							// Re-apply styles to the table as it's a sub-component
							s := table.DefaultStyles()
							s.Header = s.Header.
								BorderStyle(lipgloss.NormalBorder()).
								BorderForeground(m.theme.Dim).
								BorderBottom(true).
								Bold(true).
								Foreground(m.theme.Primary)
							s.Selected = s.Selected.
								Foreground(m.theme.Text).
								Background(m.theme.Accent).
								Bold(false)
							m.table.SetStyles(s)
						}
					}
					m.searchInput.SetValue("")
					m.searching = false
					m.searchInput.Blur()
					m.updateTable()
					return m, nil
				} else if strings.HasPrefix(strings.ToLower(val), "modes set ") {
					parts := strings.Split(val, " ")
					if len(parts) >= 3 {
						newMode := strings.ToLower(parts[2])
						if newMode == "ips" || newMode == "ids" || newMode == "strict" {
							if m.engine != nil {
								m.engine.Mode = newMode
								// If strict and PoW is not initialized, initialize it
								if newMode == "strict" && m.engine.PoW == nil {
									difficulty := 4
									if m.engine.Config != nil && m.engine.Config.Engine.PoWDifficulty > 0 {
										difficulty = m.engine.Config.Engine.PoWDifficulty
									}
									// Lazy init PoW
									// Note: pow.NewSystem might need a proper key if it was using one, 
									// but here we use empty string as default.
									m.engine.PoW = proxy.NewPoWSystem(difficulty, "")
								}
							}
						}
					}
					m.searchInput.SetValue("")
					m.searching = false
					m.searchInput.Blur()
					m.updateTable()
					return m, nil
				}
				m.searching = false
				m.searchInput.Blur()
				m.updateTable()
				return m, nil
			case "esc":
				m.searching = false
				m.searchInput.Blur()
				m.updateTable()
				return m, nil
			}
			var tiCmd tea.Cmd
			m.searchInput, tiCmd = m.searchInput.Update(msg)
			if msg.String() != "tab" {
				m.suggIdx = -1
			}
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
		m.totalRequests++
		if entry.Alert != nil || entry.Blocked {
			m.current.alerts++
			m.totalBlocks++
			if entry.Alert != nil {
				m.threatTypes[entry.Alert.Type]++
			}
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
		status := "PASSIVE MONITORING"
		if entry.Alert != nil {
			status = fmt.Sprintf("🛡️ DETECTED: %s", entry.Alert.Type)
			m.lastAlert = fmt.Sprintf("[%s] %s -> %s (%s)",
				entry.Timestamp.Format("15:04:05"), entry.RemoteIP, entry.Path, entry.Alert.Type)
		}
		if entry.Blocked {
			status = "🚫 BLOCKED (IPS)"
		}
		match := query == "" || strings.Contains(strings.ToLower(entry.ID), query) ||
			strings.Contains(strings.ToLower(entry.RemoteIP), query) ||
			strings.Contains(strings.ToLower(status), query) ||
			strings.Contains(strings.ToLower(entry.Path), query)
		if match {
			rows = append(rows, table.Row{entry.ID, entry.Timestamp.Format("15:04:05"), entry.RemoteIP, status, entry.Path})
		}
	}
	m.table.SetRows(rows)
	if query == "" {
		m.table.GotoBottom()
	}
}

func (m model) renderStats() string {
	styleBox := lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(1)
	styleStatLabel := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true)
	styleStatValue := lipgloss.NewStyle().Foreground(m.theme.Primary)
	styleAlert := lipgloss.NewStyle().Foreground(m.theme.Alert).Bold(true)

	uptime := time.Since(m.startTime).Round(time.Second)
	
	s1 := lipgloss.JoinVertical(lipgloss.Left,
		styleStatLabel.Render("UPTIME"),
		styleStatValue.Render(uptime.String()),
	)
	s2 := lipgloss.JoinVertical(lipgloss.Left,
		styleStatLabel.Render("TOTAL REQUESTS"),
		styleStatValue.Render(fmt.Sprintf("%d", m.totalRequests)),
	)
	s3 := lipgloss.JoinVertical(lipgloss.Left,
		styleStatLabel.Render("IPS BLOCKS"),
		styleAlert.Render(fmt.Sprintf("%d", m.totalBlocks)),
	)
	s4 := lipgloss.JoinVertical(lipgloss.Left,
		styleStatLabel.Render("LIVE RPS"),
		styleStatValue.Render(fmt.Sprintf("%d req/s", m.activeRequests)),
	)

	// Responsive stats boxes
	boxWidth := (m.width - 12) / 4
	if boxWidth < 15 { boxWidth = 15 }
	if boxWidth > 25 { boxWidth = 25 }

	row := lipgloss.JoinHorizontal(lipgloss.Top,
		styleBox.Width(boxWidth).Render(s1),
		styleBox.Width(boxWidth).Render(s2),
		styleBox.Width(boxWidth).Render(s3),
		styleBox.Width(boxWidth).Render(s4),
	)

	if m.width < 80 {
		row = lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Top, styleBox.Width(boxWidth).Render(s1), styleBox.Width(boxWidth).Render(s2)),
			lipgloss.JoinHorizontal(lipgloss.Top, styleBox.Width(boxWidth).Render(s3), styleBox.Width(boxWidth).Render(s4)),
		)
	}
	return row
}

func (m model) renderThreatDistribution() string {
	styleStatLabel := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true)
	styleBox := lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(1)
	styleAlert := lipgloss.NewStyle().Foreground(m.theme.Alert).Bold(true)

	var b strings.Builder
	b.WriteString(styleStatLabel.Render("THREAT DISTRIBUTION") + "\n\n")

	type kv struct {
		Key   string
		Value int
	}
	var ss []kv
	for k, v := range m.threatTypes {
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	if len(ss) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Dim).Render("No threats detected yet."))
	}

	for i, kv := range ss {
		if i >= 5 { break }
		percent := 0.0
		if m.totalBlocks > 0 {
			percent = (float64(kv.Value) / float64(m.totalBlocks)) * 100
		}
		barWidth := int(percent / 10)
		bar := styleAlert.Render(strings.Repeat("█", barWidth))
		b.WriteString(fmt.Sprintf("%-18s %s %3.0f%%\n", 
			truncateString(kv.Key, 18), bar, percent))
	}
	
	distWidth := 45
	if m.width < 110 { distWidth = m.width - 10 }
	return styleBox.Width(distWidth).Height(7).Render(b.String())
}

func (m model) renderActivityChart() string {
	styleStatLabel := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true)
	styleBox := lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(1)

	height := 6
	chartWidth := 60
	if m.width < 110 { chartWidth = m.width - 20 }
	if chartWidth < 20 { chartWidth = 20 }

	var b strings.Builder
	b.WriteString(styleStatLabel.Render("LIVE SECURITY TRAFFIC (60s)") + "\n\n")
	
	for h := height; h > 0; h-- {
		// Scale max for axis
		axisVal := 0
		if m.maxVal > 0 {
			axisVal = h * (m.maxVal / height)
		}
		b.WriteString(fmt.Sprintf("%2d ", axisVal))
		
		// Adjust history to fit chartWidth
		visibleHistory := m.history
		if len(m.history) > chartWidth {
			visibleHistory = m.history[len(m.history)-chartWidth:]
		}

		for _, s := range visibleHistory {
			safeH := 0
			alertH := 0
			if m.maxVal > 0 {
				safeH = (s.safe * height) / m.maxVal
				alertH = (s.alerts * height) / m.maxVal
			}
			
			if h <= alertH {
				b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Alert).Render("█"))
			} else if h <= (safeH + alertH) {
				b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Success).Render("█"))
			} else {
				b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Dim).Render("·"))
			}
		}
		b.WriteString("\n")
	}
	return styleBox.Width(chartWidth + 10).Height(7).Render(b.String())
}

func truncateString(s string, l int) string {
	if len(s) <= l { return s }
	if l <= 1 { return "…" }
	return s[:l-1] + "…"
}

func (m model) View() string {
	styleHeader := lipgloss.NewStyle().
			Foreground(m.theme.Primary).
			Bold(true).
			Padding(0, 1).
			BorderStyle(lipgloss.DoubleBorder()).
			BorderForeground(m.theme.Primary)

	styleBox := lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(m.theme.Dim).
			Padding(1)

	styleSearch := lipgloss.NewStyle().
			Foreground(m.theme.Primary).
			Italic(true)

	modeStr := "IPS"
	if m.engine != nil {
		modeStr = strings.ToUpper(m.engine.Mode)
	}

	header := styleHeader.Render(fmt.Sprintf("🛡️  GUARDIAN TUI v2.0 | MODE: %s | THEME: %s", modeStr, strings.ToUpper(m.theme.Name)))
	
	var topRow string
	if m.width >= 110 {
		topRow = lipgloss.JoinHorizontal(lipgloss.Top, 
			m.renderActivityChart(),
			m.renderThreatDistribution(),
		)
	} else {
		topRow = lipgloss.JoinVertical(lipgloss.Left, 
			m.renderActivityChart(),
			m.renderThreatDistribution(),
		)
	}

	searchArea := ""
	if m.searching {
		searchArea = styleBox.BorderForeground(m.theme.Primary).Render(m.searchInput.View())
	} else if m.searchInput.Value() != "" {
		searchArea = styleSearch.Render(" 🎯 ACTIVE FILTER: ") + m.searchInput.Value() + lipgloss.NewStyle().Foreground(m.theme.Dim).Render(" (esc to reset)")
	} else {
		searchArea = lipgloss.NewStyle().Foreground(m.theme.Dim).Render(" [/] SEARCH | [themes set <name>] | [modes set <name>] | [tab] AUTOCOMPLETE | [q] QUIT")
	}

	statusLine := ""
	if m.lastAlert != "" {
		statusLine = lipgloss.NewStyle().
			Background(m.theme.Alert).
			Foreground(m.theme.Text).
			Bold(true).
			Padding(0, 1).
			Render(" 🚨 CRITICAL INCIDENT DETECTED: " + m.lastAlert + " ")
	} else {
		statusLine = lipgloss.NewStyle().
			Background(m.theme.Success).
			Foreground(lipgloss.Color("#000")).
			Bold(true).
			Padding(0, 1).
			Render(" ✨ SYSTEM STATUS: FULL MONITORING MODE - ALL SYSTEMS NOMINAL ")
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		"\n",
		m.renderStats(),
		topRow,
		searchArea,
		styleBox.BorderForeground(m.theme.Secondary).Render(m.table.View()),
		statusLine,
	)
}
