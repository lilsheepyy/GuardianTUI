package tui

import (
	"fmt"
	"guardiantui/internal/proxy"
	"os"
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

	// Placeholder columns, will be resized on first WindowSizeMsg
	columns := []table.Column{
		{Title: "ID", Width: 6},
		{Title: "TIME", Width: 9},
		{Title: "SOURCE IP", Width: 15},
		{Title: "SECURITY STATUS", Width: 20},
		{Title: "REQUEST PATH", Width: 20},
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
	ti.Placeholder = "Enter command (e.g. search 1.2.3.4)"
	ti.CharLimit = 50
	ti.Width = 40
	ti.Prompt = " TERMINAL > "

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

		// Dynamic reserved height calculation
		// Base UI (Padding-Top(4), Status(1), Header(1), Spacer(1), Stats(4), Terminal(2), Footer(1)) = 14 lines
		reservedHeight := 14
		showCharts := m.height >= 35 || (m.height >= 28 && m.width >= 110)
		
		if showCharts {
			if m.width >= 110 {
				reservedHeight += 11 // Side-by-side charts
			} else {
				reservedHeight += 21 // Stacked charts
			}
		}
		
		newHeight := m.height - reservedHeight
		if newHeight < 4 {
			newHeight = 4
		}
		m.table.SetHeight(newHeight)

		// Dynamic column widths
		idW, timeW, ipW, statusW := 8, 10, 16, 30
		if m.width < 100 {
			idW, timeW, ipW, statusW = 6, 9, 15, 20
		}

		totalWidth := m.width - 10 
		pathW := totalWidth - idW - timeW - ipW - statusW
		if pathW < 10 {
			pathW = 10
		}

		m.table.SetColumns([]table.Column{
			{Title: "ID", Width: idW}, {Title: "TIME", Width: timeW},
			{Title: "SOURCE IP", Width: ipW}, {Title: "SECURITY STATUS", Width: statusW},
			{Title: "REQUEST PATH", Width: pathW},
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
				themeList := []string{"cyber", "forest", "dracula", "monochrome"}
				modeList := []string{"ips", "ids", "strict"}
				baseCmds := []string{"search ", "themes set ", "modes set ", "clear", "quit"}

				if strings.HasPrefix(val, "themes set ") {
					m.suggIdx = (m.suggIdx + 1) % len(themeList)
					m.searchInput.SetValue("themes set " + themeList[m.suggIdx])
					m.searchInput.SetCursor(len(m.searchInput.Value()))
					return m, nil
				}
				if strings.HasPrefix(val, "modes set ") {
					m.suggIdx = (m.suggIdx + 1) % len(modeList)
					m.searchInput.SetValue("modes set " + modeList[m.suggIdx])
					m.searchInput.SetCursor(len(m.searchInput.Value()))
					return m, nil
				}
				matched := false
				for _, cmd := range baseCmds {
					if strings.HasPrefix(cmd, val) && val != cmd {
						m.searchInput.SetValue(cmd)
						m.searchInput.SetCursor(len(cmd))
						matched = true
						break
					}
				}
				if !matched {
					m.suggIdx = (m.suggIdx + 1) % len(baseCmds)
					m.searchInput.SetValue(baseCmds[m.suggIdx])
					m.searchInput.SetCursor(len(baseCmds[m.suggIdx]))
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
							s := table.DefaultStyles()
							s.Header = s.Header.BorderForeground(m.theme.Dim).Foreground(m.theme.Primary)
							s.Selected = s.Selected.Foreground(m.theme.Text).Background(m.theme.Accent)
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
								if newMode == "strict" && m.engine.PoW == nil {
									m.engine.PoW = proxy.NewPoWSystem(4, "")
								}
							}
						}
					}
					m.searchInput.SetValue("")
					m.searching = false
					m.searchInput.Blur()
					m.updateTable()
					return m, nil
				} else if strings.EqualFold(val, "clear") {
					m.searchInput.SetValue("")
					m.searching = false
					m.searchInput.Blur()
					m.updateTable()
					return m, nil
				} else if strings.EqualFold(val, "quit") {
					return m, tea.Quit
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
			if msg.String() != "tab" { m.suggIdx = -1 }
			m.updateTable()
			return m, tiCmd
		}
		switch msg.String() {
		case "q", "ctrl+c": return m, tea.Quit
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
			if entry.Alert != nil { m.threatTypes[entry.Alert.Type]++ }
		} else {
			m.current.safe++
		}
		m.logs = append(m.logs, entry)
		if len(m.logs) > 500 { m.logs = m.logs[1:] }
		m.updateTable()
		return m, waitForActivity(m.logChan)
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m *model) updateTable() {
	rawInput := strings.TrimSpace(m.searchInput.Value())
	query := ""
	isSearch := false
	if strings.HasPrefix(strings.ToLower(rawInput), "search ") {
		parts := strings.SplitN(rawInput, " ", 2)
		if len(parts) == 2 {
			query = strings.ToLower(strings.TrimSpace(parts[1]))
			isSearch = true
		}
	}
	rows := make([]table.Row, 0)
	for _, entry := range m.logs {
		status := "PASSIVE MONITORING"
		if entry.Alert != nil {
			status = fmt.Sprintf("🛡️ DETECTED: %s", entry.Alert.Type)
		}
		if entry.Blocked { status = "🚫 BLOCKED (IPS)" }
		match := !isSearch || query == "" || 
				 strings.Contains(strings.ToLower(entry.ID), query) ||
				 strings.Contains(strings.ToLower(entry.RemoteIP), query) ||
				 strings.Contains(strings.ToLower(status), query)
		if match {
			rows = append(rows, table.Row{entry.ID, entry.Timestamp.Format("15:04:05"), entry.RemoteIP, status, entry.Path})
		}
	}
	m.table.SetRows(rows)
	if !isSearch { m.table.GotoBottom() }
}

func (m model) renderStats() string {
	styleBox := lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(1)
	styleStatLabel := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true)
	styleStatValue := lipgloss.NewStyle().Foreground(m.theme.Primary)
	styleAlert := lipgloss.NewStyle().Foreground(m.theme.Alert).Bold(true)

	uptime := time.Since(m.startTime).Round(time.Second)
	s1 := lipgloss.JoinVertical(lipgloss.Left, styleStatLabel.Render("UPTIME"), styleStatValue.Render(uptime.String()))
	s2 := lipgloss.JoinVertical(lipgloss.Left, styleStatLabel.Render("TOTAL REQUESTS"), styleStatValue.Render(fmt.Sprintf("%d", m.totalRequests)))
	s3 := lipgloss.JoinVertical(lipgloss.Left, styleStatLabel.Render("IPS BLOCKS"), styleAlert.Render(fmt.Sprintf("%d", m.totalBlocks)))
	s4 := lipgloss.JoinVertical(lipgloss.Left, styleStatLabel.Render("LIVE RPS"), styleStatValue.Render(fmt.Sprintf("%d req/s", m.activeRequests)))

	boxWidth := (m.width - 16) / 4
	if boxWidth < 15 { boxWidth = 15 }
	if boxWidth > 25 { boxWidth = 25 }

	row := lipgloss.JoinHorizontal(lipgloss.Top,
		styleBox.Width(boxWidth).Render(s1), lipgloss.NewStyle().Width(1).Render(" "),
		styleBox.Width(boxWidth).Render(s2), lipgloss.NewStyle().Width(1).Render(" "),
		styleBox.Width(boxWidth).Render(s3), lipgloss.NewStyle().Width(1).Render(" "),
		styleBox.Width(boxWidth).Render(s4),
	)
	if m.width < 80 {
		row = lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Top, styleBox.Width(boxWidth).Render(s1), lipgloss.NewStyle().Width(1).Render(" "), styleBox.Width(boxWidth).Render(s2)),
			lipgloss.JoinHorizontal(lipgloss.Top, styleBox.Width(boxWidth).Render(s3), lipgloss.NewStyle().Width(1).Render(" "), styleBox.Width(boxWidth).Render(s4)),
		)
	}
	return lipgloss.PlaceHorizontal(m.width-8, lipgloss.Center, row)
}

func (m model) renderThreatDistribution() string {
	styleStatLabel := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true)
	styleBox := lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(1)
	styleAlert := lipgloss.NewStyle().Foreground(m.theme.Alert).Bold(true)

	var b strings.Builder
	b.WriteString(styleStatLabel.Render("THREAT DISTRIBUTION") + "\n\n")
	type kv struct { Key string; Value int }
	var ss []kv
	for k, v := range m.threatTypes { ss = append(ss, kv{k, v}) }
	sort.Slice(ss, func(i, j int) bool { return ss[i].Value > ss[j].Value })

	if len(ss) == 0 { b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Dim).Render("No threats detected yet.")) }
	for i, kv := range ss {
		if i >= 4 { break }
		percent := 0.0
		if m.totalBlocks > 0 { percent = (float64(kv.Value) / float64(m.totalBlocks)) * 100 }
		barWidth := int(percent / 10)
		bar := styleAlert.Render(strings.Repeat("█", barWidth))
		b.WriteString(fmt.Sprintf("%-18s %s %3.0f%%\n", truncateString(kv.Key, 18), bar, percent))
	}
	distWidth := 45
	if m.width < 110 { distWidth = m.width - 14 }
	return styleBox.Width(distWidth).Height(8).Render(b.String())
}

func (m model) renderActivityChart() string {
	styleStatLabel := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true)
	styleBox := lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(1)
	height := 5
	chartWidth := 60
	if m.width < 110 { chartWidth = m.width - 24 }
	if chartWidth < 20 { chartWidth = 20 }

	var b strings.Builder
	b.WriteString(styleStatLabel.Render("LIVE SECURITY TRAFFIC (60s)") + "\n\n")
	for h := height; h > 0; h-- {
		axisVal := 0
		if m.maxVal > 0 { axisVal = h * (m.maxVal / height) }
		b.WriteString(fmt.Sprintf("%3d ", axisVal))
		visibleHistory := m.history
		if len(m.history) > chartWidth { visibleHistory = m.history[len(m.history)-chartWidth:] }
		for _, s := range visibleHistory {
			safeH, alertH := 0, 0
			if m.maxVal > 0 {
				safeH = (s.safe * height) / m.maxVal
				alertH = (s.alerts * height) / m.maxVal
			}
			if h <= alertH { b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Alert).Render("█"))
			} else if h <= (safeH + alertH) { b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Success).Render("█"))
			} else { b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Dim).Render("·")) }
		}
		b.WriteString("\n")
	}
	return styleBox.Width(chartWidth + 10).Height(8).Render(b.String())
}

func truncateString(s string, l int) string {
	if len(s) <= l { return s }
	if l <= 1 { return "…" }
	return s[:l-1] + "…"
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 { return "Initializing Dashboard..." }
	contentWidth := m.width - 4

	// 0. Top Status Bar (System-like line)
	hostname, _ := os.Hostname()
	statusBarStyle := lipgloss.NewStyle().
		Foreground(m.theme.Text).
		Background(m.theme.Dim).
		Width(contentWidth)
	
	verPart := lipgloss.NewStyle().Foreground(m.theme.Primary).Bold(true).Render(" GUARDIAN v2.0 ")
	hostPart := lipgloss.NewStyle().Faint(true).Render(" " + hostname + " ")
	timePart := time.Now().Format(" 15:04:05 ")
	
	statusBar := statusBarStyle.Render(
		lipgloss.JoinHorizontal(lipgloss.Center,
			verPart,
			lipgloss.NewStyle().Width(contentWidth - lipgloss.Width(verPart) - lipgloss.Width(hostPart) - lipgloss.Width(timePart)).Render(""),
			hostPart,
			timePart,
		),
	)

	// 1. Header Section
	headerStyle := lipgloss.NewStyle().Foreground(m.theme.Primary).Background(m.theme.Secondary).Bold(true).Padding(0, 2).Width(contentWidth).Align(lipgloss.Center)
	modeStr := "IPS (ACTIVE)"
	if m.engine != nil {
		if strings.ToLower(m.engine.Mode) == "ids" { modeStr = "IDS (PASSIVE)" } else if strings.ToLower(m.engine.Mode) == "strict" { modeStr = "STRICT (ACTIVE)" }
	}
	header := headerStyle.Render(fmt.Sprintf("🛡️  GUARDIAN TUI | MODE: %s | THEME: %s", modeStr, strings.ToUpper(m.theme.Name)))

	// 2. Stats Section
	statsRow := m.renderStats()

	// 3. Visualization Section
	var vizRow string
	showCharts := m.height >= 35 || (m.height >= 28 && m.width >= 110)
	if showCharts {
		if m.width >= 110 {
			vizRow = lipgloss.PlaceHorizontal(contentWidth, lipgloss.Center, lipgloss.JoinHorizontal(lipgloss.Top, m.renderActivityChart(), lipgloss.NewStyle().Width(2).Render(" "), m.renderThreatDistribution()))
		} else {
			vizRow = lipgloss.PlaceHorizontal(contentWidth, lipgloss.Center, lipgloss.JoinVertical(lipgloss.Center, m.renderActivityChart(), m.renderThreatDistribution()))
		}
		vizRow += "\n"
	}

	// 4. Command Area
	termStyle := lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(m.theme.Dim).Width(contentWidth - 2).Padding(0, 1)
	var cmdArea string
	if m.searching { cmdArea = termStyle.BorderForeground(m.theme.Primary).Render(m.searchInput.View())
	} else if m.searchInput.Value() != "" {
		cmdArea = termStyle.Render(lipgloss.NewStyle().Foreground(m.theme.Primary).Italic(true).Render("🎯 FILTERED: ") + m.searchInput.Value() + lipgloss.NewStyle().Foreground(m.theme.Dim).Render(" (esc to clear)"))
	} else {
		helpText := "[/] TERMINAL | [search <query>] | [themes/modes set <val>]"
		if m.width > 100 { helpText = "[/] TERMINAL | [search <id/ip/status>] | [themes set <name>] | [modes set <name>] | [tab] AUTOCOMPLETE" }
		cmdArea = termStyle.Render(lipgloss.NewStyle().Foreground(m.theme.Dim).Width(contentWidth - 4).Render(helpText))
	}

	// 5. Main Table Area
	tableBox := lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(0).MarginTop(1).Width(contentWidth).Render(m.table.View())

	// 6. Status Footer
	footerStyle := lipgloss.NewStyle().Bold(true).Padding(0, 1).Width(contentWidth)
	var statusLine string
	if m.lastAlert != "" {
		statusLine = footerStyle.Background(m.theme.Alert).Foreground(m.theme.Text).Render(" 🚨 CRITICAL: " + truncateString(m.lastAlert, contentWidth-10))
	} else {
		statusLine = footerStyle.Background(m.theme.Success).Foreground(lipgloss.Color("#000")).Render(" ✨ MONITORING ACTIVE" + truncateString(" - ALL SYSTEMS NOMINAL", contentWidth-25))
	}

	mainContent := lipgloss.JoinVertical(lipgloss.Left, statusBar, "\n", header, "\n", lipgloss.NewStyle().Padding(0, 2).Render(lipgloss.JoinVertical(lipgloss.Left, statsRow, vizRow, cmdArea, tableBox)), statusLine)
	return lipgloss.NewStyle().Padding(4, 2, 0, 2).Render(mainContent)
}
