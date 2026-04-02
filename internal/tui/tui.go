package tui

import (
	"fmt"
	"guardiantui/internal/proxy"
	"runtime"
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
	Name       string
	Primary    lipgloss.Color
	Secondary  lipgloss.Color
	Accent     lipgloss.Color
	Alert      lipgloss.Color
	Success    lipgloss.Color
	Text       lipgloss.Color
	Dim        lipgloss.Color
	Background lipgloss.Color
}

var themes = map[string]Theme{
	"cyber": {
		Name:       "Cyber",
		Primary:    lipgloss.Color("#00f2ff"),
		Secondary:  lipgloss.Color("#252a34"),
		Accent:     lipgloss.Color("#08d9d6"),
		Alert:      lipgloss.Color("#ff2e63"),
		Success:    lipgloss.Color("#08ffc8"),
		Text:       lipgloss.Color("#eaeaea"),
		Dim:        lipgloss.Color("#393e46"),
		Background: lipgloss.Color("#1a1a1a"),
	},
	"forest": {
		Name:       "Forest",
		Primary:    lipgloss.Color("#a2d076"),
		Secondary:  lipgloss.Color("#2d3319"),
		Accent:     lipgloss.Color("#6fb98f"),
		Alert:      lipgloss.Color("#e27d60"),
		Success:    lipgloss.Color("#85cdca"),
		Text:       lipgloss.Color("#f1f1f1"),
		Dim:        lipgloss.Color("#4d5d53"),
		Background: lipgloss.Color("#1e241e"),
	},
	"dracula": {
		Name:       "Dracula",
		Primary:    lipgloss.Color("#bd93f9"),
		Secondary:  lipgloss.Color("#282a36"),
		Accent:     lipgloss.Color("#ff79c6"),
		Alert:      lipgloss.Color("#ff5555"),
		Success:    lipgloss.Color("#50fa7b"),
		Text:       lipgloss.Color("#f8f8f2"),
		Dim:        lipgloss.Color("#6272a4"),
		Background: lipgloss.Color("#282a36"),
	},
	"monochrome": {
		Name:       "Monochrome",
		Primary:    lipgloss.Color("#ffffff"),
		Secondary:  lipgloss.Color("#111111"),
		Accent:     lipgloss.Color("#aaaaaa"),
		Alert:      lipgloss.Color("#cccccc"),
		Success:    lipgloss.Color("#eeeeee"),
		Text:       lipgloss.Color("#ffffff"),
		Dim:        lipgloss.Color("#333333"),
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
		{Title: "ID", Width: 6},
		{Title: "TIME", Width: 9},
		{Title: "SOURCE IP", Width: 15},
		{Title: "SECURITY STATUS", Width: 20},
		{Title: "REQUEST PATH", Width: 20},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
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
	ti.Placeholder = "Enter command (search, themes set, modes set, clear, quit)"
	ti.CharLimit = 100
	ti.Width = 60
	ti.Prompt = " ❯ "

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

		// PRECISION CALCULATIONS FOR "WAY BETTER" LOOK
		// Header(1) + Padding(2) + Stats(5) + Charts(10) + Command(3) + Footer(1) = 22 rows reserved
		reservedHeight := 14
		showCharts := m.height >= 35 || (m.height >= 28 && m.width >= 110)
		
		if showCharts {
			if m.width >= 110 {
				reservedHeight += 10
			} else {
				reservedHeight += 18
			}
		}
		
		newHeight := m.height - reservedHeight - 4 // Padding
		if newHeight < 4 { newHeight = 4 }
		m.table.SetHeight(newHeight)

		idW, timeW, ipW, statusW := 8, 10, 16, 30
		if m.width < 100 {
			idW, timeW, ipW, statusW = 6, 9, 15, 20
		}

		totalWidth := m.width - 12
		pathW := totalWidth - idW - timeW - ipW - statusW
		if pathW < 10 { pathW = 10 }

		m.table.SetColumns([]table.Column{
			{Title: "ID", Width: idW},
			{Title: "TIME", Width: timeW},
			{Title: "SOURCE IP", Width: ipW},
			{Title: "SECURITY STATUS", Width: statusW},
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

func (m model) renderStats(width int) string {
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(m.theme.Dim).
		Padding(0, 1).
		Align(lipgloss.Center)

	labelStyle := lipgloss.NewStyle().Foreground(m.theme.Text).Faint(true).Bold(true)
	valueStyle := lipgloss.NewStyle().Foreground(m.theme.Primary).Bold(true)
	alertStyle := lipgloss.NewStyle().Foreground(m.theme.Alert).Bold(true)

	uptime := time.Since(m.startTime).Round(time.Second).String()
	
	cardWidth := (width - 6) / 4
	if cardWidth < 12 { cardWidth = 12 }

	c1 := boxStyle.Width(cardWidth).Render(lipgloss.JoinVertical(lipgloss.Center, labelStyle.Render("UPTIME"), valueStyle.Render(uptime)))
	c2 := boxStyle.Width(cardWidth).Render(lipgloss.JoinVertical(lipgloss.Center, labelStyle.Render("REQUESTS"), valueStyle.Render(fmt.Sprintf("%d", m.totalRequests))))
	c3 := boxStyle.Width(cardWidth).Render(lipgloss.JoinVertical(lipgloss.Center, labelStyle.Render("BLOCKED"), alertStyle.Render(fmt.Sprintf("%d", m.totalBlocks))))
	c4 := boxStyle.Width(cardWidth).Render(lipgloss.JoinVertical(lipgloss.Center, labelStyle.Render("LIVE RPS"), valueStyle.Render(fmt.Sprintf("%d", m.activeRequests))))

	return lipgloss.JoinHorizontal(lipgloss.Top, c1, " ", c2, " ", c3, " ", c4)
}

func (m model) renderThreatDistribution(width int) string {
	styleBox := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(1)
	labelStyle := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true)

	var b strings.Builder
	b.WriteString(labelStyle.Render("🛡️  THREAT VECTORS") + "\n\n")
	
	type kv struct { Key string; Value int }
	var ss []kv
	for k, v := range m.threatTypes { ss = append(ss, kv{k, v}) }
	sort.Slice(ss, func(i, j int) bool { return ss[i].Value > ss[j].Value })

	if len(ss) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Dim).Render("CLEAN TRAFFIC ONLY"))
	}
	for i, kv := range ss {
		if i >= 4 { break }
		percent := 0.0
		if m.totalBlocks > 0 { percent = (float64(kv.Value) / float64(m.totalBlocks)) * 100 }
		barWidth := int((float64(width-20) * percent) / 100)
		if barWidth < 1 && percent > 0 { barWidth = 1 }
		bar := lipgloss.NewStyle().Foreground(m.theme.Alert).Render(strings.Repeat("█", barWidth))
		b.WriteString(fmt.Sprintf("%-14s %s %3.0f%%\n", truncateString(kv.Key, 14), bar, percent))
	}
	return styleBox.Width(width).Height(8).Render(b.String())
}

func (m model) renderActivityChart(width int) string {
	styleBox := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(1)
	labelStyle := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true)

	height := 5
	var b strings.Builder
	b.WriteString(labelStyle.Render("📈 NETWORK ACTIVITY") + "\n\n")
	
	chartAreaWidth := width - 8
	for h := height; h > 0; h-- {
		axisVal := 0
		if m.maxVal > 0 { axisVal = h * (m.maxVal / height) }
		b.WriteString(fmt.Sprintf("%2d ", axisVal))
		
		visibleHistory := m.history
		if len(m.history) > chartAreaWidth { visibleHistory = m.history[len(m.history)-chartAreaWidth:] }
		
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
	return styleBox.Width(width).Height(8).Render(b.String())
}

func truncateString(s string, l int) string {
	if len(s) <= l { return s }
	if l <= 3 { return "..." }
	return s[:l-1] + "…"
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 { return "LOADING MISSION CONTROL..." }
	
	// Set up base styles
	contentWidth := m.width - 8
	
	// 0. SYSTEM STATUS BAR (Topmost)
	statusBarS := lipgloss.NewStyle().
		Background(m.theme.Secondary).
		Foreground(m.theme.Text).
		Bold(true).
		Width(contentWidth)
	
	leftPart := lipgloss.NewStyle().Background(m.theme.Primary).Foreground(lipgloss.Color("#000")).Padding(0, 1).Render(" 🛡️  GUARDIANTUI v2.0 ")
	midPart := lipgloss.NewStyle().Padding(0, 1).Render(fmt.Sprintf("SYSTEM: %s | CPU: %s", strings.ToUpper(runtime.GOOS), strings.ToUpper(runtime.GOARCH)))
	rightPart := lipgloss.NewStyle().Padding(0, 1).Render(time.Now().Format("15:04:05"))
	
	spacer := lipgloss.NewStyle().Width(contentWidth - lipgloss.Width(leftPart) - lipgloss.Width(midPart) - lipgloss.Width(rightPart)).Render("")
	statusBar := statusBarS.Render(lipgloss.JoinHorizontal(lipgloss.Top, leftPart, midPart, spacer, rightPart))

	// 1. METRICS ROW
	metrics := m.renderStats(contentWidth)

	// 2. VISUALIZATION ROW
	var viz string
	showCharts := m.height >= 35 || (m.height >= 28 && m.width >= 110)
	if showCharts {
		if m.width >= 110 {
			chartW := (contentWidth - 2) / 2
			viz = lipgloss.JoinHorizontal(lipgloss.Top, m.renderActivityChart(chartW), " ", m.renderThreatDistribution(chartW))
		} else {
			viz = lipgloss.JoinVertical(lipgloss.Left, m.renderActivityChart(contentWidth), m.renderThreatDistribution(contentWidth))
		}
	}

	// 3. TERMINAL/COMMAND AREA
	termBorder := lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(m.theme.Dim).Width(contentWidth)
	var termContent string
	if m.searching {
		termContent = termBorder.BorderForeground(m.theme.Primary).Render(m.searchInput.View())
	} else if m.searchInput.Value() != "" {
		termContent = termBorder.Render(lipgloss.NewStyle().Foreground(m.theme.Primary).Bold(true).Render(" 🎯 CMD: ") + m.searchInput.Value())
	} else {
		termContent = termBorder.Render(lipgloss.NewStyle().Foreground(m.theme.Dim).Render(" [/] ACTIVATE TERMINAL | TAB TO AUTOCOMPLETE"))
	}

	// 4. LOG TABLE
	tableBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(m.theme.Dim).
		Width(contentWidth).
		Render(m.table.View())

	// 5. FOOTER / ALERTS
	footer := lipgloss.NewStyle().Width(contentWidth).Bold(true).Padding(0, 1)
	var footerOut string
	if m.lastAlert != "" {
		footerOut = footer.Background(m.theme.Alert).Foreground(m.theme.Text).Render(" 🚨 LAST THREAT: " + truncateString(m.lastAlert, contentWidth-20))
	} else {
		modeStr := "ENFORCING (IPS)"
		if m.engine != nil && m.engine.Mode == "ids" { modeStr = "MONITORING (IDS)" }
		footerOut = footer.Background(m.theme.Success).Foreground(lipgloss.Color("#000")).Render(" ✨ STATUS: " + modeStr + " | NO ACTIVE INCIDENTS")
	}

	// Final Assembly with precise vertical spacing
	layout := lipgloss.JoinVertical(lipgloss.Left,
		statusBar,
		"\n",
		metrics,
		"\n",
		viz,
		termContent,
		tableBox,
		footerOut,
	)

	return lipgloss.NewStyle().Padding(2, 4).Render(layout)
}
