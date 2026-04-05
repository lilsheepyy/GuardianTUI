package tui

import (
	"fmt"
	"guardiantui/internal/proxy"
	"guardiantui/internal/scanner/utils"
	"runtime"
	"sort"
	"strconv"
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
	"strict": {
		Name:       "Strict Alert",
		Primary:    lipgloss.Color("#ff0000"),
		Secondary:  lipgloss.Color("#200000"),
		Accent:     lipgloss.Color("#ff4d4d"),
		Alert:      lipgloss.Color("#ffffff"),
		Success:    lipgloss.Color("#ff9999"),
		Text:       lipgloss.Color("#ffe5e5"),
		Dim:        lipgloss.Color("#660000"),
		Background: lipgloss.Color("#100000"),
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
	userTheme      string // Store user preference to restore after leaving strict mode
	theme          Theme
	suggestion     string
	suggIdx        int
	view           string // main, detail, config
	selectedLog    *proxy.LogEntry
	configFocus    int
	configInputs   []textinput.Model
	configLabels   []string

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
	mTheme := themes["cyber"]
	if t, ok := themes[strings.ToLower(themeName)]; ok {
		mTheme = t
	}

	columns := []table.Column{
		{Title: "ID", Width: 6},
		{Title: "TIME", Width: 9},
		{Title: "SOURCE IP", Width: 15},
		{Title: "SECURITY STATUS", Width: 20},
		{Title: "REQUEST PATH", Width: 20},
	}

	t := table.New(table.WithColumns(columns), table.WithFocused(true), table.WithHeight(10))

	// Initialize config inputs
	labels := []string{"System Mode (ips/ids/strict)", "Max Scan Size (bytes)", "Probing Window (sec)", "Probing Threshold", "Spam Threshold", "Ghost Shield (on/off)", "Shield Difficulty (1-8)", "Honeypots (on/off)"}
	inputs := make([]textinput.Model, len(labels))
	for i := range inputs {
		inputs[i] = textinput.New()
		inputs[i].Prompt = " > "
		inputs[i].CharLimit = 32
	}

	// Fill initial values if engine exists
	if engine != nil && engine.Config != nil {
		inputs[0].SetValue(engine.Mode)
		inputs[1].SetValue(fmt.Sprintf("%d", engine.Config.Engine.MaxScanSize))
		inputs[2].SetValue(fmt.Sprintf("%d", engine.Config.Engine.ProbingWindow))
		inputs[3].SetValue(fmt.Sprintf("%d", engine.Config.Engine.ProbingThreshold))
		inputs[4].SetValue(fmt.Sprintf("%d", engine.Config.Engine.SpamThreshold))
		powVal := "off"; if engine.Config.Engine.PoWEnabled { powVal = "on" }
		inputs[5].SetValue(powVal)
		inputs[6].SetValue(fmt.Sprintf("%d", engine.Config.Engine.PoWDifficulty))
		hpVal := "off"; if engine.HoneypotsEnabled { hpVal = "on" }
		inputs[7].SetValue(hpVal)
	}

	return model{
		table:        t,
		logChan:      logChan,
		engine:       engine,
		logs:         make([]proxy.LogEntry, 0),
		searchInput:  textinput.New(),
		history:      make([]stats, 60),
		maxVal:       10,
		threatTypes:  make(map[string]int),
		startTime:    time.Now(),
		userTheme:    strings.ToLower(themeName),
		theme:        mTheme,
		suggIdx:      -1,
		view:         "main",
		configInputs: inputs,
		configLabels: labels,
	}
}

func (m model) Init() tea.Cmd {
	m.searchInput.Placeholder = "Enter command..."
	m.searchInput.CharLimit = 100
	m.searchInput.Width = 60
	m.searchInput.Prompt = " ❯ "
	return tea.Batch(waitForActivity(m.logChan), tickEverySecond())
}

func tickEverySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func waitForActivity(c chan proxy.LogEntry) tea.Cmd {
	return func() tea.Msg { return logMsg(<-c) }
}

type logMsg proxy.LogEntry

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// DYNAMIC MODE-THEME SYNC
	if m.engine != nil {
		if m.engine.Mode == "strict" && m.theme.Name != "Strict Alert" {
			m.theme = themes["strict"]
			m.applyTableStyles()
		} else if m.engine.Mode != "strict" && m.theme.Name == "Strict Alert" {
			m.theme = themes[m.userTheme]
			if m.theme.Name == "" { m.theme = themes["cyber"] }
			m.applyTableStyles()
		}
	}

	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		reservedHeight := 13
		showCharts := m.height >= 35 || (m.height >= 28 && m.width >= 110)
		if showCharts {
			if m.width >= 110 { reservedHeight += 9 } else { reservedHeight += 17 }
		}
		newHeight := m.height - reservedHeight
		if newHeight < 4 { newHeight = 4 }
		m.table.SetHeight(newHeight)

		idW, timeW, ipW, statusW := 8, 10, 16, 30
		if m.width < 100 { idW, timeW, ipW, statusW = 6, 9, 15, 20 }
		totalWidth := m.width - 10
		pathW := totalWidth - idW - timeW - ipW - statusW
		if pathW < 10 { pathW = 10 }
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
			if s.safe+s.alerts > m.maxVal { m.maxVal = s.safe + s.alerts }
		}
		return m, tickEverySecond()

	case tea.KeyMsg:
		if m.view == "detail" {
			switch msg.String() {
			case "esc", "backspace", "q":
				m.view = "main"
			}
			return m, nil
		}

		if m.view == "config" {
			switch msg.String() {
			case "esc":
				m.view = "main"
				return m, nil
			case "tab", "down":
				m.configInputs[m.configFocus].Blur()
				m.configFocus = (m.configFocus + 1) % len(m.configInputs)
				m.configInputs[m.configFocus].Focus()
			case "shift+tab", "up":
				m.configInputs[m.configFocus].Blur()
				m.configFocus--
				if m.configFocus < 0 { m.configFocus = len(m.configInputs) - 1 }
				m.configInputs[m.configFocus].Focus()
			case "enter":
				m.saveConfigField(m.configFocus)
			default:
				var cmd tea.Cmd
				m.configInputs[m.configFocus], cmd = m.configInputs[m.configFocus].Update(msg)
				return m, cmd
			}
			return m, nil
		}

		if m.searching {
			switch msg.String() {
			case "tab":
				val := strings.ToLower(m.searchInput.Value())
				themeList := []string{"cyber", "forest", "dracula", "monochrome"}
				modeList := []string{"ips", "ids", "strict"}
				baseCmds := []string{"search ", "themes set ", "modes set ", "shield set ", "honeypots set ", "clear", "quit"}
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
				if strings.HasPrefix(val, "shield set ") {
					shieldOpts := []string{"on", "off"}
					m.suggIdx = (m.suggIdx + 1) % len(shieldOpts)
					m.searchInput.SetValue("shield set " + shieldOpts[m.suggIdx])
					m.searchInput.SetCursor(len(m.searchInput.Value()))
					return m, nil
				}
				if strings.HasPrefix(val, "honeypots set ") {
					hpOpts := []string{"on", "off"}
					m.suggIdx = (m.suggIdx + 1) % len(hpOpts)
					m.searchInput.SetValue("honeypots set " + hpOpts[m.suggIdx])
					m.searchInput.SetCursor(len(m.searchInput.Value()))
					return m, nil
				}
				matched := false
				for _, bCmd := range baseCmds {
					if strings.HasPrefix(bCmd, val) && val != bCmd {
						m.searchInput.SetValue(bCmd); m.searchInput.SetCursor(len(bCmd))
						matched = true; break
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
							m.userTheme = newThemeName
							if m.engine.Mode != "strict" {
								m.theme = newTheme
								m.applyTableStyles()
							}
						}
					}
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
				} else if strings.HasPrefix(strings.ToLower(val), "shield set ") {
					parts := strings.Split(val, " ")
					if len(parts) >= 3 {
						choice := strings.ToLower(parts[2])
						if m.engine != nil {
							if choice == "on" {
								m.engine.PoWForce = true
								if m.engine.PoW == nil {
									m.engine.PoW = proxy.NewPoWSystem(4, "")
								}
							} else if choice == "off" {
								m.engine.PoWForce = false
							}
						}
					}
				} else if strings.HasPrefix(strings.ToLower(val), "honeypots set ") {
					parts := strings.Split(val, " ")
					if len(parts) >= 3 {
						choice := strings.ToLower(parts[2])
						if m.engine != nil {
							if choice == "on" {
								m.engine.HoneypotsEnabled = true
							} else if choice == "off" {
								m.engine.HoneypotsEnabled = false
							}
						}
					}
				} else if strings.EqualFold(val, "clear") {
					m.searchInput.SetValue("")
				} else if strings.EqualFold(val, "quit") {
					return m, tea.Quit
				}
				m.searching = false
				m.searchInput.Blur()
				m.table.Focus()
				m.updateTable()
				return m, nil
			case "esc":
				m.searching = false; m.searchInput.Blur(); m.table.Focus(); m.updateTable(); return m, nil
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
			m.searchInput.SetValue("") // Clear previous command
			m.suggIdx = -1             // Reset autocomplete
			m.searchInput.Focus()
			return m, nil
		case "c":
			m.view = "config"
			m.configFocus = 0
			m.configInputs[m.configFocus].Focus()
			return m, nil
		case "b":
			if len(m.table.Rows()) > 0 {
				row := m.table.SelectedRow()
				ip := row[2]
				id := row[0]
				if ip != "" && ip != "INTERNAL" {
					if m.engine != nil {
						fp := ""
						logEntry := m.findLogByID(id)
						if logEntry != nil {
							fp = logEntry.Fingerprint
						}
						m.engine.BlockPersistent(ip, fp)
						m.lastAlert = "🛡️ IP & FP MANUALLY BLOCKED: " + ip
						m.totalBlocks++
						m.updateTable()
					}
				}
			}
		case "w":
			if len(m.table.Rows()) > 0 {
				id := m.table.SelectedRow()[0]
				if m.engine != nil {
					logEntry := m.findLogByID(id)
					if logEntry != nil && logEntry.Fingerprint != "" {
						m.engine.WhitelistFingerprintPersistent(logEntry.Fingerprint)
						m.lastAlert = "✨ FP WHITELISTED: " + logEntry.Fingerprint
						m.updateTable()
					}
				}
			}
		case "enter":
			if len(m.table.Rows()) > 0 {
				id := m.table.SelectedRow()[0]
				m.selectedLog = m.findLogByID(id)
				if m.selectedLog != nil {
					m.view = "detail"
				}
			}
		case "esc": m.searchInput.SetValue(""); m.updateTable(); return m, nil
		}

	case logMsg:
		entry := proxy.LogEntry(msg)
		m.totalRequests++
		if entry.Alert != nil || entry.Blocked {
			m.current.alerts++; m.totalBlocks++
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

func (m *model) applyTableStyles() {
	s := table.DefaultStyles()
	s.Header = s.Header.BorderForeground(m.theme.Dim).Foreground(m.theme.Primary).Bold(true)
	s.Selected = s.Selected.Foreground(m.theme.Text).Background(m.theme.Accent)
	m.table.SetStyles(s)
}

func (m model) findLogByID(id string) *proxy.LogEntry {
	for i := range m.logs {
		if m.logs[i].ID == id {
			return &m.logs[i]
		}
	}
	return nil
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
		if entry.Alert != nil { status = fmt.Sprintf("🛡️ DETECTED: %s", entry.Alert.Type) }
		if entry.Blocked { status = "🚫 BLOCKED (IPS)" }
		match := !isSearch || query == "" || strings.Contains(strings.ToLower(entry.ID), query) || strings.Contains(strings.ToLower(entry.RemoteIP), query) || strings.Contains(strings.ToLower(status), query)
		if match { rows = append(rows, table.Row{entry.ID, entry.Timestamp.Format("15:04:05"), entry.RemoteIP, status, entry.Path}) }
	}
	m.table.SetRows(rows)
	if !isSearch { m.table.GotoBottom() }
}

func (m model) renderStats(width int) string {
	isStrict := m.engine != nil && m.engine.Mode == "strict"
	border := lipgloss.RoundedBorder()
	if isStrict { border = lipgloss.DoubleBorder() }

	boxStyle := lipgloss.NewStyle().Border(border).BorderForeground(m.theme.Dim).Padding(0, 1).Align(lipgloss.Center)
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
	isStrict := m.engine != nil && m.engine.Mode == "strict"
	border := lipgloss.RoundedBorder()
	if isStrict { border = lipgloss.DoubleBorder() }

	styleBox := lipgloss.NewStyle().Border(border).BorderForeground(m.theme.Dim).Padding(1)
	labelStyle := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true).Faint(true)

	var b strings.Builder
	title := "[ THREAT VECTORS ]"
	if isStrict { title = "🚨 [ CRITICAL THREAT INTELLIGENCE ] 🚨" }
	b.WriteString(labelStyle.Render(title) + "\n\n")
	
	type kv struct { Key string; Value int }
	var ss []kv
	for k, v := range m.threatTypes { ss = append(ss, kv{k, v}) }
	sort.Slice(ss, func(i, j int) bool { return ss[i].Value > ss[j].Value })

	if len(ss) == 0 { b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Dim).Render("CLEAN TRAFFIC")) }
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
	isStrict := m.engine != nil && m.engine.Mode == "strict"
	border := lipgloss.RoundedBorder()
	if isStrict { border = lipgloss.DoubleBorder() }

	styleBox := lipgloss.NewStyle().Border(border).BorderForeground(m.theme.Dim).Padding(1)
	labelStyle := lipgloss.NewStyle().Foreground(m.theme.Text).Bold(true).Faint(true)

	height := 5
	var b strings.Builder
	title := "[ NETWORK ACTIVITY ]"
	if isStrict { title = "[ ACTIVE ATTACK SURFACE ]" }
	b.WriteString(labelStyle.Render(title) + "\n\n")
	
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
				safeH, alertH = (s.safe * height) / m.maxVal, (s.alerts * height) / m.maxVal
			}
			if h <= alertH { b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Alert).Render("█"))
			} else if h <= (safeH + alertH) { b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Success).Render("█"))
			} else { b.WriteString(lipgloss.NewStyle().Foreground(m.theme.Dim).Render("·")) }
		}
		b.WriteString("\n")
	}
	return styleBox.Width(width).Height(8).Render(b.String())
}

func (m *model) saveConfigField(idx int) {
	if m.engine == nil || m.engine.Config == nil { return }
	val := strings.TrimSpace(m.configInputs[idx].Value())
	
	switch idx {
	case 0: // Mode
		m.engine.Mode = val
	case 1: // Max Scan Size
		if i, err := strconv.Atoi(val); err == nil { m.engine.Config.Engine.MaxScanSize = i }
	case 2: // Probing Window
		if i, err := strconv.Atoi(val); err == nil { m.engine.Config.Engine.ProbingWindow = i }
	case 3: // Probing Threshold
		if i, err := strconv.Atoi(val); err == nil { m.engine.Config.Engine.ProbingThreshold = i }
	case 4: // Spam Threshold
		if i, err := strconv.Atoi(val); err == nil { m.engine.Config.Engine.SpamThreshold = i }
	case 5: // PoW Enabled
		m.engine.Config.Engine.PoWEnabled = (val == "on" || val == "true")
	case 6: // PoW Difficulty
		if i, err := strconv.Atoi(val); err == nil { m.engine.Config.Engine.PoWDifficulty = i }
	case 7: // Honeypots
		m.engine.HoneypotsEnabled = (val == "on" || val == "true")
	}

	if m.engine.ConfigPath != "" {
		m.engine.Config.Save(m.engine.ConfigPath)
	}
}

func (m model) renderDetail(width, height int) string {
	if m.selectedLog == nil { return "NO LOG SELECTED" }
	l := m.selectedLog
	
	headerStyle := lipgloss.NewStyle().Foreground(m.theme.Primary).Bold(true).Underline(true)
	labelStyle := lipgloss.NewStyle().Foreground(m.theme.Text).Faint(true).Width(15)
	valueStyle := lipgloss.NewStyle().Foreground(m.theme.Text)
	boxStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(0, 1).Width(width - 4)

	// Section 1: General Info
	generalInfo := lipgloss.JoinVertical(lipgloss.Left,
		headerStyle.Render("EVENT IDENTIFICATION"),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Incident ID:"), valueStyle.Render(l.ID)),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Timestamp:"), valueStyle.Render(l.Timestamp.Format(time.RFC1123))),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Source IP:"), valueStyle.Render(l.RemoteIP)),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Fingerprint:"), valueStyle.Render(l.Fingerprint)),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Method:"), valueStyle.Render(l.Method)),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Path:"), valueStyle.Render(l.Path)),
	)

	// Section 2: Security Status
	statusColor := m.theme.Success
	statusText := "ALLOWED / CLEAN"
	if l.Blocked {
		statusColor = m.theme.Alert
		statusText = "BLOCKED / THREAT"
	}
	
	securityInfo := lipgloss.JoinVertical(lipgloss.Left,
		headerStyle.Render("SECURITY ANALYSIS"),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Status:"), lipgloss.NewStyle().Foreground(statusColor).Bold(true).Render(statusText)),
	)
	if l.Alert != nil {
		securityInfo = lipgloss.JoinVertical(lipgloss.Left, securityInfo,
			lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Threat Type:"), valueStyle.Render(l.Alert.Type)),
			lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Pattern:"), valueStyle.Render(l.Alert.Pattern)),
		)
	}

	// Section 3: Headers
	var headStr strings.Builder
	for k, v := range l.FullHeaders {
		headStr.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	headersInfo := headerStyle.Render("HTTP HEADERS") + "\n" + lipgloss.NewStyle().Foreground(m.theme.Dim).Render(headStr.String())

	// Section 4: Payloads
	rawPayload := headerStyle.Render("RAW PAYLOAD") + "\n" + valueStyle.Render(l.Payload)
	normPayload := headerStyle.Render("DE-OBFUSCATED PAYLOAD") + "\n" + lipgloss.NewStyle().Foreground(m.theme.Accent).Render(utils.Normalize(l.Payload))

	content := lipgloss.JoinVertical(lipgloss.Left,
		boxStyle.Render(generalInfo),
		boxStyle.Render(securityInfo),
		boxStyle.Render(headersInfo),
		boxStyle.Render(rawPayload),
		boxStyle.Render(normPayload),
	)

	title := lipgloss.NewStyle().Background(m.theme.Primary).Foreground(lipgloss.Color("#000")).Padding(0, 2).Bold(true).Render(" 🔍 DEEP INCIDENT INSPECTOR ")
	footer := lipgloss.NewStyle().Foreground(m.theme.Dim).Render(" [esc/backspace] RETURN TO DASHBOARD")
	
	return lipgloss.NewStyle().Padding(1, 2).Render(lipgloss.JoinVertical(lipgloss.Left, title, content, footer))
}

func (m model) renderConfig(width, height int) string {
	headerStyle := lipgloss.NewStyle().Foreground(m.theme.Primary).Bold(true).Padding(0, 1)
	boxStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(m.theme.Dim).Padding(1, 2).Width(width - 10)
	
	activeLabelStyle := lipgloss.NewStyle().Foreground(m.theme.Accent).Bold(true)
	inactiveLabelStyle := lipgloss.NewStyle().Foreground(m.theme.Text).Faint(true)

	var fields []string
	for i := range m.configInputs {
		label := m.configLabels[i]
		input := m.configInputs[i]
		
		if i == m.configFocus {
			input.PromptStyle = lipgloss.NewStyle().Foreground(m.theme.Accent)
			fields = append(fields, activeLabelStyle.Render("▶ "+label)+"\n"+input.View())
		} else {
			input.PromptStyle = lipgloss.NewStyle().Foreground(m.theme.Dim)
			fields = append(fields, inactiveLabelStyle.Render("  "+label)+"\n"+input.View())
		}
	}

	content := lipgloss.JoinVertical(lipgloss.Left, fields...)
	
	title := headerStyle.Background(m.theme.Primary).Foreground(lipgloss.Color("#000")).Render(" ⚙️  INTERACTIVE CONFIGURATION EDITOR ")
	footer := lipgloss.NewStyle().Foreground(m.theme.Dim).Padding(1, 0).Render(" [tab/shift+tab] NAVIGATE | [enter] APPLY & SAVE | [esc] RETURN ")

	return lipgloss.NewStyle().Padding(2, 4).Render(lipgloss.JoinVertical(lipgloss.Left, title, boxStyle.Render(content), footer))
}

func truncateString(s string, l int) string {
	if len(s) <= l { return s }
	if l <= 3 { return "..." }
	return s[:l-1] + "…"
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 { return "LOADING MISSION CONTROL..." }
	
	switch m.view {
	case "detail":
		return m.renderDetail(m.width, m.height)
	case "config":
		return m.renderConfig(m.width, m.height)
	}

	contentWidth := m.width - 8
	isStrict := m.engine != nil && m.engine.Mode == "strict"

	// 0. SYSTEM STATUS BAR
	statusBarS := lipgloss.NewStyle().Background(m.theme.Secondary).Foreground(m.theme.Text).Bold(true).Width(contentWidth)
	brandColor := m.theme.Primary
	if isStrict { brandColor = lipgloss.Color("#ffffff") }
	
	leftPart := lipgloss.NewStyle().Background(brandColor).Foreground(lipgloss.Color("#000")).Padding(0, 1).Render(" 🛡️  GUARDIANTUI v2.0 ")
	midPart := lipgloss.NewStyle().Padding(0, 1).Render(fmt.Sprintf("SYSTEM: %s | ARCH: %s", strings.ToUpper(runtime.GOOS), strings.ToUpper(runtime.GOARCH)))
	rightPart := lipgloss.NewStyle().Padding(0, 1).Render(time.Now().Format("15:04:05"))
	spacer := lipgloss.NewStyle().Width(contentWidth - lipgloss.Width(leftPart) - lipgloss.Width(midPart) - lipgloss.Width(rightPart)).Render("")
	statusBar := statusBarS.Render(lipgloss.JoinHorizontal(lipgloss.Top, leftPart, midPart, spacer, rightPart))

	// 1. METRICS
	metrics := m.renderStats(contentWidth)

	// 2. VISUALIZATION (Layout Shift in Strict mode)
	var viz string
	showCharts := m.height >= 35 || (m.height >= 28 && m.width >= 110)
	if showCharts {
		chartW := (contentWidth - 2) / 2
		c1, c2 := m.renderActivityChart(chartW), m.renderThreatDistribution(chartW)
		if isStrict && m.width >= 110 {
			// In Strict mode, swap positions to prioritize threat vectors on the left
			viz = lipgloss.JoinHorizontal(lipgloss.Top, c2, " ", c1)
		} else if m.width >= 110 {
			viz = lipgloss.JoinHorizontal(lipgloss.Top, c1, " ", c2)
		} else {
			viz = lipgloss.JoinVertical(lipgloss.Left, c1, c2)
		}
	}

	// 3. TERMINAL
	termBorder := lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(m.theme.Dim).Width(contentWidth).Padding(0, 1)
	var termContent string
	if m.searching {
		termContent = termBorder.BorderForeground(m.theme.Primary).Render(m.searchInput.View())
	} else if m.searchInput.Value() != "" {
		termContent = termBorder.Render(lipgloss.NewStyle().Foreground(m.theme.Primary).Bold(true).Render(" 🎯 CMD: ") + m.searchInput.Value() + lipgloss.NewStyle().Foreground(m.theme.Dim).Render(" (esc to clear)"))
	} else {
		helpText := "[/] SEARCH | [c] CONFIG | [b] BLOCK | [w] WHITELIST | [Enter] DETAILS | [q] QUIT"
		if m.width > 100 { helpText = "[/] SEARCH LOGS | [c] SYSTEM CONFIG | [b] BLOCK IP | [w] WHITELIST FP | [Enter] DETAILS | [q] QUIT | [shield set <on/off>]" }
		termContent = termBorder.Render(lipgloss.NewStyle().Foreground(m.theme.Dim).Width(contentWidth - 4).Render(helpText))
	}

	// 4. LOG TABLE
	tableBorder := lipgloss.RoundedBorder()
	if isStrict { tableBorder = lipgloss.DoubleBorder() }
	tableBox := lipgloss.NewStyle().Border(tableBorder).BorderForeground(m.theme.Dim).Width(contentWidth).Render(m.table.View())

	// 5. FOOTER
	footer := lipgloss.NewStyle().Width(contentWidth).Bold(true).Padding(0, 1)
	var footerOut string
	if m.lastAlert != "" {
		footerOut = footer.Background(m.theme.Alert).Foreground(m.theme.Text).Render(" 🚨 LAST THREAT: " + truncateString(m.lastAlert, contentWidth-20))
	} else {
		modeStr := "ENFORCING (IPS)"
		if isStrict { modeStr = "AGGRESSIVE DEFENSE (STRICT)" } else if m.engine != nil && m.engine.Mode == "ids" { modeStr = "MONITORING (IDS)" }
		footerOut = footer.Background(m.theme.Success).Foreground(lipgloss.Color("#000")).Render(" ✨ STATUS: " + modeStr + " | ALL SYSTEMS NOMINAL")
	}

	layout := lipgloss.JoinVertical(lipgloss.Left, statusBar, metrics, viz, termContent, tableBox, footerOut)
	return lipgloss.NewStyle().Padding(2, 4, 0, 4).Render(layout)
}
