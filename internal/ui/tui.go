package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"bpflite/internal/event"
)

var (
	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240"))
	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

type ViewMode int

const (
	ViewAll ViewMode = iota
	ViewExec
	ViewOpen
	ViewNet
	ViewSignal
)

type UIModel struct {
	table          table.Model
	textInput      textinput.Model
	events         []interface{}
	filteredEvents []interface{}
	filtering      bool
	filterText     string
	viewMode       ViewMode
	width          int
	height         int
}

func NewUIModel() *UIModel {
	columns := []table.Column{
		{Title: "PID", Width: 8},
		{Title: "PPID", Width: 8},
		{Title: "COMM", Width: 15},
		{Title: "ARGS", Width: 50},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows([]table.Row{}),
		table.WithFocused(true),
		table.WithHeight(20),
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
	ti.Placeholder = "Filter by COMM or PID..."
	ti.CharLimit = 50
	ti.Width = 30

	return &UIModel{
		table:          t,
		textInput:      ti,
		events:         make([]interface{}, 0),
		filteredEvents: make([]interface{}, 0),
		viewMode:       ViewAll,
	}
}

func (m *UIModel) Init() tea.Cmd {
	return nil
}

func (m *UIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		h := msg.Height - 13
		if h < 5 {
			h = 5
		}
		m.table.SetHeight(h)
		m.table.SetWidth(msg.Width - 4)

		argsW := msg.Width - 40
		if argsW < 10 {
			argsW = 10
		}
		m.table.SetColumns([]table.Column{
			{Title: "PID", Width: 8},
			{Title: "PPID", Width: 8},
			{Title: "COMM", Width: 15},
			{Title: "ARGS", Width: argsW},
		})

		return m, nil

	case *event.ExecEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.updateTable()
		return m, nil

	case *event.OpenEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.updateTable()
		return m, nil

	case *event.NetEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.updateTable()
		return m, nil

	case *event.SignalEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.updateTable()
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if !m.filtering {
				return m, tea.Quit
			}
		case "f", "/":
			if !m.filtering {
				m.filtering = true
				m.textInput.Focus()
				return m, textinput.Blink
			}
		case "tab":
			if !m.filtering {
				m.viewMode = (m.viewMode + 1) % 5
				m.updateTable()
				return m, nil
			}
		case "1", "2", "3", "4", "5":
			if !m.filtering {
				m.viewMode = ViewMode(msg.String()[0] - '1')
				m.updateTable()
				return m, nil
			}
		case "enter", "esc":
			if m.filtering {
				m.filtering = false
				m.textInput.Blur()
				m.filterText = m.textInput.Value()
				m.updateTable()
				return m, nil
			}
		}
	}

	if m.filtering {
		m.textInput, cmd = m.textInput.Update(msg)
		cmds = append(cmds, cmd)
		m.filterText = m.textInput.Value()
		m.updateTable()
	} else {
		m.table, cmd = m.table.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *UIModel) updateTable() {
	var rows []table.Row
	var filtered []interface{}
	for _, ev := range m.events {
		var pidStr, ppidStr, commStr, args string

		switch e := ev.(type) {
		case *event.ExecEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewExec {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = fmt.Sprintf("%d", e.Ppid)
			commStr = e.CommString()
			args = strings.Join(e.ArgvList(), " ")
		case *event.OpenEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewOpen {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = "-"
			commStr = e.CommString()
			args = e.FilenameString()
		case *event.NetEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewNet {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = "-"
			commStr = e.CommString()
			saddr := fmt.Sprintf("%d.%d.%d.%d", e.Saddr[0], e.Saddr[1], e.Saddr[2], e.Saddr[3])
			daddr := fmt.Sprintf("%d.%d.%d.%d", e.Daddr[0], e.Daddr[1], e.Daddr[2], e.Daddr[3])
			args = fmt.Sprintf("%s:%d -> %s:%d (%s -> %s)", saddr, e.Sport, daddr, e.Dport, e.OldStateString(), e.NewStateString())
		case *event.SignalEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewSignal {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = "-"
			commStr = e.CommString()
			args = fmt.Sprintf("sent SIG %d to PID %d", e.Sig, e.Tpid)
		}

		if m.filterText != "" {
			if !strings.Contains(pidStr, m.filterText) && !strings.Contains(strings.ToLower(commStr), strings.ToLower(m.filterText)) {
				continue
			}
		}

		filtered = append(filtered, ev)
		rows = append(rows, table.Row{
			pidStr,
			ppidStr,
			commStr,
			args,
		})
	}

	m.filteredEvents = filtered

	// Remember if we were at the bottom
	atBottom := m.table.Cursor() == len(m.table.Rows())-1 || m.table.Cursor() == 0

	m.table.SetRows(rows)

	if atBottom {
		m.table.GotoBottom()
	}
}

func (m *UIModel) View() string {
	var b strings.Builder

	boxStyle := baseStyle.Copy().
		Width(m.width - 2).
		Height(m.height - 2)

	// We'll render the table and the footer inside this box.
	var content strings.Builder

	// Render Tabs
	tabNames := []string{"1:All", "2:Exec", "3:Open", "4:Net", "5:Signal"}
	activeTabStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Padding(0, 1)
	inactiveTabStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	var renderedTabs []string
	for i, name := range tabNames {
		if ViewMode(i) == m.viewMode {
			renderedTabs = append(renderedTabs, activeTabStyle.Render(name))
		} else {
			renderedTabs = append(renderedTabs, inactiveTabStyle.Render(name))
		}
	}
	content.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...))
	content.WriteString("\n\n")

	content.WriteString(m.table.View())
	content.WriteString("\n")

	detailsStyle := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), true, false, false, false).
		BorderForeground(lipgloss.Color("240")).
		Width(m.width-4).
		Height(4).
		Padding(0, 1)

	var detailsText string
	if len(m.filteredEvents) > 0 && m.table.Cursor() >= 0 && m.table.Cursor() < len(m.filteredEvents) {
		ev := m.filteredEvents[m.table.Cursor()]
		switch e := ev.(type) {
		case *event.ExecEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Bold(true).Render("EXEC") + " " + e.CommString() + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(strings.Join(e.ArgvList(), " "))
		case *event.OpenEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("119")).Bold(true).Render("OPEN") + " " + e.CommString() + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(e.FilenameString())
		case *event.NetEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("213")).Bold(true).Render("NET") + " " + e.CommString() + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(e.HumanDescription())
		case *event.SignalEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("202")).Bold(true).Render("SIGNAL") + " " + e.CommString() + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(fmt.Sprintf("Process %s (PID %d) sent signal %d to target PID %d", e.CommString(), e.Pid, e.Sig, e.Tpid))
		}
	} else {
		detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("No event selected")
	}

	content.WriteString(detailsStyle.Render(detailsText))
	content.WriteString("\n")

	if m.filtering {
		content.WriteString(m.textInput.View())
		content.WriteString("\n")
	} else {
		content.WriteString(helpStyle.Render(" ↑/k up • ↓/j down • Tab switch mode • / filter • q quit"))
		content.WriteString("\n")
	}

	b.WriteString(boxStyle.Render(content.String()))

	return b.String()
}
