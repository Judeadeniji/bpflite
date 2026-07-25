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

type UIModel struct {
	table      table.Model
	textInput  textinput.Model
	events     []interface{}
	filtering  bool
	filterText string
	width      int
	height     int
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
		table:     t,
		textInput: ti,
		events:    make([]interface{}, 0),
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

		h := msg.Height - 6
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
	for _, ev := range m.events {
		var pidStr, ppidStr, commStr, args string

		switch e := ev.(type) {
		case *event.ExecEvent:
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = fmt.Sprintf("%d", e.Ppid)
			commStr = e.CommString()
			args = strings.Join(e.ArgvList(), " ")
		case *event.OpenEvent:
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = "-"
			commStr = e.CommString()
			args = e.FilenameString()
		}

		if m.filterText != "" {
			if !strings.Contains(pidStr, m.filterText) && !strings.Contains(strings.ToLower(commStr), strings.ToLower(m.filterText)) {
				continue
			}
		}

		rows = append(rows, table.Row{
			pidStr,
			ppidStr,
			commStr,
			args,
		})
	}
	
	// Keep selection at bottom or current relative pos? Table usually resets if rows change completely.
	// For simplicity, just set rows.
	m.table.SetRows(rows)
	m.table.GotoBottom()
}

func (m *UIModel) View() string {
	var b strings.Builder

	boxStyle := baseStyle.Copy().
		Width(m.width - 2).
		Height(m.height - 2)

	// We'll render the table and the footer inside this box.
	var content strings.Builder
	content.WriteString(m.table.View() + "\n")
	
	if m.filtering {
		content.WriteString(m.textInput.View() + "\n")
	} else {
		content.WriteString(helpStyle.Render(" ↑/k up • ↓/j down • / filter • q quit") + "\n")
	}

	b.WriteString(boxStyle.Render(content.String()))

	return b.String()
}
