package ui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"bpflite/internal/event"
)

// overlayModal composites a modal string centered over a background string
// using lipgloss v2's Canvas+Layer system for correct ANSI cell compositing.
func overlayModal(modal, bg string, width, height int) string {
	mw := lipgloss.Width(modal)
	mh := lipgloss.Height(modal)
	px := (width - mw) / 2
	py := (height - mh) / 2
	if px < 0 {
		px = 0
	}
	if py < 0 {
		py = 0
	}

	bgLayer := lipgloss.NewLayer(bg)
	modalLayer := lipgloss.NewLayer(modal).X(px).Y(py).Z(1)

	comp := lipgloss.NewCompositor(bgLayer, modalLayer)
	canvas := lipgloss.NewCanvas(width, height)
	comp.Draw(canvas, canvas.Bounds())
	return canvas.Render()
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

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
	ViewOom
	ViewUnlink
	ViewMount
	ViewSetuid
	ViewBpf
	ViewModule
)

type item struct {
	title, desc string
	mode        ViewMode
}

func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.desc }
func (i item) FilterValue() string { return i.title }

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
	dirty          bool

	palette     list.Model
	paletteOpen bool
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
	ti.SetWidth(30)

	items := []list.Item{
		item{title: "All", desc: "View all events simultaneously", mode: ViewAll},
		item{title: "Exec", desc: "Process executions (sys_enter_execve)", mode: ViewExec},
		item{title: "Open", desc: "File openings (sys_enter_openat)", mode: ViewOpen},
		item{title: "Net", desc: "TCP connection state changes", mode: ViewNet},
		item{title: "Signal", desc: "Signals sent (sys_enter_kill)", mode: ViewSignal},
		item{title: "OOM", desc: "Out-of-memory kills (mark_victim)", mode: ViewOom},
		item{title: "Unlink", desc: "File deletions (sys_enter_unlinkat)", mode: ViewUnlink},
		item{title: "Mount", desc: "Filesystem mounts (sys_enter_mount)", mode: ViewMount},
		item{title: "Setuid", desc: "Privilege escalations (sys_enter_setuid)", mode: ViewSetuid},
		item{title: "Bpf", desc: "BPF program loading (sys_enter_bpf)", mode: ViewBpf},
		item{title: "Module", desc: "Kernel module loading (init/finit_module)", mode: ViewModule},
	}
	pal := list.New(items, list.NewDefaultDelegate(), 40, 20)
	pal.Title = "Switch Tracer"
	pal.SetShowHelp(false)
	pal.SetShowStatusBar(false)

	return &UIModel{
		table:          t,
		textInput:      ti,
		palette:        pal,
		events:         make([]interface{}, 0),
		filteredEvents: make([]interface{}, 0),
		viewMode:       ViewAll,
	}
}

func (m *UIModel) Init() tea.Cmd {
	return tickCmd()
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

		pw := msg.Width / 2
		if pw < 40 {
			pw = 40
		}
		if pw > 80 {
			pw = 80
		}
		ph := msg.Height / 2
		if ph < 15 {
			ph = 15
		}
		if ph > 25 {
			ph = 25
		}
		m.palette.SetWidth(pw)
		m.palette.SetHeight(ph)

		return m, nil

	case tickMsg:
		if m.dirty {
			m.updateTable()
			m.dirty = false
		}
		return m, tickCmd()

	case *event.ExecEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.dirty = true
		return m, nil

	case *event.OpenEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.dirty = true
		return m, nil

	case *event.NetEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.dirty = true
		return m, nil

	case *event.SignalEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.dirty = true
		return m, nil

	case *event.OomEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.dirty = true
		return m, nil

	case *event.UnlinkEvent, *event.MountEvent, *event.SetuidEvent, *event.BpfEvent, *event.ModuleEvent:
		m.events = append(m.events, msg)
		if len(m.events) > 1000 {
			m.events = m.events[1:]
		}
		m.dirty = true
		return m, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if !m.filtering && !m.paletteOpen {
				return m, tea.Quit
			}
		case "ctrl+p":
			if !m.filtering {
				m.paletteOpen = !m.paletteOpen
				if m.paletteOpen {
					m.palette.ResetFilter()
				}
				return m, nil
			}
		case "f", "/":
			if !m.filtering && !m.paletteOpen {
				m.filtering = true
				m.textInput.Focus()
				return m, nil
			}
		case "enter":
			if m.filtering {
				m.filtering = false
				m.textInput.Blur()
				m.filterText = m.textInput.Value()
				m.updateTable()
				return m, nil
			} else if m.paletteOpen {
				if i, ok := m.palette.SelectedItem().(item); ok {
					m.viewMode = i.mode
					m.paletteOpen = false
					m.updateTable()
				}
				return m, nil
			}
		case "esc":
			if m.filtering {
				m.filtering = false
				m.textInput.Blur()
				m.filterText = m.textInput.Value()
				m.updateTable()
				return m, nil
			}
			if m.paletteOpen {
				m.paletteOpen = false
				return m, nil
			}
		}
	}

	if m.paletteOpen {
		m.palette, cmd = m.palette.Update(msg)
		cmds = append(cmds, cmd)
	} else if m.filtering {
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
		case *event.OomEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewOom {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.TriggerPid)
			ppidStr = "-"
			commStr = e.TriggerCommString()
			args = fmt.Sprintf("killed %s (PID %d) reclaiming %d pages", e.VictimCommString(), e.VictimPid, e.Pages)
		case *event.UnlinkEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewUnlink {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = "-"
			commStr = e.Comm
			args = fmt.Sprintf("deleted %s", e.Pathname)
		case *event.MountEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewMount {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = "-"
			commStr = e.Comm
			args = fmt.Sprintf("mounted %s on %s", e.DevName, e.DirName)
		case *event.SetuidEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewSetuid {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = "-"
			commStr = e.Comm
			args = fmt.Sprintf("setuid %d", e.Uid)
		case *event.BpfEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewBpf {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = "-"
			commStr = e.Comm
			args = fmt.Sprintf("cmd: %d", e.Cmd)
		case *event.ModuleEvent:
			if m.viewMode != ViewAll && m.viewMode != ViewModule {
				continue
			}
			pidStr = fmt.Sprintf("%d", e.Pid)
			ppidStr = "-"
			commStr = e.Comm
			args = fmt.Sprintf("loaded %s", e.Name)
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

func (m *UIModel) renderBackground() string {
	var b strings.Builder

	boxStyle := baseStyle.
		Width(m.width - 2).
		Height(m.height - 2)

	var content strings.Builder

	// Render Header Title (Current View)
	viewTitle := "ALL EVENTS"
	switch m.viewMode {
	case ViewExec:
		viewTitle = "EXEC"
	case ViewOpen:
		viewTitle = "OPEN"
	case ViewNet:
		viewTitle = "NET"
	case ViewSignal:
		viewTitle = "SIGNAL"
	case ViewOom:
		viewTitle = "OOM"
	case ViewUnlink:
		viewTitle = "UNLINK"
	case ViewMount:
		viewTitle = "MOUNT"
	case ViewSetuid:
		viewTitle = "SETUID"
	case ViewBpf:
		viewTitle = "BPF"
	case ViewModule:
		viewTitle = "MODULE"
	}

	logo := lipgloss.NewStyle().
		Foreground(lipgloss.Color("212")).
		Bold(true).
		MarginRight(2).
		Render("🐝 bpflite")
		
	title := lipgloss.NewStyle().
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Padding(0, 1).
		Render(viewTitle)
		
	info := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		MarginLeft(2).
		Render("• 's' switch • '/' filter • 'q' quit")
		
	headerGroup := lipgloss.JoinHorizontal(lipgloss.Center, logo, title, info)
	
	lineStr := strings.Repeat("─", lipgloss.Width(headerGroup))
	line := lipgloss.NewStyle().
		Foreground(lipgloss.Color("236")).
		Render(lineStr)
		
	fullHeader := lipgloss.PlaceHorizontal(m.width, lipgloss.Center, headerGroup+"\n"+line)

	content.WriteString(fullHeader)
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
		case *event.OomEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true).Render("OOM") + " " + e.TriggerCommString() + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(fmt.Sprintf("Process %s (PID %d) was killed due to Out-Of-Memory, reclaiming %d pages", e.VictimCommString(), e.VictimPid, e.Pages))
		case *event.UnlinkEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("204")).Bold(true).Render("UNLINK") + " " + e.Comm + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(fmt.Sprintf("Process deleted file: %s", e.Pathname))
		case *event.MountEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true).Render("MOUNT") + " " + e.Comm + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(fmt.Sprintf("Mounted %s on %s (fs: %s)", e.DevName, e.DirName, e.FsType))
		case *event.SetuidEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("160")).Bold(true).Render("SETUID") + " " + e.Comm + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(fmt.Sprintf("Changed uid to %d", e.Uid))
		case *event.BpfEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("27")).Bold(true).Render("BPF") + " " + e.Comm + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(fmt.Sprintf("Performed bpf syscall cmd: %d", e.Cmd))
		case *event.ModuleEvent:
			detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("130")).Bold(true).Render("MODULE") + " " + e.Comm + "\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(fmt.Sprintf("Loaded kernel module: %s", e.Name))
		}
	} else {
		detailsText = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("No event selected")
	}

	content.WriteString(detailsStyle.Render(detailsText))
	content.WriteString("\n")

	content.WriteString(helpStyle.Render(" ↑/k up • ↓/j down • Ctrl+P switch tracer • / filter • q quit"))
	content.WriteString("\n")

	b.WriteString(boxStyle.Render(content.String()))
	return b.String()
}

func (m *UIModel) View() tea.View {
	v := func(s string) tea.View {
		view := tea.NewView(s)
		view.AltScreen = true
		return view
	}

	if m.paletteOpen {
		// Render the full background first so events stay visible behind the modal.
		bgStr := m.renderBackground()

		paletteStr := lipgloss.NewStyle().
			Width(50).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("87")).
			BorderBackground(lipgloss.Color("235")).
			Background(lipgloss.Color("235")).
			Padding(1, 2).
			Render(m.palette.View())

		return v(overlayModal(paletteStr, bgStr, m.width, m.height))
	}

	bg := m.renderBackground()

	if m.filtering {
		// Inject filter input into the last line of the background
		lines := strings.Split(bg, "\n")
		if len(lines) > 1 {
			lines[len(lines)-2] = " " + m.textInput.View()
		}
		return v(strings.Join(lines, "\n"))
	}

	return v(bg)
}

