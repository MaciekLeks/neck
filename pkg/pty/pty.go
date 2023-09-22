package pty

import (
	"fmt"
	"github.com/MaciekLeks/neck/pkg/common"
	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"strconv"
)

func (m *model) Init() tea.Cmd {
	return textinput.Blink
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	tea.Printf("event\n")
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			close(m.stop)
			return m, tea.Quit
		case tea.KeyUp:
			if m.active == rawView {
				m.raw.MoveUp(1)
			} else {
				m.config.MoveUp(1)
			}
			return m, nil
		case tea.KeyDown:
			if m.active == rawView {
				m.raw.MoveDown(1)
			} else {
				m.config.MoveDown(1)
			}
			return m, nil
		case tea.KeyTab:
			m.changeView()
		case tea.KeyCtrlN:
			return m, nil
		case tea.KeyEnter:
			if m.active == cidrView {
				tea.Printf("Let's go to 1: %s!", m.cidr.Value())
				key, err := common.ParseCidr(m.cidr.Value())
				if err != nil {
					return m, tea.Printf("Value is not a CIDR:%s", m.cidr.Value())
				}
				tea.Printf("Let's go to 2: %s!", m.cidr.Value())
				cidr := m.cidr.Value()
				m.cidr.Reset()
				m.cidr.SetValue("")
				return m, m.updateConfig(cidr, key)
			}
		}
	case tea.WindowSizeMsg:
		m.resize(msg)
	case common.RawEvent:
		if msg.Blocked != 0 {
			//find related cidr and update counter
			for _, cidr := range m.cidrList {
				if cidr.id == msg.LpmVal.Id {
					cidr.count = msg.LpmVal.Counter
				}
			}
			m.config.SetRows(m.cidrList.TeaRows())
		}

		m.raw.SetRows(append(m.raw.Rows(), []string{msg.Command, msg.IP.String(), strconv.Itoa(int(msg.Pid)), strconv.Itoa(int(msg.Uid)), strconv.Itoa(int(msg.Blocked))}))
	case uiCidr:
		m.config.SetRows(append(m.config.Rows(), []string{
			strconv.Itoa(int(msg.id)),
			msg.cidr,
			strconv.FormatUint(msg.count, 10),
		}))
	}

	m.cidr, cmd = m.cidr.Update(msg)
	return m, cmd
}

func (m *model) resize(msg tea.Msg) {
	wsize, ok := msg.(tea.WindowSizeMsg)
	if !ok {
		return
	}
	m.width = wsize.Width
	m.height = wsize.Height
	m.raw.SetWidth(int(float32(m.width) * 0.7))
	m.raw.SetHeight(int(float32(m.height) * 0.8))
	m.config.SetWidth(int(float32(m.width) * 0.3))
	m.config.SetHeight(int(float32(m.height) * 0.8))
	m.ready = ready
}

// updateConfig cidrList and return new uiCidr for tea to be added into the ui
func (m *model) updateConfig(cidr string, key common.Ipv4LpmKey) tea.Cmd {
	return func() tea.Msg {
		ch := make(chan common.CidrResponse)
		defer close(ch)
		m.output <- common.CidrRequestResponse{Key: key, Result: ch}
		res := <-ch
		if res.Error != nil {
			return tea.Printf("Error adding CIDR:%s", res.Error)
		}
		cidr := uiCidr{
			id:    res.Id,
			cidr:  cidr,
			count: res.Counter,
		}
		m.cidrList = append(m.cidrList, &cidr)
		return cidr
	}
}

func (m *model) changeView() {
	if m.active == rawView {
		m.cidr.Reset()
		m.config.Focus()
		m.cidr.Cursor.SetMode(cursor.CursorHide)
		m.cidr.PromptStyle = inputStyle
		m.cidr.TextStyle = inputStyle
		m.active = configView
	} else if m.active == configView {
		m.active = cidrView
		m.cidr.Cursor.SetMode(cursor.CursorBlink)
		m.cidr.PromptStyle = inputFocusedStyle
		m.cidr.TextStyle = inputFocusedStyle
		m.cidr.Focus()
	} else {
		m.raw.Focus()
		m.cidr.Reset()
		m.cidr.Cursor.SetMode(cursor.CursorHide)
		m.cidr.PromptStyle = inputStyle
		m.cidr.TextStyle = inputStyle
		m.active = rawView
	}
}

func (m *model) View() string {
	if m.ready == notReady {
		return "Initializing..."
	}
	var s string
	model := m.currentFocusedModel()
	if m.active == rawView {
		s += lipgloss.JoinVertical(lipgloss.Top, m.cidr.View(), lipgloss.JoinHorizontal(lipgloss.Top, focusedModelStyle.Render(fmt.Sprintf("%4s", m.raw.View())), modelStyle.Render(m.config.View())))
	} else if m.active == configView {
		s += lipgloss.JoinVertical(lipgloss.Top, m.cidr.View(), lipgloss.JoinHorizontal(lipgloss.Top, modelStyle.Render(fmt.Sprintf("%4s", m.raw.View())), focusedModelStyle.Render(m.config.View())))
	} else {
		s += lipgloss.JoinVertical(lipgloss.Top, m.cidr.View(), lipgloss.JoinHorizontal(lipgloss.Top, modelStyle.Render(fmt.Sprintf("%4s", m.raw.View())), modelStyle.Render(m.config.View())))
	}
	if m.active == configView {
		s += helpStyle.Render(fmt.Sprintf("\ntab: focus next • ctrl-n: new %s • ctrl-c: exit\n", model))
	} else if m.active == rawView {
		s += helpStyle.Render(fmt.Sprintf("\ntab: focus next • ctrl-c: exit\n"))
	} else {
		s += helpStyle.Render(fmt.Sprintf("\ntab: focus next • enter: cidr • ctrl-c: exit\n"))
	}

	return s
}

func (m *model) currentFocusedModel() string {
	if m.active == rawView {
		return "raw"
	}
	return "config"
}

var (
	modelStyle        lipgloss.Style
	focusedModelStyle lipgloss.Style
	tableStyle        table.Styles
	helpStyle         lipgloss.Style
	inputFocusedStyle lipgloss.Style
	inputStyle        lipgloss.Style
)

func init() {
	modelStyle = lipgloss.NewStyle().
		Align(lipgloss.Center, lipgloss.Center).
		BorderStyle(lipgloss.HiddenBorder())
	focusedModelStyle = lipgloss.NewStyle().
		Align(lipgloss.Center, lipgloss.Center).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("69"))
	tableStyle = table.DefaultStyles()
	tableStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	tableStyle.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	inputFocusedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	inputStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
}

func newModel(stop chan struct{}, output chan<- common.CidrRequestResponse) *model {
	rawColumns := []table.Column{
		{Title: "Command", Width: 16},
		{Title: "IP", Width: 16},
		{Title: "Pid", Width: 10},
		{Title: "Uid", Width: 10},
		{Title: "Blocked", Width: 8},
	}
	configColumns := []table.Column{
		{Title: "Id", Width: 8},
		{Title: "CIDR", Width: 16},
		{Title: "Count", Width: 10},
	}
	rawData := RawEventList{}
	configData := uiCidrList{}

	rawTable := table.New(
		table.WithColumns(rawColumns),
		table.WithRows(rawData.TeaRows()),
		table.WithFocused(true),
		//table.WithHeight(7),
	)
	rawTable.SetStyles(tableStyle)

	configTable := table.New(
		table.WithColumns(configColumns),
		table.WithRows(configData.TeaRows()),
		table.WithFocused(true),
		//table.WithHeight(7),
	)
	configTable.SetStyles(tableStyle)

	ti := textinput.New()
	ti.Placeholder = "0.0.0.0/0"
	ti.CharLimit = 18
	ti.Width = 18
	ti.Prompt = "CIDR:> "
	ti.PromptStyle = inputFocusedStyle
	ti.TextStyle = inputFocusedStyle

	m := model{active: rawView, raw: rawTable, config: configTable, cidr: ti, stop: stop, output: output}
	return &m
}
func NewPty(stop chan struct{}, output chan<- common.CidrRequestResponse) (*tea.Program, error) {
	m := newModel(stop, output)
	p := tea.NewProgram(m)
	if p == nil {
		return nil, fmt.Errorf("error creating program")
	}
	return p, nil
}
