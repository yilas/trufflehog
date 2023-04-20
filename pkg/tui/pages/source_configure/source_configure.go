package source_configure

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/tabs"
)

type SetSourceMsg struct {
	Source string
}

type tab int

const (
	configTab tab = iota
	truffleConfigTab
	runTab
)

func (t tab) String() string {
	return []string{
		"1. Configuration",
		"2. Truffle Configuration",
		"3. Run",
	}[t]
}

type SourceConfigure struct {
	common.Common
	activeTab       tab
	tabs            *tabs.Tabs
	configTabSource string
	tabComponents   []common.Component
}

func (m SourceConfigure) Init() tea.Cmd {
	return m.tabs.Init()
}

func New(c common.Common) *SourceConfigure {
	tb := tabs.New(c, []string{configTab.String(), truffleConfigTab.String(), runTab.String()})
	tabComponents := []common.Component{
		configTab:        NewSourceComponent(c),
		truffleConfigTab: NewTrufflehogComponent(c),
		runTab:           NewRunComponent(c),
	}

	return &SourceConfigure{
		tabs:          tb,
		Common:        c,
		tabComponents: tabComponents,
	}
}

func (m *SourceConfigure) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tabs.ActiveTabMsg:
		m.activeTab = tab(msg)
		t, cmd := m.tabs.Update(msg)
		m.tabs = t.(*tabs.Tabs)

		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case tea.KeyMsg:
		t, cmd := m.tabs.Update(msg)
		m.tabs = t.(*tabs.Tabs)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case SetSourceMsg:
		m.configTabSource = msg.Source

	}

	tab, cmd := m.tabComponents[m.activeTab].Update(msg)
	m.tabComponents[m.activeTab] = tab.(common.Component)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *SourceConfigure) View() string {
	return lipgloss.JoinVertical(lipgloss.Top,
		m.tabs.View(),
		m.tabComponents[m.activeTab].View(),
	)
}

func (m *SourceConfigure) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *SourceConfigure) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
