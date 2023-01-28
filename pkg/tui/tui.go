package tui

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type state int

const (
	showWizardIntro state = iota
	showSourceSelect
)

var (
	appStyle = lipgloss.NewStyle().Padding(1, 2)
)

type model struct {
	state        state
	wizardIntro  wizardIntroModel
	sourceSelect sourceSelectModel
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Always pass WindowSizeMsg to all pages.
	if msg, ok := msg.(tea.WindowSizeMsg); ok {
		m.wizardIntro, _ = update(m.wizardIntro, msg)
		m.sourceSelect, _ = update(m.sourceSelect, msg)
		return m, nil
	}

	var cmd tea.Cmd
	switch m.state {
	case showWizardIntro:
		m.wizardIntro, cmd = update(m.wizardIntro, msg)
		if m.wizardIntro.action != "" {
			m.state = showSourceSelect
		}
		return m, cmd

	case showSourceSelect:
		m.sourceSelect, cmd = update(m.sourceSelect, msg)
		// Potential logic for changing the state goes here. You change the
		// state based on how the update affected the section model.
		return m, cmd

	default:
		return m, nil
	}
}

func update[T tea.Model](m T, msg tea.Msg) (T, tea.Cmd) {
	model, cmd := m.Update(msg)
	return model.(T), cmd
}

func (m model) View() string {
	switch m.state {
	case showWizardIntro:
		return m.wizardIntro.View()
	case showSourceSelect:
		return m.sourceSelect.View()
	default:
		return m.wizardIntro.View()
	}
}

func Run() []string {
	// TODO: Print normal help message.
	p := tea.NewProgram(model{sourceSelect: newSourceSelectModel()})
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
	// TODO: Remove exit when we finish.
	os.Exit(0)
	return nil
}
