package main

import (
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/creack/pty"
	"golang.org/x/term"
)

type model struct {
	prompt      string
	affirmative string
	negative    string

	selection bool

	selectedStyle   lipgloss.Style
	unselectedStyle lipgloss.Style
	promptStyle     lipgloss.Style
	borderStyle     lipgloss.Style
}

func DefaultModel() model {
	return model{
		prompt:          "Press Enter to continue...",
		affirmative:     "Yes",
		negative:        "No",
		selection:       true,
		selectedStyle:   lipgloss.NewStyle().Background(lipgloss.Color("212")).Foreground(lipgloss.Color("230")).Padding(0, 3).Margin(0, 1),
		unselectedStyle: lipgloss.NewStyle().Background(lipgloss.Color("235")).Foreground(lipgloss.Color("254")).Padding(0, 3).Margin(0, 1),
		promptStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("#7571F9")).Bold(true),
		borderStyle:     lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#7571F9")).Padding(1, 2),
	}
}

func (model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyEnter {
			return m, tea.Quit
		}
		switch msg.String() {
		case "y":
			m.selection = true
			return m, nil
		case "n":
			m.selection = false
			return m, nil
		case "up", "down", "left", "right", "h", "j", "k", "l":
			m.selection = !m.selection
			return m, nil
		}
	}
	return m, nil
}

func (m model) View() string {
	var aff, neg string
	if m.selection {
		aff = m.selectedStyle.Render(m.affirmative)
		neg = m.unselectedStyle.Render(m.negative)
	} else {
		aff = m.unselectedStyle.Render(m.affirmative)
		neg = m.selectedStyle.Render(m.negative)
	}

	return m.borderStyle.Render(lipgloss.JoinVertical(
		lipgloss.Left,
		m.promptStyle.Render(m.prompt)+"\n",
		lipgloss.JoinHorizontal(lipgloss.Left, aff, neg),
	))
}

func setPtySize(ptyFile *os.File, width, height int) error {
	return pty.Setsize(ptyFile, &pty.Winsize{
		Rows: uint16(height),
		Cols: uint16(width),
	})
}

func getTerminalSize() (int, int, error) {
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 0, 0, err
	}
	return width, height, nil
}
