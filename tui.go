package main

import (
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/creack/pty"
	"golang.org/x/term"
)

type model struct {
	mode string
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
		case "n":
			m.mode = "n"
			return m, nil
		case "p":
			m.mode = "p"
			return m, nil
		}
	}
	return m, nil
}

func (m model) View() string {
	return "-----\n🔒 Dialog: Press Enter to continue... " + m.mode + "\n-----"
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
