package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pterm/pterm"
)

const (
	browseParent    = ".."
	browseSelectDir = "[ Use this directory ]"
)

// browseForFile navigates directories (starting at the working directory) and
// returns a file the user selects. It only ever touches the entry the user picks
// and never scans on its own — real confinement is left to the OS sandbox the
// binary runs under (e.g. flatpak/firejail granting just the working dir).
func (a *App) browseForFile() (string, error) { return a.browse(false) }

// browseForDir is like browseForFile but returns a directory the user selects.
func (a *App) browseForDir() (string, error) { return a.browse(true) }

func (a *App) browse(pickDir bool) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}

	for {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", fmt.Errorf("read directory %q: %w", dir, err)
		}

		options := make([]string, 0, len(entries)+2)
		paths := make(map[string]string, len(entries))
		if pickDir {
			options = append(options, browseSelectDir)
		}
		options = append(options, browseParent)

		// Directories first, then files (skipped when picking a directory), no dotfiles.
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".") || !entry.IsDir() {
				continue
			}
			label := entry.Name() + "/"
			options = append(options, label)
			paths[label] = filepath.Join(dir, entry.Name())
		}
		if !pickDir {
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".") || entry.IsDir() {
					continue
				}
				options = append(options, entry.Name())
				paths[entry.Name()] = filepath.Join(dir, entry.Name())
			}
		}

		selected, err := a.interactiveSelect.WithMaxHeight(20).WithOptions(options).Show(dir)
		if err != nil {
			return "", err
		}

		switch selected {
		case browseSelectDir:
			return dir, nil
		case browseParent:
			dir = filepath.Dir(dir)
		default:
			dir = paths[selected]
			if info, err := os.Stat(dir); err != nil {
				return "", err
			} else if !info.IsDir() {
				return dir, nil
			}
		}
	}
}

// writeOutput saves data to a file the user chooses via the directory browser.
// Files are written 0600 since they may carry key material.
func (a *App) writeOutput(defaultName string, data []byte) error {
	dir, err := a.browseForDir()
	if err != nil {
		return err
	}
	name, err := a.interactiveText.Show(fmt.Sprintf("Filename [%s]", defaultName))
	if err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		name = defaultName
	}
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // user-selected path, no trust boundary crossed
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			a.log.Error("Failed to close output file", a.log.Args("path", path), a.log.Args("error", err))
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	pterm.Success.Printfln("Wrote %s", path)
	return nil
}
