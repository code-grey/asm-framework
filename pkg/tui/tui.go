package tui

import (
	"fmt"
	"sort"

	"asm-framework/pkg/storage"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/net/publicsuffix"
)

// RunTUI launches the interactive database viewer
func RunTUI(store storage.Storage) error {
	app := tview.NewApplication()

	// Load all subdomains from DB
	subdomains, err := store.GetSubdomains()
	if err != nil {
		return err
	}

	// Group subdomains by Root Domain
	domainMap := make(map[string][]storage.Subdomain)
	for _, sub := range subdomains {
		root, err := publicsuffix.EffectiveTLDPlusOne(sub.Domain)
		if err != nil {
			root = sub.Domain // Fallback
		}
		domainMap[root] = append(domainMap[root], sub)
	}

	// Extract and sort root domains
	var rootDomains []string
	for root := range domainMap {
		rootDomains = append(rootDomains, root)
	}
	sort.Strings(rootDomains)

	// Layout Elements
	flex := tview.NewFlex().SetDirection(tview.FlexColumn)

	// 1. Root Domains List
	domainList := tview.NewList().ShowSecondaryText(false)
	domainList.SetBorder(true).SetTitle(" Target Domains ")
	domainList.SetSelectedBackgroundColor(tcell.ColorBlue)

	// 2. Subdomains List
	subList := tview.NewList().ShowSecondaryText(false)
	subList.SetBorder(true).SetTitle(" Subdomains ")
	subList.SetSelectedBackgroundColor(tcell.ColorGreen)

	// 3. Ports Table
	portTable := tview.NewTable().SetBorders(true)
	portTable.SetBorder(true).SetTitle(" Open Ports ")
	portTable.SetSelectable(true, false)

	// State trackers
	var currentSubdomains []storage.Subdomain

	// Update Subdomains based on selected Root Domain
	updateSubdomains := func(rootDomain string) {
		subList.Clear()
		portTable.Clear()
		
		currentSubdomains = domainMap[rootDomain]
		sort.Slice(currentSubdomains, func(i, j int) bool {
			return currentSubdomains[i].Domain < currentSubdomains[j].Domain
		})

		for _, sub := range currentSubdomains {
			subList.AddItem(sub.Domain, "", 0, nil)
		}
	}

	// Update Ports based on selected Subdomain
	updatePorts := func(index int) {
		portTable.Clear()

		portTable.SetCell(0, 0, tview.NewTableCell("Port").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		portTable.SetCell(0, 1, tview.NewTableCell("Service").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		portTable.SetCell(0, 2, tview.NewTableCell("Version").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		portTable.SetCell(0, 3, tview.NewTableCell("State").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		portTable.SetCell(0, 4, tview.NewTableCell("Discovered").SetTextColor(tcell.ColorYellow).SetSelectable(false))

		if len(currentSubdomains) == 0 || index < 0 || index >= len(currentSubdomains) {
			return
		}

		selectedSub := currentSubdomains[index]
		ports, err := store.GetPorts(selectedSub.ID)
		if err != nil {
			return
		}

		for i, p := range ports {
			row := i + 1
			portTable.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("%d", p.Number)).SetTextColor(tcell.ColorWhite))
			portTable.SetCell(row, 1, tview.NewTableCell(p.Service).SetTextColor(tcell.ColorWhite))
			portTable.SetCell(row, 2, tview.NewTableCell(p.Version).SetTextColor(tcell.ColorTeal))
			portTable.SetCell(row, 3, tview.NewTableCell(p.State).SetTextColor(tcell.ColorGreen))
			portTable.SetCell(row, 4, tview.NewTableCell(p.DiscoveredAt.Format("2006-01-02 15:04")).SetTextColor(tcell.ColorGray))
		}
	}

	// Navigation: Domain List
	for _, rd := range rootDomains {
		domainList.AddItem(rd, "", 0, nil)
	}

	domainList.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		updateSubdomains(mainText)
		if len(currentSubdomains) > 0 {
			updatePorts(0)
		}
	})

	domainList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRight || event.Key() == tcell.KeyEnter {
			if subList.GetItemCount() > 0 {
				app.SetFocus(subList)
			}
			return nil
		}
		return event
	})

	// Navigation: Subdomain List
	subList.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		updatePorts(index)
	})

	subList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyLeft || event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyBackspace || event.Key() == tcell.KeyBackspace2 {
			app.SetFocus(domainList)
			return nil
		}
		if event.Key() == tcell.KeyRight || event.Key() == tcell.KeyEnter {
			if portTable.GetRowCount() > 1 {
				app.SetFocus(portTable)
			}
			return nil
		}
		return event
	})

	// Navigation: Port Table
	portTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyLeft || event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyBackspace || event.Key() == tcell.KeyBackspace2 {
			app.SetFocus(subList)
			return nil
		}
		return event
	})

	// Initialize first view
	if len(rootDomains) > 0 {
		updateSubdomains(rootDomains[0])
		if len(currentSubdomains) > 0 {
			updatePorts(0)
		}
	}

	// Layout Setup
	flex.AddItem(domainList, 0, 1, true).
		AddItem(subList, 0, 2, false).
		AddItem(portTable, 0, 2, false)

	// Global Application Input Capture (Fixes the freeze/exit issue)
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC || event.Rune() == 'q' {
			app.Stop()
			return nil
		}
		return event
	})

	// Info Frame
	frame := tview.NewFrame(flex).
		AddText("ASM Database Viewer", true, tview.AlignCenter, tcell.ColorWhite).
		AddText("q / Ctrl+C: Quit | ↑/↓: Navigate | Enter/→: Step In | ←/ESC: Step Back", false, tview.AlignCenter, tcell.ColorGray)

	if err := app.SetRoot(frame, true).EnableMouse(true).Run(); err != nil {
		return err
	}

	return nil
}
