package tui

import (
	"fmt"
	"sort"

	"asm-framework/pkg/storage"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/net/publicsuffix"
)

// subEntry holds a subdomain and its pre-built display label.
// Built once at startup per domain bucket; never rebuilt during navigation.
type subEntry struct {
	sub   storage.Subdomain
	label string // plain domain name, no markup
}

// RunTUI launches the interactive database viewer.
func RunTUI(store storage.Storage) error {
	app := tview.NewApplication()

	// Load all subdomains from DB once at startup.
	subdomains, err := store.GetSubdomains()
	if err != nil {
		return err
	}

	// Group into per-root buckets. Within each bucket, live subdomains come
	// first (sorted A-Z), followed by dead ones (sorted A-Z).
	// All sorting happens here — never again during navigation.
	type domainBucket struct {
		entries []subEntry // live first, then dead
		live    int        // count of live entries (for title display)
		dead    int
	}
	domainMap := make(map[string]*domainBucket)

	for _, sub := range subdomains {
		root, err := publicsuffix.EffectiveTLDPlusOne(sub.Domain)
		if err != nil {
			root = sub.Domain
		}
		if domainMap[root] == nil {
			domainMap[root] = &domainBucket{}
		}
		b := domainMap[root]
		e := subEntry{sub: sub, label: sub.Domain}
		if sub.IsAlive {
			b.live++
		} else {
			b.dead++
		}
		b.entries = append(b.entries, e)
	}

	for _, b := range domainMap {
		sort.Slice(b.entries, func(i, j int) bool {
			// live before dead; tie-break alphabetically
			if b.entries[i].sub.IsAlive != b.entries[j].sub.IsAlive {
				return b.entries[i].sub.IsAlive
			}
			return b.entries[i].label < b.entries[j].label
		})
	}

	var rootDomains []string
	for root := range domainMap {
		rootDomains = append(rootDomains, root)
	}
	sort.Strings(rootDomains)

	// ── Widgets ───────────────────────────────────────────────────────────────

	domainList := tview.NewList().ShowSecondaryText(false)
	domainList.SetBorder(true).SetTitle(" Target Domains ")
	domainList.SetSelectedBackgroundColor(tcell.ColorDarkBlue)
	domainList.SetSelectedTextColor(tcell.ColorWhite)

	subList := tview.NewList().ShowSecondaryText(false)
	subList.SetBorder(true).SetTitle(" Subdomains ")
	subList.SetSelectedBackgroundColor(tcell.ColorDarkCyan)
	subList.SetSelectedTextColor(tcell.ColorWhite)

	portTable := tview.NewTable().SetBorders(true)
	portTable.SetBorder(true).SetTitle(" Open Ports ")
	portTable.SetSelectable(true, false)

	vulnTable := tview.NewTable().SetBorders(true)
	vulnTable.SetBorder(true).SetTitle(" Vulnerabilities ")
	vulnTable.SetSelectable(true, false)

	detailsPane := tview.NewTextView().
		SetWrap(true).
		SetWordWrap(true).
		SetDynamicColors(true).
		SetTextColor(tcell.ColorWhite)
	detailsPane.SetBorder(true).SetTitle(" Details ")

	// ── State ─────────────────────────────────────────────────────────────────
	var currentEntries []subEntry
	var currentPorts []storage.Port
	var currentVulns []storage.Vulnerability

	// ── Helpers ───────────────────────────────────────────────────────────────

	// populateSubList is called only when the selected root domain changes.
	// It rebuilds the subList widget from the pre-sorted bucket entries.
	populateSubList := func(b *domainBucket) {
		subList.Clear()
		portTable.Clear()
		vulnTable.Clear()
		detailsPane.Clear()

		currentEntries = b.entries

		for _, e := range currentEntries {
			var label string
			if e.sub.IsAlive {
				label = "[#00ff7f]● " + e.label + "[-]"
			} else {
				label = "[#ff5555]✗ " + e.label + "[-]"
			}
			subList.AddItem(label, "", 0, nil)
		}

		subList.SetTitle(fmt.Sprintf(" Subdomains [%d live · %d dead] ", b.live, b.dead))
	}

	updatePorts := func(index int) {
		portTable.Clear()
		vulnTable.Clear()

		portTable.SetCell(0, 0, tview.NewTableCell("Port").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		portTable.SetCell(0, 1, tview.NewTableCell("Service").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		portTable.SetCell(0, 2, tview.NewTableCell("Version").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		portTable.SetCell(0, 3, tview.NewTableCell("State").SetTextColor(tcell.ColorYellow).SetSelectable(false))

		if len(currentEntries) == 0 || index < 0 || index >= len(currentEntries) {
			return
		}

		ports, err := store.GetPorts(currentEntries[index].sub.ID)
		if err != nil {
			return
		}
		currentPorts = ports

		for i, p := range ports {
			row := i + 1
			portTable.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("%d", p.Number)).SetTextColor(tcell.ColorWhite))
			portTable.SetCell(row, 1, tview.NewTableCell(p.Service).SetTextColor(tcell.ColorWhite))
			portTable.SetCell(row, 2, tview.NewTableCell(p.Version).SetTextColor(tcell.ColorTeal))
			portTable.SetCell(row, 3, tview.NewTableCell(p.State).SetTextColor(tcell.ColorGreen))
		}
	}

	updateVulnerabilities := func(portIndex int) {
		vulnTable.Clear()
		vulnTable.SetCell(0, 0, tview.NewTableCell("ID").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		vulnTable.SetCell(0, 1, tview.NewTableCell("Severity").SetTextColor(tcell.ColorYellow).SetSelectable(false))
		vulnTable.SetCell(0, 2, tview.NewTableCell("Name").SetTextColor(tcell.ColorYellow).SetSelectable(false))

		if len(currentPorts) == 0 || portIndex < 0 || portIndex >= len(currentPorts) {
			return
		}

		vulns, err := store.GetVulnerabilities(currentPorts[portIndex].ID)
		if err != nil {
			return
		}
		currentVulns = vulns

		for i, v := range vulns {
			row := i + 1
			color := tcell.ColorRed
			if v.Severity == "low" {
				color = tcell.ColorGreen
			} else if v.Severity == "medium" {
				color = tcell.ColorYellow
			}
			vulnTable.SetCell(row, 0, tview.NewTableCell(v.TemplateID).SetTextColor(tcell.ColorWhite))
			vulnTable.SetCell(row, 1, tview.NewTableCell(v.Severity).SetTextColor(color))
			vulnTable.SetCell(row, 2, tview.NewTableCell(v.Name).SetTextColor(tcell.ColorWhite))
		}
	}

	// ── Navigation ────────────────────────────────────────────────────────────

	for _, rd := range rootDomains {
		domainList.AddItem(rd, "", 0, nil)
	}

	domainList.SetChangedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		if b := domainMap[mainText]; b != nil {
			populateSubList(b)
			if len(currentEntries) > 0 {
				updatePorts(0)
				updateVulnerabilities(0)
			}
		}
	})

	domainList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Key() == tcell.KeyCtrlC {
			app.Stop()
			return nil
		}
		if event.Key() == tcell.KeyRight || event.Key() == tcell.KeyEnter {
			if subList.GetItemCount() > 0 {
				app.SetFocus(subList)
			}
			return nil
		}
		return event
	})

	subList.SetChangedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		updatePorts(index)
		updateVulnerabilities(0)
	})

	subList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Key() == tcell.KeyCtrlC {
			app.Stop()
			return nil
		}
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

	portTable.SetSelectionChangedFunc(func(row, column int) {
		updateVulnerabilities(row - 1)
		if row > 0 && row-1 < len(currentPorts) {
			p := currentPorts[row-1]
			detailsPane.SetText(fmt.Sprintf("[yellow]Port:[white] %d\n[yellow]Service:[white] %s\n[yellow]Version:[teal] %s\n[yellow]State:[green] %s", p.Number, p.Service, p.Version, p.State))
		} else {
			detailsPane.Clear()
		}
	})

	vulnTable.SetSelectionChangedFunc(func(row, column int) {
		if row > 0 && row-1 < len(currentVulns) {
			v := currentVulns[row-1]
			detailsPane.SetText(fmt.Sprintf("[yellow]Vulnerability:[white] %s\n[yellow]Severity:[white] %s\n[yellow]ID/Template:[white] %s", v.Name, v.Severity, v.TemplateID))
		} else {
			detailsPane.Clear()
		}
	})

	portTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Key() == tcell.KeyCtrlC {
			app.Stop()
			return nil
		}
		if event.Key() == tcell.KeyLeft || event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyBackspace || event.Key() == tcell.KeyBackspace2 {
			app.SetFocus(subList)
			return nil
		}
		if event.Key() == tcell.KeyRight || event.Key() == tcell.KeyEnter {
			if vulnTable.GetRowCount() > 1 {
				app.SetFocus(vulnTable)
				row, _ := vulnTable.GetSelection()
				if row > 0 && row-1 < len(currentVulns) {
					v := currentVulns[row-1]
					detailsPane.SetText(fmt.Sprintf("[yellow]Vulnerability:[white] %s\n[yellow]Severity:[white] %s\n[yellow]ID/Template:[white] %s", v.Name, v.Severity, v.TemplateID))
				}
			}
			return nil
		}
		return event
	})

	vulnTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Key() == tcell.KeyCtrlC {
			app.Stop()
			return nil
		}
		if event.Key() == tcell.KeyLeft || event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyBackspace || event.Key() == tcell.KeyBackspace2 {
			app.SetFocus(portTable)
			row, _ := portTable.GetSelection()
			if row > 0 && row-1 < len(currentPorts) {
				p := currentPorts[row-1]
				detailsPane.SetText(fmt.Sprintf("[yellow]Port:[white] %d\n[yellow]Service:[white] %s\n[yellow]Version:[teal] %s\n[yellow]State:[green] %s", p.Number, p.Service, p.Version, p.State))
			} else {
				detailsPane.Clear()
			}
			return nil
		}
		return event
	})

	// ── Initialise ────────────────────────────────────────────────────────────
	if len(rootDomains) > 0 {
		if b := domainMap[rootDomains[0]]; b != nil {
			populateSubList(b)
			if len(currentEntries) > 0 {
				updatePorts(0)
				updateVulnerabilities(0)
			}
		}
	}

	// ── Layout ────────────────────────────────────────────────────────────────
	topFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(domainList, 0, 1, true).
		AddItem(subList, 0, 2, false).
		AddItem(portTable, 0, 2, false).
		AddItem(vulnTable, 0, 2, false)

	mainFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topFlex, 0, 3, true).
		AddItem(detailsPane, 0, 1, false)

	// Global fallback for quit.
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC || event.Rune() == 'q' {
			app.Stop()
			return nil
		}
		return event
	})

	frame := tview.NewFrame(mainFlex).
		AddText("ASM Database Viewer", true, tview.AlignCenter, tcell.ColorWhite).
		AddText("q/Ctrl+C: Quit | ↑/↓: Navigate | Enter/→: Step In | ←/ESC: Step Back", false, tview.AlignCenter, tcell.ColorGray)

	if err := app.SetRoot(frame, true).EnableMouse(true).Run(); err != nil {
		return err
	}

	return nil
}
