//go:build windows

package main

import (
	"log"
	"runtime"

	"github.com/energye/systray"
)

// runTray sets up the system-tray icon and menu. It is started in a goroutine
// from startup; systray.Run creates the hidden tray window AND runs the Win32
// message loop (GetMessage/DispatchMessage) on this same goroutine.
//
// On Windows, tray-icon clicks (WM_LBUTTONUP/WM_RBUTTONUP) are delivered only to
// the OS thread that created the window. We therefore pin this goroutine to its
// OS thread for its whole life (never unlock): otherwise the Go scheduler
// migrates it across threads on each blocking GetMessage, GetMessage ends up on
// a thread that doesn't own the tray window, and clicks (left AND right) stop
// arriving — and a right-click TrackPopupMenu firing on the wrong thread can
// hang the loop and freeze the app. systray's own init() LockOSThread only pins
// the main goroutine, not this one, so we must lock here ourselves.
func (a *App) runTray() {
	runtime.LockOSThread()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("tray: recovered: %v", r)
		}
	}()
	systray.Run(a.trayOnReady, func() {})
}

func trayGuard(fn func()) func() {
	return func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("tray: handler recovered: %v", r)
			}
		}()
		fn()
	}
}

func (a *App) trayOnReady() {
	if len(trayIcon) > 0 {
		systray.SetIcon(trayIcon)
	}
	systray.SetTitle("Ultron Firewall")
	systray.SetTooltip("Ultron Firewall — protegendo em segundo plano")

	mOpen := systray.AddMenuItem("Abrir painel", "Mostrar a janela do Ultron")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Encerrar (requer senha)", "Encerra o firewall")

	mOpen.Click(trayGuard(func() { a.ShowWindow() }))
	mQuit.Click(trayGuard(func() { a.trayQuit() }))
	// Left-click on the tray icon reopens the panel.
	systray.SetOnClick(func(_ systray.IMenu) {
		trayGuard(func() { a.ShowWindow() })()
	})
}

// trayQuit quits only when unlocked (QuitApp enforces the master password).
func (a *App) trayQuit() {
	if err := a.QuitApp(); err != nil {
		a.ShowWindow()
		a.toast("Ultron Firewall", `Para encerrar, destrave com a senha master e use "Encerrar" no painel.`)
	}
}
