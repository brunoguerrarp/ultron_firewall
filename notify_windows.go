//go:build windows

package main

import (
	"log"
	"runtime"

	toast "git.sr.ht/~jackmordaunt/go-toast/v2"
)

const (
	toastAppID = "UltronFirewall"
	// A stable GUID so Windows groups our notifications under one app identity.
	toastGUID = "{6F3C9A41-7B2E-4C58-9E1D-2A8F0B5C7D34}"
)

type toastMsg struct{ title, body string }

// toastCh feeds the dedicated toast worker. All toast/WinRT COM work happens on
// that one thread — never on the Wails/WebView2 main thread, whose COM
// apartment must not be disturbed (doing so crashes WindowHide).
var toastCh = make(chan toastMsg, 64)

// initToast starts the dedicated toast worker goroutine.
func (a *App) initToast() {
	go a.toastWorker()
}

func (a *App) toastWorker() {
	// Own a dedicated OS thread for the lifetime of the app. WinRT COM
	// (RoInitialize) can then initialise cleanly here, and nothing we do
	// touches the main thread's apartment.
	runtime.LockOSThread()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("toastWorker: recovered: %v", r)
		}
	}()

	if err := toast.SetAppData(toast.AppData{AppID: toastAppID, GUID: toastGUID}); err != nil {
		log.Printf("toast: SetAppData failed: %v", err)
	}
	toast.SetActivationCallback(func(_ string, _ []toast.UserData) {
		defer func() { _ = recover() }()
		a.ShowWindow()
	})

	for m := range toastCh {
		pushToast(m)
	}
}

func pushToast(m toastMsg) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("toast: push recovered: %v", r)
		}
	}()
	n := toast.Notification{
		AppID:               toastAppID,
		Title:               m.title,
		Body:                m.body,
		ActivationArguments: "open",
	}
	if err := n.Push(); err != nil {
		log.Printf("toast: push failed: %v", err)
	}
}

// toast queues a Windows toast notification (shown by the worker thread).
// Clicking it reopens the panel. Safe to call from any goroutine.
func (a *App) toast(title, body string) {
	select {
	case toastCh <- toastMsg{title: title, body: body}:
	default: // queue full: drop rather than block the caller
	}
}
