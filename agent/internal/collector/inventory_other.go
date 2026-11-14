//go:build !windows

package collector

// windowsInventory gibt es nur unter Windows; nil lässt Collect den Linux-Weg gehen.
var windowsInventory func() ([]byte, error)
