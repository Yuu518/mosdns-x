//go:build linux || freebsd

package utils

import eTLS "gitlab.com/go-extension/tls"

func ETLSKernelOptions(tx, rx bool) eTLS.KernelOptions {
	return eTLS.KernelOptions{TX: tx, RX: rx}
}
