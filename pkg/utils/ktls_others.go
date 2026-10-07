//go:build !(linux || freebsd)

package utils

import eTLS "gitlab.com/go-extension/tls"

func ETLSKernelOptions(_, _ bool) eTLS.KernelOptions {
	return eTLS.KernelOptions{}
}
