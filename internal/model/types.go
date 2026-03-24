package model

import "net"

type Scanner struct {
	Network string
	IP      string
	Port    int
	Conn    net.Conn
}

type ScanResult struct {
	Address string
	Err     error
	ErrType string
	Open    bool
	Service string
	Banner  string
}
