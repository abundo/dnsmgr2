package internal

// DhcpManager is a placeholder for future DHCP destination support.
type DhcpManager struct {
	P ConfigRoot
}

func NewDhcpManager(p ConfigRoot) (*DhcpManager, error) {
	return &DhcpManager{P: p}, nil
}
