package internal

import (
	"github.com/gaissmai/bart"
	"gorm.io/gorm"
)

type DnsManager struct {
	C            ConfigRoot
	Zones        *ZonesType // All zones
	ZonesForward *ZonesType // All forward zones
	ZoneReverse4 *bart.Table[*Zone]
	ZoneReverse6 *bart.Table[*Zone]
	DB           *gorm.DB
}

// Create a manager, that handles the DNS server
func NewDnsManager(p ConfigRoot) (*DnsManager, error) {
	manager := new(DnsManager)
	manager.C = p
	manager.Zones = new(ZonesType)
	manager.ZonesForward = new(ZonesType)
	manager.ZoneReverse4 = new(bart.Table[*Zone])
	manager.ZoneReverse6 = new(bart.Table[*Zone])
	return manager, nil
}
