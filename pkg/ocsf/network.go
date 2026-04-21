package ocsf

import "fmt"

// NetworkActivity (OCSF class_uid 4001).
type NetworkActivity struct {
	Metadata    Metadata          `json:"metadata"`
	ClassUID    ClassID           `json:"class_uid"`
	ClassName   string            `json:"class_name"`
	ActivityID  NetActivityID     `json:"activity_id"`
	TypeUID     uint64            `json:"type_uid"`
	Severity    Severity          `json:"severity_id"`
	SeverityStr string            `json:"severity,omitempty"`
	Time        TimeOCSF          `json:"time"`
	Device      Device            `json:"device"`
	Actor       Actor             `json:"actor"`
	Connection  NetConnectionInfo `json:"connection_info"`
	SrcEndpoint NetEndpoint       `json:"src_endpoint"`
	DstEndpoint NetEndpoint       `json:"dst_endpoint"`
	BytesOut    uint64            `json:"traffic.bytes_out,omitempty"`
	BytesIn     uint64            `json:"traffic.bytes_in,omitempty"`
}

type NetActivityID uint8

const (
	NetActivityUnknown  NetActivityID = 0
	NetActivityOpen     NetActivityID = 1  // connect
	NetActivityClose    NetActivityID = 2
	NetActivityReset    NetActivityID = 3
	NetActivityFail     NetActivityID = 4
	NetActivityRefuse   NetActivityID = 5
	NetActivityTraffic  NetActivityID = 6
	NetActivityListen   NetActivityID = 7
	NetActivityOther    NetActivityID = 99
)

type NetConnectionInfo struct {
	Protocol  string `json:"protocol_name,omitempty"` // tcp, udp, icmp
	ProtoNum  uint8  `json:"protocol_num,omitempty"`
	Direction string `json:"direction,omitempty"`     // inbound, outbound, lateral
	DirID     uint8  `json:"direction_id,omitempty"`
}

type NetEndpoint struct {
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
}

func (n *NetworkActivity) ClassID() ClassID { return ClassNetworkActivity }

func (n *NetworkActivity) Validate() error {
	if n.ClassUID != ClassNetworkActivity {
		return fmt.Errorf("%w: class_uid %d != %d", ErrInvalidEvent, n.ClassUID, ClassNetworkActivity)
	}
	if n.ActivityID == NetActivityUnknown {
		return fmt.Errorf("%w: activity_id required", ErrInvalidEvent)
	}
	if n.Time == 0 {
		return fmt.Errorf("%w: time required", ErrInvalidEvent)
	}
	if n.Connection.Protocol == "" {
		return fmt.Errorf("%w: connection_info.protocol_name required", ErrInvalidEvent)
	}
	return nil
}

// DnsActivity (OCSF class_uid 4003).
type DnsActivity struct {
	Metadata    Metadata      `json:"metadata"`
	ClassUID    ClassID       `json:"class_uid"`
	ClassName   string        `json:"class_name"`
	ActivityID  DnsActivityID `json:"activity_id"`
	TypeUID     uint64        `json:"type_uid"`
	Severity    Severity      `json:"severity_id"`
	SeverityStr string        `json:"severity,omitempty"`
	Time        TimeOCSF      `json:"time"`
	Device      Device        `json:"device"`
	Actor       Actor         `json:"actor"`
	Query       DnsQuery      `json:"query"`
	Answers     []DnsAnswer   `json:"answers,omitempty"`
	RCode       string        `json:"rcode,omitempty"`
	RCodeID     uint16        `json:"rcode_id,omitempty"`
}

type DnsActivityID uint8

const (
	DnsActivityUnknown  DnsActivityID = 0
	DnsActivityQuery    DnsActivityID = 1
	DnsActivityResponse DnsActivityID = 2
	DnsActivityTraffic  DnsActivityID = 6
	DnsActivityOther    DnsActivityID = 99
)

type DnsQuery struct {
	Name    string `json:"hostname,omitempty"`
	Type    string `json:"type,omitempty"`
	Class   string `json:"class,omitempty"`
}

type DnsAnswer struct {
	RData string `json:"rdata,omitempty"`
	Type  string `json:"type,omitempty"`
	TTL   uint32 `json:"ttl,omitempty"`
	Class string `json:"class,omitempty"`
}

func (d *DnsActivity) ClassID() ClassID { return ClassDnsActivity }

func (d *DnsActivity) Validate() error {
	if d.ClassUID != ClassDnsActivity {
		return fmt.Errorf("%w: class_uid %d != %d", ErrInvalidEvent, d.ClassUID, ClassDnsActivity)
	}
	if d.ActivityID == DnsActivityUnknown {
		return fmt.Errorf("%w: activity_id required", ErrInvalidEvent)
	}
	if d.Time == 0 {
		return fmt.Errorf("%w: time required", ErrInvalidEvent)
	}
	if d.Query.Name == "" {
		return fmt.Errorf("%w: query.hostname required", ErrInvalidEvent)
	}
	return nil
}
