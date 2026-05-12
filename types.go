package main

type Response struct {
	Verdict  string   `json:"verdict"`
	Intel    Intel    `json:"intel"`
	Identity Identity `json:"identity"`
	Location Location `json:"location"`
}

type Intel struct {
	Risk             string            `json:"risk"`
	Score            uint32            `json:"score"`
	Attribution      string            `json:"attribution,omitempty"`
	TorNode          bool              `json:"tor_node"`
	VPNProxy         bool              `json:"vpn_proxy"`
	IsBlacklisted    bool              `json:"is_blacklisted"`
	IsDatacenter     bool              `json:"is_datacenter"`
	CloudProvider    *CloudProvider    `json:"cloud_provider,omitempty"`
	ResidentialProxy *ResidentialProxy `json:"residential_proxy,omitempty"`

	Activity  string `json:"activity,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	IsScanner bool   `json:"is_scanner,omitempty"`
}

type ResidentialProxy struct {
	Type      string `json:"type"`
	Provider  string `json:"provider"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	DaysSeen  uint32 `json:"days_seen,omitempty"`
	Score     uint32 `json:"proxy_score,omitempty"`
}

type CloudProvider struct {
	Provider string `json:"provider"`
	Region   string `json:"region,omitempty"`
	Service  string `json:"service,omitempty"`
}

type Identity struct {
	IP             string `json:"ip"`
	ConnectionType string `json:"connection_type"`
	ISP            string `json:"isp"`
	Org            string `json:"org"`
	ASN            int    `json:"asn"`
}

type Location struct {
	City        string      `json:"city"`
	Country     string      `json:"country"`
	CountryCode string      `json:"country_code"`
	Coordinates Coordinates `json:"coordinates"`
}

type Coordinates struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type Quota struct {
	Limit          int    `json:"limit"`
	Used           int    `json:"used"`
	Remaining      int    `json:"remaining"`
	GraceTotal     int    `json:"grace_total"`
	GraceRemaining int    `json:"grace_remaining"`
	InGrace        bool   `json:"in_grace"`
	ResetsAt       string `json:"resets_at"`
}
