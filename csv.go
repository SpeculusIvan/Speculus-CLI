package main

import "strconv"

var csvHeader = []string{
	"ip", "verdict", "risk", "score", "attribution",
	"tor_node", "vpn_proxy", "is_blacklisted", "is_datacenter", "is_scanner",
	"activity", "first_seen", "last_seen",
	"cloud_provider", "cloud_region", "cloud_service",
	"residential_proxy_type", "residential_proxy_provider",
	"residential_proxy_first_seen", "residential_proxy_last_seen",
	"residential_proxy_days_seen", "residential_proxy_score",
	"connection_type", "isp", "org", "asn",
	"city", "country", "country_code", "lat", "lon",
}

func responseToRow(r Response) []string {
	row := []string{
		r.Identity.IP,
		r.Verdict,
		r.Intel.Risk,
		strconv.FormatUint(uint64(r.Intel.Score), 10),
		r.Intel.Attribution,
		strconv.FormatBool(r.Intel.TorNode),
		strconv.FormatBool(r.Intel.VPNProxy),
		strconv.FormatBool(r.Intel.IsBlacklisted),
		strconv.FormatBool(r.Intel.IsDatacenter),
		strconv.FormatBool(r.Intel.IsScanner),
		r.Intel.Activity,
		r.Intel.FirstSeen,
		r.Intel.LastSeen,
	}

	if cp := r.Intel.CloudProvider; cp != nil {
		row = append(row, cp.Provider, cp.Region, cp.Service)
	} else {
		row = append(row, "", "", "")
	}

	if rp := r.Intel.ResidentialProxy; rp != nil {
		row = append(row,
			rp.Type, rp.Provider, rp.FirstSeen, rp.LastSeen,
			strconv.FormatUint(uint64(rp.DaysSeen), 10),
			strconv.FormatUint(uint64(rp.Score), 10),
		)
	} else {
		row = append(row, "", "", "", "", "", "")
	}

	row = append(row,
		r.Identity.ConnectionType,
		r.Identity.ISP,
		r.Identity.Org,
		strconv.Itoa(r.Identity.ASN),
		r.Location.City,
		r.Location.Country,
		r.Location.CountryCode,
		strconv.FormatFloat(r.Location.Coordinates.Lat, 'f', -1, 64),
		strconv.FormatFloat(r.Location.Coordinates.Lon, 'f', -1, 64),
	)
	return row
}
