// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package enums

import "strconv"

func DNSRecordTypeName(qType uint16) string {
	switch qType {
	case DNS_RECORD_TYPE_A:
		return "A"
	case DNS_RECORD_TYPE_AAAA:
		return "AAAA"
	case DNS_RECORD_TYPE_CNAME:
		return "CNAME"
	case DNS_RECORD_TYPE_MX:
		return "MX"
	case DNS_RECORD_TYPE_NS:
		return "NS"
	case DNS_RECORD_TYPE_PTR:
		return "PTR"
	case DNS_RECORD_TYPE_SRV:
		return "SRV"
	case DNS_RECORD_TYPE_SVCB:
		return "SVCB"
	case DNS_RECORD_TYPE_CAA:
		return "CAA"
	case DNS_RECORD_TYPE_NAPTR:
		return "NAPTR"
	case DNS_RECORD_TYPE_SOA:
		return "SOA"
	case DNS_RECORD_TYPE_TXT:
		return "TXT"
	case DNS_RECORD_TYPE_HTTPS:
		return "HTTPS"
	default:
		return "TYPE" + strconv.FormatUint(uint64(qType), 10)
	}
}
