/*
   OxiRush
   Copyright 2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! The values of the layouts of clause 8.2 that their figures alone do not say: written
//! by hand from the clauses, which give the conditions of their fields.

use alloc::vec::Vec;
use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;
use crate::check::{Check, Deviation};
use crate::ie::{Codec, listed_value};
use crate::macros::{pfcp_bits, pfcp_layout};
use crate::octets::Octets;
use crate::enums::*;
use crate::values::*;

// ── Flags, then the fields that they announce ──────────────────────────────

pfcp_layout! {
    /// SDF Filter (§8.2.5). The (S)RTP Multiplexed Media Identification Information,
    /// which SMMII announces, is kept as its octets.
    pub struct SdfFilter "8.2.5" {
        flags(u8) { smmii "SMMII": 6, bid "BID": 5, fl "FL": 4, spi "SPI": 3, ttc "TTC": 2, fd "FD": 1 }
        spare_octet "Spare octet": Spare if true,
        flow_description "Flow Description": Lv16 if fd,
        tos_traffic_class "ToS Traffic Class": u16 if ttc,
        security_parameter_index "Security Parameter Index": u32 if spi,
        flow_label "Flow Label": U24 if fl,
        sdf_filter_id "SDF Filter ID": u32 if bid,
        rtp_multiplexed_media "(S)RTP Multiplexed Media Identification Information": Counted<Lv16> if smmii,
    }
}

pfcp_layout! {
    /// Redirect Information (§8.2.20): the Redirect Address Type of Table 8.2.20-1 (0 IPv4,
    /// 1 IPv6, 2 URL, 3 SIP URI, 4 IPv4 and IPv6, 5 Port, 6 IPv4 and Port, 7 IPv6 and
    /// Port, 8 IPv4 and IPv6 and Port), the addresses and the port.
    pub struct RedirectInformation "8.2.20" {
        flags(u8) { redirect_address_type "Redirect Address Type": 1 / 4 as RedirectAddressType }
        redirect_server_address "Redirect Server Address": Lv16 if true,
        other_redirect_server_address "Other Redirect Server Address": Lv16 if matches!(redirect_address_type.value(), 4 | 8),
        redirect_port "Redirect Port": u16 if (5..=8).contains(&redirect_address_type.value()),
    }
}

pfcp_layout! {
    /// Downlink Data Service Information (§8.2.27): the Paging Policy Indication value and
    /// the QFI each in its octet, with its two spare bits.
    pub struct DownlinkDataServiceInformation "8.2.27" {
        flags(u8) { dlpsi "DLPSI": 3, qfii "QFII": 2, ppi "PPI": 1 }
        paging_policy_indication "Paging Policy Indication value": u8 if ppi,
        qfi "QFI": u8 if qfii,
        dl_data_packets_size "DL Data Packets Size": u16 if dlpsi,
    }
}

pfcp_layout! {
    /// PFD contents (§8.2.39). The additional flow descriptions, URLs and domain names are
    /// kept as the octets of their lists.
    pub struct PfdContents "8.2.39" {
        flags(u8) { adnp "ADNP": 8, aurl "AURL": 7, afd "AFD": 6, dnp "DNP": 5, cp "CP": 4, dn "DN": 3, url "URL": 2, fd "FD": 1 }
        spare_octet "Spare octet": Spare if true,
        flow_description "Flow Description": Lv16 if fd,
        url_field "URL field": Lv16 if url,
        domain_name "Domain Name": Lv16 if dn,
        custom_pfd_content "Custom PFD Content": Lv16 if cp,
        domain_name_protocol "Domain Name Protocol": Lv16 if dnp,
        additional_flow_description "Additional Flow Description": Lv16 if afd,
        additional_url "Additional URL": Lv16 if aurl,
        additional_domain_name_and_protocol "Additional Domain Name and Domain Name Protocol": Lv16 if adnp,
    }
}

pfcp_layout! {
    /// Flow Information (§8.2.61): the Flow Direction of Table 8.2.61-1 and the flow.
    pub struct FlowInformation "8.2.61" {
        flags(u8) { flow_direction "Flow Direction": 1 / 3 as FlowDirection }
        flow_description "Flow Description": Lv16 if true,
    }
}

pfcp_layout! {
    /// Packet Rate (§8.2.63): each rate after its time unit (Table 8.2.63.1), in the octet
    /// of the unit with its spare bits.
    pub struct PacketRate "8.2.63" {
        flags(u8) { aprc "APRC": 3, dlpr "DLPR": 2, ulpr "ULPR": 1 }
        uplink_time_unit "Uplink Time Unit": TimeUnit if ulpr,
        maximum_uplink_packet_rate "Maximum Uplink Packet Rate": u16 if ulpr,
        downlink_time_unit "Downlink Time Unit": TimeUnit if dlpr,
        maximum_downlink_packet_rate "Maximum Downlink Packet Rate": u16 if dlpr,
        additional_uplink_time_unit "Additional Uplink Time Unit": TimeUnit if aprc && ulpr,
        additional_maximum_uplink_packet_rate "Additional Maximum Uplink Packet Rate": u16 if aprc && ulpr,
        additional_downlink_time_unit "Additional Downlink Time Unit": TimeUnit if aprc && dlpr,
        additional_maximum_downlink_packet_rate "Additional Maximum Downlink Packet Rate": u16 if aprc && dlpr,
    }
}

pfcp_layout! {
    /// Header Enrichment (§8.2.67): the Header Type of Table 8.2.67-1, the name and the
    /// value of the header field.
    pub struct HeaderEnrichment "8.2.67" {
        flags(u8) { header_type "Header Type": 1 / 5 as HeaderType }
        header_field_name "Header Field Name": Lv8 if true,
        header_field_value "Header Field Value": Lv8 if true,
    }
}

pfcp_layout! {
    /// Failed Rule ID (§8.2.80): the Rule ID Type of Table 8.2.80-1 and the rule ID, of the
    /// length of its type.
    pub struct FailedRuleId "8.2.80" {
        flags(u8) { rule_id_type "Rule ID Type": 1 / 5 as RuleIdType }
        rule_id_value "Rule ID value": Rest if true,
    }
}

pfcp_layout! {
    /// Time Quota Mechanism (§8.2.81): the Base Time Interval Type of Table 8.2.81-1 and the
    /// interval, in seconds.
    pub struct TimeQuotaMechanism "8.2.81" {
        flags(u8) { btit "BTIT": 1 / 2 as BaseTimeIntervalType }
        base_time_interval "Base Time Interval": u32 if true,
    }
}

pfcp_layout! {
    /// MAC address (§8.2.93).
    pub struct MacAddress "8.2.93" {
        flags(u8) { udes "UDES": 4, usou "USOU": 3, dest "DEST": 2, sour "SOUR": 1 }
        source_mac_address "Source MAC address value": Mac if sour,
        destination_mac_address "Destination MAC address value": Mac if dest,
        upper_source_mac_address "Upper Source MAC address value": Mac if usou,
        upper_destination_mac_address "Upper Destination MAC address value": Mac if udes,
    }
}

pfcp_layout! {
    /// CP PFCP Entity IP Address (§8.2.135).
    pub struct CpPfcpEntityIpAddress "8.2.135" {
        flags(u8) { v4 "V4": 2, v6 "V6": 1 }
        ipv4_address "IPv4 address": Ipv4Addr if v4,
        ipv6_address "IPv6 address": Ipv6Addr if v6,
    }
}

pfcp_layout! {
    /// Source IP Address (§8.2.138).
    pub struct SourceIpAddress "8.2.138" {
        flags(u8) { mpl "MPL": 3, v4 "V4": 2, v6 "V6": 1 }
        ipv4_address "IPv4 address": Ipv4Addr if v4,
        ipv6_address "IPv6 address": Ipv6Addr if v6,
        mask_prefix_length "mask/prefix length": u8 if mpl,
    }
}

pfcp_layout! {
    /// Packet Rate Status (§8.2.139).
    pub struct PacketRateStatus "8.2.139" {
        flags(u8) { apr "APR": 3, dl "DL": 2, ul "UL": 1 }
        remaining_uplink_packets "Number of Remaining Uplink Packets Allowed": u16 if ul,
        remaining_additional_uplink_packets "Number of Remaining Additional Uplink Packets Allowed": u16 if apr && ul,
        remaining_downlink_packets "Number of Remaining Downlink Packets Allowed": u16 if dl,
        remaining_additional_downlink_packets "Number of Remaining Additional Downlink Packets Allowed": u16 if apr && dl,
        rate_control_status_validity_time "Rate Control Status Validity Time": u64 if ul || dl,
    }
}

pfcp_layout! {
    /// PMF Control Information (§8.2.156): its flags, then, with PQPM, the number of QFIs and the QFIs,
    /// kept as their octets.
    pub struct PmfControlInformation "8.2.156" {
        flags(u8) { pqpm "PQPM": 3, drtti "DRTTI": 2, pmfi "PMFI": 1 }
        qfis "value of QFI": Counted<u8> if pqpm,
    }
}

pfcp_layout! {
    /// MPTCP Address Information (§8.2.157).
    pub struct MptcpAddressInformation "8.2.157" {
        flags(u8) { v6 "V6": 2, v4 "V4": 1 }
        mptcp_proxy_type "MPTCP Proxy Type": u8 if true,
        mptcp_proxy_port "MPTCP Proxy Port": u16 if true,
        mptcp_proxy_ipv4_address "MPTCP Proxy IPv4 Address": Ipv4Addr if v4,
        mptcp_proxy_ipv6_address "MPTCP Proxy IPv6 Address": Ipv6Addr if v6,
    }
}

pfcp_layout! {
    /// Link-Specific Multipath IP Address (§8.2.158). The figure gives the IPv6 address for
    /// non-3GPP access four octets; it is an IPv6 address, of sixteen.
    pub struct LinkSpecificMultipathIpAddress "8.2.158" {
        flags(u8) { nv6 "NV6": 4, nv4 "NV4": 3, v6 "V6": 2, v4 "V4": 1 }
        ipv4_for_3gpp_access "Link-Specific Multipath IPv4 Address for 3GPP Access": Ipv4Addr if v4,
        ipv6_for_3gpp_access "Link-Specific Multipath IPv6 Address for 3GPP Access": Ipv6Addr if v6,
        ipv4_for_non_3gpp_access "Link-Specific Multipath IPv4 Address for Non-3GPP Access": Ipv4Addr if nv4,
        ipv6_for_non_3gpp_access "Link-Specific Multipath IPv6 Address for Non-3GPP Access": Ipv6Addr if nv6,
    }
}

pfcp_layout! {
    /// PMF Address Information (§8.2.159).
    pub struct PmfAddressInformation "8.2.159" {
        flags(u8) { mac "MAC": 3, v6 "V6": 2, v4 "V4": 1 }
        pmf_ipv4_address "PMF IPv4 Address": Ipv4Addr if v4,
        pmf_ipv6_address "PMF IPv6 Address": Ipv6Addr if v6,
        pmf_port_for_3gpp_access "PMF Port for 3GPP Access": u16 if v4 || v6,
        pmf_port_for_non_3gpp_access "PMF Port for Non-3GPP Access": u16 if v4 || v6,
        pmf_mac_address_for_3gpp_access "PMF MAC Address for 3GPP Access": Mac if mac,
        pmf_mac_address_for_non_3gpp_access "PMF MAC Address for Non-3GPP Access": Mac if mac,
    }
}

pfcp_layout! {
    /// IP Address and Port number Replacement (§8.2.200).
    pub struct IpAddressAndPortNumberReplacement "8.2.200" {
        flags(u8) {
            umn6rs "UMN6RS": 7, spn "SPN": 6, sipv6 "SIPV6": 5, sipv4 "SIPV4": 4,
            dpn "DPN": 3, dipv6 "DIPV6": 2, dipv4 "DIPV4": 1,
        }
        destination_ipv4_address "Destination IPv4 Address": Ipv4Addr if dipv4,
        destination_ipv6_address "Destination IPv6 Address": Ipv6Addr if dipv6,
        destination_port_number "Destination Port Number": u16 if dpn,
        source_ipv4_address "Source IPv4 Address": Ipv4Addr if sipv4,
        source_ipv6_address "Source IPv6 Address": Ipv6Addr if sipv6,
        source_port_number "Source Port Number": u16 if spn,
    }
}

pfcp_layout! {
    /// MBS Session Identifier (§8.2.206): the TMGI, then, with SSMI, the Source Specific IP
    /// Multicast Address and what follows it, kept as their octets.
    pub struct MbsSessionIdentifier "8.2.206" {
        flags(u8) { nidi "NIDI": 3, ssmi "SSMI": 2, tmgi "TMGI": 1 }
        tmgi_field "TMGI field": Mac if tmgi,
        nid "NID": Mac if nidi && !ssmi,
        source_specific_ip_multicast_address "Source Specific IP Multicast Address": Rest if ssmi,
    }
}

pfcp_layout! {
    /// Local Ingress Tunnel (§8.2.209).
    pub struct LocalIngressTunnel "8.2.209" {
        flags(u8) { ch "CH": 3, v6 "V6": 2, v4 "V4": 1 }
        udp_port "UDP Port": u16 if !ch,
        ipv4_address "IPv4 address": Ipv4Addr if v4 && !ch,
        ipv6_address "IPv6 address": Ipv6Addr if v6 && !ch,
    }
}

pfcp_layout! {
    /// DSCP to PPI Mapping Information (§8.2.214): the PPI value, then its DSCP values,
    /// each in an octet with two spare bits.
    pub struct DscpToPpiMappingInformation "8.2.214" {
        flags(u8) { ppi_value "PPI Value": 1 / 3 }
        dscp_values "DSCP Value": Each<u8> if true,
    }
}

pfcp_layout! {
    /// Traffic Parameter Threshold (§8.2.220).
    pub struct TrafficParameterThreshold "8.2.220" {
        flags(u8) { dl "DL": 1 }
        downlink_n6_jitter_threshold "Downlink N6 Jitter threshold": u32 if dl,
    }
}

pfcp_layout! {
    /// N6 Jitter Measurement (§8.2.222).
    pub struct N6JitterMeasurement "8.2.222" {
        flags(u8) { dl "DL": 1 }
        dl_periodicity "DL Periodicity": u32 if dl,
        lower_dl_jitter_measurement "Lower DL Jitter Measurement": u32 if dl,
        higher_dl_jitter_measurement "Higher DL Jitter Measurement": u32 if dl,
    }
}

pfcp_layout! {
    /// MPQUIC Address Information (§8.2.226).
    pub struct MpquicAddressInformation "8.2.226" {
        flags(u8) { v6 "V6": 2, v4 "V4": 1 }
        mpquic_proxy_type "MPQUIC Proxy Type": u8 if true,
        mpquic_proxy_port "MPQUIC Proxy Port": u16 if true,
        mpquic_proxy_ipv4_address "MPQUIC Proxy IPv4 Address": Ipv4Addr if v4,
        mpquic_proxy_ipv6_address "MPQUIC Proxy IPv6 Address": Ipv6Addr if v6,
    }
}

pfcp_layout! {
    /// Reporting Suggestion Info (§8.2.229): the Reporting Urgency of Table 8.2.229-1 and
    /// the time.
    pub struct ReportingSuggestionInfo "8.2.229" {
        flags(u8) { reporting_urgency "Reporting Urgency value": 1 / 4 as ReportingUrgencyValue }
        reporting_time_info "Reporting Time Info": u32 if true,
    }
}

pfcp_layout! {
    /// Reporting Thresholds (§8.2.240).
    pub struct ReportingThresholds "8.2.240" {
        flags(u8) { uldr "ULDR": 4, dldr "DLDR": 3, ulci "ULCI": 2, dlci "DLCI": 1 }
        dl_congestion_information_threshold "DL Congestion information threshold": u16 if dlci,
        ul_congestion_information_threshold "UL Congestion information threshold": u16 if ulci,
        dl_data_rate_threshold "DL Data Rate threshold": U40 if dldr,
        ul_data_rate_threshold "UL Data Rate threshold": U40 if uldr,
    }
}

pfcp_layout! {
    /// On-path N6 Connection Information (§8.2.261): the Signaling method of Table
    /// 8.2.261-1, then the destination of the connection.
    pub struct OnPathN6ConnectionInformation "8.2.261" {
        flags(u8) { pn "PN": 6, v6 "V6": 5, v4 "V4": 4, signaling_method "Signaling method": 1 / 3 as SignalingMethod }
        destination_ipv4 "Destination IPv4 (Connection Address)": Ipv4Addr if v4,
        destination_ipv6 "Destination IPv6 (Connection Address)": Ipv6Addr if v6,
        port_number "Port Number": u16 if pn,
    }
}

// ── Fixed fields, a length and its octets ──────────────────────────────────

pfcp_fields! {
    /// Forwarding Policy (§8.2.23).
    pub struct ForwardingPolicy "8.2.23" { forwarding_policy_identifier "Forwarding Policy Identifier": Lv8 }
    /// UE IP address Pool Identity (§8.2.128).
    pub struct UeIpAddressPoolIdentity "8.2.128" { ue_ip_address_pool_identity "UE IP address Pool Identity": Lv16 }
    /// SMF Set ID (§8.2.131): a spare octet, then the FQDN.
    pub struct SmfSetId "8.2.131" { spare_octet "Spare": Spare, fqdn "FQDN": Rest }
    /// Offending IE Information (§8.2.185).
    pub struct OffendingIeInformation "8.2.185" { type_of_the_offending_ie "Type of the offending IE": u16, value_of_the_offending_ie "Value of the offending IE": Rest }
    /// DNS Query/Response Filter (§8.2.201).
    pub struct DnsQueryResponseFilter "8.2.201" { domain_name_pattern "Domain Name Pattern": Lv16 }
    /// Multicast Transport Information (§8.2.207): a spare octet, the Common Tunnel
    /// Endpoint Identifier, then the IP multicast distribution address and the source
    /// address, each after its type and length, kept as their octets.
    pub struct MulticastTransportInformation "8.2.207" { spare_octet "Spare": Spare, common_tunnel_endpoint_identifier "Common Tunnel Endpoint Identifier": u32, ip_multicast_distribution_address "IP Multicast Distribution Address (IPv4 or IPv6)": TypedAddress, ip_source_address "IP Source Address (IPv4 or IPv6)": TypedAddress }
    /// Vendor-Specific Node Report Type (§8.2.217): the Enterprise ID and its octet of
    /// flags, which the vendor defines.
    pub struct VendorSpecificNodeReportType "8.2.217" { enterprise_id "Enterprise ID": u16, flags "Flags": u8 }
    /// UE Level Measurements Configuration (§8.2.245): the Job Type (Table 8.2.245-1), the
    /// Measurement Types after their number (Table 8.2.245-2), and the Time Period, in
    /// seconds.
    pub struct UeLevelMeasurementsConfiguration "8.2.245" { job_type "Job Type": JobType, measurement_types "Measurement Type": Counted<MeasurementType>, time_period "Time Period": U24 }
}

pfcp_layout! {
    /// L2TP User Authentication (§8.2.187): the Proxy Authen Type, then the name, the
    /// challenge, the response and the ID that its flags announce, each as the Attribute
    /// Value of its AVP (IETF RFC 2661).
    pub struct L2tpUserAuthentication "8.2.187" {
        head { proxy_authen_type_value "Proxy Authen Type Value": u16 }
        flags(u8) { pai "PAI": 4, par "PAR": 3, pac "PAC": 2, pan "PAN": 1 }
        proxy_authen_name_value "Proxy Authen Name Value": Lv8 if pan,
        proxy_authen_challenge_value "Proxy Authen Challenge Value": Lv8 if pac,
        proxy_authen_response_value "Proxy Authen Response Value": Lv8 if par,
        proxy_authen_id "Proxy Authen ID": u8 if pai,
    }
}

pfcp_number! {
    /// RAT Type (§8.2.186): its value of Table 8.2.186-1.
    RatType(RatTypeValue) "RAT Type" "8.2.186";
}

pfcp_octets! {
    /// LNS Address (§8.2.188): an IPv4 or an IPv6 address.
    LnsAddress "LNS Address value" "8.2.188";
    /// Binding Indication (§8.2.281).
    BindingIndication "Binding Indication" "8.2.281";
}

// ── Octets of bits ─────────────────────────────────────────────────────────

pfcp_bits! {
    /// Additional Usage Reports Information (§8.2.91): AURI, and the number of additional
    /// usage reports, its seven high bits in octet 5 and its eight low ones in octet 6.
    pub struct AdditionalUsageReportsInformation "8.2.91" octets 2 min 2 {
        auri "AURI": 0 8 1, number "Number of Additional Usage Reports value": 0 1 7 + 1 1 8,
    }
}

pfcp_bits! {
    /// C-TAG (§8.2.94): its flags, then the PCP value, the DEI flag and the C-VID value, its
    /// four high bits in octet 6 and its eight low ones in octet 7.
    pub struct CTag "8.2.94" octets 3 min 3 {
        pcp "PCP": 0 1 1, dei "DEI": 0 2 1, vid "VID": 0 3 1,
        pcp_value "PCP value": 1 1 3, dei_flag "DEI Flag": 1 4 1, cvid "C-VID value": 1 5 4 + 2 1 8,
    }
}

pfcp_bits! {
    /// S-TAG (§8.2.95): as C-TAG, with the S-VID.
    pub struct STag "8.2.95" octets 3 min 3 {
        pcp "PCP": 0 1 1, dei "DEI": 0 2 1, vid "VID": 0 3 1,
        pcp_value "PCP value": 1 1 3, dei_flag "DEI Flag": 1 4 1, svid "S-VID value": 1 5 4 + 2 1 8,
    }
}

pfcp_bits! {
    /// UP Function Features (§8.2.25): the features of Table 8.2.25-1, each a bit.
    pub struct UpFunctionFeatures "8.2.25" octets 12 min 1 {
        bucp "BUCP": 0 1 1, ddnd "DDND": 0 2 1, dlbd "DLBD": 0 3 1, trst "TRST": 0 4 1,
        ftup "FTUP": 0 5 1, pfdm "PFDM": 0 6 1, heeu "HEEU": 0 7 1, treu "TREU": 0 8 1,
        empu "EMPU": 1 1 1, pdiu "PDIU": 1 2 1, udbc "UDBC": 1 3 1, quoac "QUOAC": 1 4 1,
        trace "TRACE": 1 5 1, frrt "FRRT": 1 6 1, pfde "PFDE": 1 7 1, epfar "EPFAR": 1 8 1,
        dpdra "DPDRA": 2 1 1, adpdp "ADPDP": 2 2 1, ueip "UEIP": 2 3 1, sset "SSET": 2 4 1,
        mnop "MNOP": 2 5 1, mte "MTE": 2 6 1, bundl "BUNDL": 2 7 1, gcom "GCOM": 2 8 1,
        mpas "MPAS": 3 1 1, rttl "RTTL": 3 2 1, vtime "VTIME": 3 3 1, norp "NORP": 3 4 1,
        iptv "IPTV": 3 5 1, ip6pl "IP6PL": 3 6 1, tsn "TSN": 3 7 1, mptcp "MPTCP": 3 8 1,
        atsss_ll "ATSSS-LL": 4 1 1, qfqm "QFQM": 4 2 1, gpqm "GPQM": 4 3 1, mt_edt "MT-EDT": 4 4 1,
        ciot "CIOT": 4 5 1, ethar "ETHAR": 4 6 1, ddds "DDDS": 4 7 1, rds "RDS": 4 8 1,
        rttwp "RTTWP": 5 1 1, quasf "QUASF": 5 2 1, nspoc "NSPOC": 5 3 1, l2tp "L2TP": 5 4 1,
        upber "UPBER": 5 5 1, resps "RESPS": 5 6 1, iprep "IPREP": 5 7 1, dnsts "DNSTS": 5 8 1,
        drqos "DRQOS": 6 1 1, mbsn4 "MBSN4": 6 2 1, psuprm "PSUPRM": 6 3 1, epppi "EPPPI": 6 4 1,
        ratp "RATP": 6 5 1, upidp "UPIDP": 6 6 1, afsfc "AFSFC": 6 7 1, mpquic_udp "MPQUIC-UDP": 6 8 1,
        redsm "REDSM": 7 1 1, dbdm "DBDM": 7 2 1, tscts "TSCTS": 7 3 1, drtsc "DRTSC": 7 4 1,
        n6jedb "N6JEDB": 7 5 1, qmcon "QMCON": 7 6 1, detnet "DETNET": 7 7 1, eml4s "EML4S": 7 8 1,
        pdusm "PDUSM": 8 1 1, cn_tl "CN-TL": 8 2 1, qmdrm "QMDRM": 8 3 1, edbnc "EDBNC": 8 4 1,
        mt_sdt "MT-SDT": 8 5 1, upsbies "UPSBIES": 8 6 1, umn6ip "UMN6IP": 8 7 1, un6tu "UN6TU": 8 8 1,
        mbsch "MBSCH": 9 1 1, un6dm "UN6DM": 9 2 1, natpub "NATPUB": 9 3 1, ushph "USHPH": 9 4 1,
        mpquic_ip "MPQUIC-IP": 9 5 1, mpquic_e "MPQUIC-E": 9 6 1, dyntr "DYNTR": 9 7 1, muxmf "MUXMF": 9 8 1,
        conudp "CONUDP": 10 1 1, moq "MOQ": 10 2 1, ulm "ULM": 10 3 1, psitlm "PSITLM": 10 4 1,
        udpopt "UDPOPT": 10 5 1, qmabr "QMABR": 10 6 1, papfd "PAPFD": 10 7 1,
    }
}

pfcp_bits! {
    /// CP Function Features (§8.2.58): the features of Table 8.2.58-1, each a bit.
    pub struct CpFunctionFeatures "8.2.58" octets 3 min 1 {
        load "LOAD": 0 1 1, ovrl "OVRL": 0 2 1, epfar "EPFAR": 0 3 1, sset "SSET": 0 4 1,
        bundl "BUNDL": 0 5 1, mpas "MPAS": 0 6 1, ardr "ARDR": 0 7 1, uiaur "UIAUR": 0 8 1,
        psucc "PSUCC": 1 1 1, rpgur "RPGUR": 1 2 1, papfd "PAPFD": 1 3 1,
    }
}

// ── Secrets ────────────────────────────────────────────────────────────────

/// Octets of a key, which `Debug` does not print: their length alone.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretLv8(pub Vec<u8>);

impl fmt::Debug for SecretLv8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecretLv8({} octets)", self.0.len())
    }
}

impl Field for SecretLv8 {
    fn read(octets: &mut &[u8]) -> Option<Self> {
        Lv8::read(octets).map(|value| Self(value.0))
    }
    fn write(&self, out: &mut Vec<u8>) {
        Lv8(self.0.clone()).write(out);
    }
    fn size(&self) -> usize {
        1 + self.0.len()
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::octets(&self.0)
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        reading.secret(|reading| Lv8::from_tree(value, reading)).map(|value| Self(value.0))
    }
}

pfcp_fields! {
    /// Key ID and Shared Secret (OWAMP or TWAMP) (§8.2.276): the shared secret is a key,
    /// which `Debug` does not print.
    pub struct KeyIdAndSharedSecret "8.2.276" { key_id "Key ID": Lv8, shared_secret "Shared Secret": SecretLv8 }
}

/// HMAC Key (STAMP) (§8.2.274): a key, which `Debug` does not print.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HmacKeyStamp(pub Octets);

impl fmt::Debug for HmacKeyStamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HmacKeyStamp({} octets)", self.0.len())
    }
}

impl HmacKeyStamp {
    /// The name of its field.
    pub const FIELDS: &'static [&'static str] = &["HMAC Key"];
}

impl Codec for HmacKeyStamp {
    fn decode(octets: &[u8]) -> Option<Self> {
        Some(Self(Octets::wire(octets)))
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.0.len()
    }
}

impl Check for HmacKeyStamp {}

#[cfg(feature = "serde")]
oxirush_utils::impl_serde!(HmacKeyStamp);

#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for HmacKeyStamp {
    const NAME: &'static str = "HMAC Key (STAMP)";
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::octets(&self.0)
    }
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        reading.secret(|reading| reading.octets(value)).map(|octets| Self(octets.into()))
    }
}

listed_value!(
    SdfFilter, RedirectInformation, DownlinkDataServiceInformation, PfdContents, FlowInformation,
    PacketRate, HeaderEnrichment, FailedRuleId, TimeQuotaMechanism, MacAddress,
    CpPfcpEntityIpAddress, SourceIpAddress, PacketRateStatus, PmfControlInformation,
    MptcpAddressInformation, LinkSpecificMultipathIpAddress, PmfAddressInformation,
    IpAddressAndPortNumberReplacement, MbsSessionIdentifier, LocalIngressTunnel,
    DscpToPpiMappingInformation, TrafficParameterThreshold, N6JitterMeasurement,
    MpquicAddressInformation, ReportingSuggestionInfo, ReportingThresholds,
    OnPathN6ConnectionInformation, ForwardingPolicy, UeIpAddressPoolIdentity, SmfSetId,
    OffendingIeInformation, DnsQueryResponseFilter, MulticastTransportInformation,
    VendorSpecificNodeReportType, UeLevelMeasurementsConfiguration, L2tpUserAuthentication,
    RatType, AdditionalUsageReportsInformation, CTag, STag, UpFunctionFeatures,
    CpFunctionFeatures, KeyIdAndSharedSecret, HmacKeyStamp,
);

pfcp_fields! {
    /// Trace Information (§8.2.108): the PLMN of the trace, as TS 29.274 writes MCC and MNC,
    /// the Trace ID, the triggering events, the depth, the interfaces and the IP address of
    /// the Trace Collection Entity.
    pub struct TraceInformation "8.2.108" {
        mcc_mnc "MCC and MNC": PlmnId, trace_id "Trace ID": U24, triggering_events "Triggering Events": Lv8,
        session_trace_depth "Session Trace Depth": u8, list_of_interfaces "List of Interfaces": Lv8,
        ip_address_of_trace_collection_entity "IP Address of Trace Collection Entity": Lv8,
    }
}

/// FQ-CSID (§8.2.43): the node that allocated the PDN Connection Set Identifiers, by its
/// Node-ID Type (0 an IPv4 address, 1 an IPv6 address, 2 MCC, MNC and a number), the
/// identifiers, and the Node Type (Table 8.2.43-2) that a later release added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FqCsid {
    /// The Node-ID Type, bits 8 to 5 of octet 5.
    pub node_id_type: u8,
    /// The Node-Address: four octets, or sixteen for an IPv6 address.
    pub node_address: Vec<u8>,
    /// The PDN Connection Set Identifiers, at most fifteen.
    pub csids: Vec<u16>,
    /// The octet of the Node Type, bits 4 to 1, and four spare bits: absent from a sender
    /// of an earlier release.
    pub node_type: Option<NodeType>,
    /// The octets after them, which a later release adds.
    pub extra: Octets,
}

impl FqCsid {
    /// The names of its fields.
    pub const FIELDS: &'static [&'static str] = &["FQ-CSID Node-ID Type", "Node-Address", "PDN Connection Set Identifiers", "Node Type"];

    /// The length of the Node-Address of a Node-ID Type: `None` for a spare type.
    fn address_length(node_id_type: u8) -> Option<usize> {
        match node_id_type {
            0 | 2 => Some(4),
            1 => Some(16),
            _ => None,
        }
    }
}

impl Codec for FqCsid {
    fn decode(octets: &[u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        let node_id_type = first >> 4;
        let (address, mut rest) = rest.split_at_checked(Self::address_length(node_id_type)?)?;
        let mut csids = Vec::with_capacity(usize::from(first & 0x0f));
        for _ in 0..first & 0x0f {
            csids.push(u16::read(&mut rest)?);
        }
        let node_type = NodeType::read(&mut rest);
        Some(Self { node_id_type, node_address: address.to_vec(), csids, node_type, extra: Octets::wire(rest) })
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.csids.len() > 15 || Self::address_length(self.node_id_type) != Some(self.node_address.len()) {
            return Err(Error::Inconsistent { ie: "FQ-CSID", field: "Node-Address or PDN Connection Set Identifiers", clause: "8.2.43" });
        }
        out.push(self.node_id_type << 4 | self.csids.len() as u8);
        out.extend_from_slice(&self.node_address);
        for csid in &self.csids {
            out.extend_from_slice(&csid.to_be_bytes());
        }
        if self.node_type.is_none() && !self.extra.is_empty() {
            return Err(Error::Inconsistent { ie: "FQ-CSID", field: "Node Type", clause: "8.2.43" });
        }
        if let Some(node_type) = self.node_type {
            out.push(node_type.value());
        }
        out.extend_from_slice(&self.extra);
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        1 + self.node_address.len() + 2 * self.csids.len() + usize::from(self.node_type.is_some()) + self.extra.len()
    }
}

impl Check for FqCsid {
    fn check(&self, path: &crate::check::Path, found: &mut Vec<Deviation>) {
        if Self::address_length(self.node_id_type).is_none() {
            found.push(Deviation::new(path, "8.2.43", crate::check::DeviationKind::SpareValue { value: self.node_id_type.into() }));
        }
        if let Some(node_type) = self.node_type {
            node_type.check(path, "8.2.43", found);
        }
    }
}

#[cfg(feature = "serde")]
oxirush_utils::impl_serde!(FqCsid);

/// `{"FQ-CSID Node-ID Type": 0, "Node-Address": "10.0.0.1", "PDN Connection Set Identifiers": [1]}`:
/// an IPv4 or IPv6 address as text, the other Node-Address as its octets.
#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for FqCsid {
    const NAME: &'static str = "FQ-CSID";
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        use oxirush_utils::tree;
        let mut members = tree::Members::new();
        members.put("FQ-CSID Node-ID Type", tree::unsigned(self.node_id_type.into()));
        let address = match (self.node_id_type, self.node_address.len()) {
            (0, 4) => tree::Value::String(alloc::format!("{}", Ipv4Addr::from(<[u8; 4]>::try_from(&self.node_address[..]).unwrap_or_default()))),
            (1, 16) => tree::Value::String(alloc::format!("{}", Ipv6Addr::from(<[u8; 16]>::try_from(&self.node_address[..]).unwrap_or_default()))),
            _ => tree::octets(&self.node_address),
        };
        members.put("Node-Address", address);
        members.put("PDN Connection Set Identifiers", tree::Value::Array(self.csids.iter().map(|csid| tree::unsigned((*csid).into())).collect()));
        if let Some(node_type) = self.node_type {
            members.put("Node Type", node_type.tree());
        }
        if !self.extra.is_empty() {
            members.put("extra", tree::octets(&self.extra));
        }
        members.finish()
    }
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        let read = reading.members(value, &["FQ-CSID Node-ID Type", "Node-Address", "PDN Connection Set Identifiers", "Node Type", "extra"])?;
        let node_id_type = reading.member(&read, 0, |value, reading| reading.unsigned(value, 0, 15))? as u8;
        let node_address = reading.member(&read, 1, |value, reading| {
            let text = value.as_str().unwrap_or_default();
            match node_id_type {
                0 => text.parse::<Ipv4Addr>().map(|address| address.octets().to_vec()).map_err(|_| reading.mismatch("an IPv4 address", value)),
                1 => text.parse::<Ipv6Addr>().map(|address| address.octets().to_vec()).map_err(|_| reading.mismatch("an IPv6 address", value)),
                _ => reading.octets(value),
            }
        })?;
        let csids = reading.member(&read, 2, |value, reading| reading.list(value, |value, reading| Ok(reading.unsigned(value, 0, 0xffff)? as u16)))?;
        let node_type = reading.optional(&read, 3, NodeType::from_tree)?;
        let extra = reading.optional(&read, 4, |value, reading| reading.octets(value))?;
        let fq_csid = Self { node_id_type, node_address, csids, node_type, extra: extra.map(Octets::from).unwrap_or_default() };
        if fq_csid.node_type.is_none() && !fq_csid.extra.is_empty() {
            return Err(reading.refuse(oxirush_utils::tree::ErrorKind::Value, "extra octets after a Node Type only (8.2.43)"));
        }
        if fq_csid.csids.len() > 15 || Self::address_length(node_id_type) != Some(fq_csid.node_address.len()) {
            return Err(reading.refuse(oxirush_utils::tree::ErrorKind::Value, "a Node-Address of the length of its type, and at most fifteen identifiers (8.2.43)"));
        }
        Ok(fq_csid)
    }
}

/// The MAC addresses of MAC Addresses Detected and MAC Addresses Removed (§8.2.103,
/// §8.2.104): their number, the addresses, then the C-TAG and the S-TAG after their lengths,
/// which a later release added.
macro_rules! mac_addresses {
    ($($(#[$meta:meta])* $ty:ident $name:literal $clause:literal;)*) => {$(
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $ty {
            /// The MAC addresses.
            pub mac_addresses: Vec<Mac>,
            /// The C-TAG, after its length.
            pub c_tag: Option<Lv8>,
            /// The S-TAG, after its length.
            pub s_tag: Option<Lv8>,
            /// The octets after them, which a later release adds.
            pub extra: Octets,
        }

        impl $ty {
            /// The names of its fields.
            pub const FIELDS: &'static [&'static str] = &["MAC address values", "C-TAG", "S-TAG"];
        }

        impl Codec for $ty {
            fn decode(octets: &[u8]) -> Option<Self> {
                let (&count, mut rest) = octets.split_first()?;
                let mut mac_addresses = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    mac_addresses.push(Mac::read(&mut rest)?);
                }
                let c_tag = if rest.is_empty() { None } else { Some(Lv8::read(&mut rest)?) };
                let s_tag = if rest.is_empty() { None } else { Some(Lv8::read(&mut rest)?) };
                Some(Self { mac_addresses, c_tag, s_tag, extra: Octets::wire(rest) })
            }
            fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                if self.mac_addresses.len() > 255 || (self.s_tag.is_some() && self.c_tag.is_none()) {
                    return Err(Error::Inconsistent { ie: $name, field: "MAC address value", clause: $clause });
                }
                out.push(self.mac_addresses.len() as u8);
                for mac in &self.mac_addresses {
                    out.extend_from_slice(mac);
                }
                if let Some(tag) = &self.c_tag {
                    tag.write(out);
                }
                if let Some(tag) = &self.s_tag {
                    tag.write(out);
                }
                out.extend_from_slice(&self.extra);
                Ok(())
            }
            fn encoded_len(&self) -> usize {
                1 + 6 * self.mac_addresses.len()
                    + self.c_tag.as_ref().map_or(0, Field::size)
                    + self.s_tag.as_ref().map_or(0, Field::size)
                    + self.extra.len()
            }
        }

        impl Check for $ty {}

        #[cfg(feature = "serde")]
        oxirush_utils::impl_serde!($ty);

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = $name;
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                use oxirush_utils::tree;
                let mut members = tree::Members::new();
                members.put("MAC address values", tree::Value::Array(self.mac_addresses.iter().map(|mac| tree::octets(mac)).collect()));
                members.put_optional("C-TAG", self.c_tag.as_ref().map(Field::to_tree));
                members.put_optional("S-TAG", self.s_tag.as_ref().map(Field::to_tree));
                if !self.extra.is_empty() {
                    members.put("extra", tree::octets(&self.extra));
                }
                members.finish()
            }
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let read = reading.members(value, &["MAC address values", "C-TAG", "S-TAG", "extra"])?;
                let mac_addresses = reading.member(&read, 0, |value, reading| reading.list(value, |value, reading| reading.octet_array::<6>(value)))?;
                let c_tag = reading.optional(&read, 1, Lv8::from_tree)?;
                let s_tag = reading.optional(&read, 2, Lv8::from_tree)?;
                let extra = reading.optional(&read, 3, |value, reading| reading.octets(value))?;
                Ok(Self { mac_addresses, c_tag, s_tag, extra: extra.map(Octets::from).unwrap_or_default() })
            }
        }
    )*};
}

mac_addresses! {
    /// MAC Addresses Detected (§8.2.103).
    MacAddressesDetected "MAC Addresses Detected" "8.2.103";
    /// MAC Addresses Removed (§8.2.104).
    MacAddressesRemoved "MAC Addresses Removed" "8.2.104";
}

listed_value!(TraceInformation, FqCsid, MacAddressesDetected, MacAddressesRemoved);
