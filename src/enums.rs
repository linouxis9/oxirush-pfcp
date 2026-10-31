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

//! The values that the tables of clause 8.2 name, one enumeration each: written from the
//! tables by a script. Tables of the same values share one.

use crate::macros::pfcp_enum;

pfcp_enum! {
    /// Cause values (Table 8.2.1-1).
    pub enum CauseValue "Table 8.2.1-1" bits 8 reserved [0] {
        1 RequestAccepted "Request accepted (success)",
        2 MoreUsageReportToSend "More Usage Report to send",
        3 RequestPartiallyAccepted "Request partially accepted",
        64 RequestRejected "Request rejected (reason not specified)",
        65 SessionContextNotFound "Session context not found",
        66 MandatoryIeMissing "Mandatory IE missing",
        67 ConditionalIeMissing "Conditional IE missing",
        68 InvalidLength "Invalid length",
        69 MandatoryIeIncorrect "Mandatory IE incorrect",
        70 InvalidForwardingPolicy "Invalid Forwarding Policy",
        71 InvalidFTeidAllocationOption "Invalid F-TEID allocation option",
        72 NoEstablishedPfcpAssociation "No established PFCP Association",
        73 RuleCreationModificationFailure "Rule creation/modification Failure",
        74 PfcpEntityInCongestion "PFCP entity in congestion",
        75 NoResourcesAvailable "No resources available",
        76 ServiceNotSupported "Service not supported",
        77 SystemFailure "System failure",
        78 RedirectionRequested "Redirection Requested",
        79 AllDynamicAddressesAreOccupied "All dynamic addresses are occupied",
        80 UnknownPreDefinedRule "Unknown Pre-defined Rule",
        81 UnknownApplicationId "Unknown Application ID",
        82 L2tpTunnelEstablishmentFailure "L2TP tunnel Establishment failure",
        83 L2tpSessionEstablishmentFailure "L2TP session Establishment failure",
        84 L2tpTunnelRelease "L2TP tunnel release",
        85 L2tpSessionRelease "L2TP session release",
        86 PfcpSessionRestorationFailure "PFCP session restoration failure due to requested resource not available",
        87 L2tpTunnelEstablishmentFailureTunnelAuthFailure "L2TP tunnel Establishment failure – Tunnel Auth Failure",
        88 L2tpSessionEstablishmentFailureSessionAuthFailure "L2TP Session Establishment failure – Session Auth Failure",
        89 L2tpTunnelEstablishmentFailureLnsNotReachable "L2TP tunnel Establishment failure – LNS not reachable",
        90 PfdContentsSyntaxError "PFD Contents Syntax Error",
        91 PfdContentsSemanticsError "PFD Contents Semantics Error",
        92 PfdApplicationIdUnknown "PFD Application Id Unknown",
    }
    /// Interface value (Table 8.2.2-1).
    pub enum SourceInterfaceValue "Table 8.2.2-1" bits 4 {
        0 Access "Access",
        1 Core "Core",
        2 SgiLanN6Lan "SGi-LAN/N6-LAN",
        3 CpFunction "CP-function",
        4 FiveGVnInternal "5G VN Internal",
    }
    /// UL Gate and DL Gate (Table 8.2.7-1 and Table 8.2.7-2).
    pub enum Gate "Table 8.2.7-1 and Table 8.2.7-2" bits 2 {
        0 Open "OPEN",
        1 Closed "CLOSED",
    }
    /// Redirect Address Type (Table 8.2.20-1).
    pub enum RedirectAddressType "Table 8.2.20-1" bits 4 {
        0 Ipv4Address "IPv4 address",
        1 Ipv6Address "IPv6 address",
        2 Url "URL",
        3 SipUri "SIP URI",
        4 Ipv4AndIpv6Addresses "IPv4 and IPv6 addresses",
        5 Port "Port",
        6 Ipv4AddressAndPort "IPv4 address and Port",
        7 Ipv6AddressAndPort "IPv6 address and Port",
        8 Ipv4AndIpv6AddressesAndPort "IPv4 and IPv6 addresses and Port",
    }
    /// Interface value (Table 8.2.24-1).
    pub enum DestinationInterfaceValue "Table 8.2.24-1" bits 4 {
        0 Access "Access",
        1 Core "Core",
        2 SgiLanN6Lan "SGi-LAN/N6-LAN",
        3 CpFunction "CP- Function",
        4 LiFunction "LI Function",
        5 FiveGVnInternal "5G VN Internal",
    }
    /// Timer unit (Table 8.2.29.1 and Table 8.2.35.1 and Table 8.2.78.1).
    pub enum TimerUnit "Table 8.2.29.1 and Table 8.2.35.1 and Table 8.2.78.1" bits 3 {
        0 TwoSeconds "2 seconds",
        1 OneMinute "1 minute",
        2 TenMinutes "10 minutes",
        3 OneHour "1 hour",
        4 TenHours "10 hours",
        7 Infinite "infinite",
    }
    /// Node ID Type (Table 8.2.38-2).
    pub enum NodeIdType "Table 8.2.38-2" bits 4 {
        0 Ipv4Address "IPv4 address",
        1 Ipv6Address "IPv6 address",
        2 Fqdn "FQDN",
    }
    /// Node Type (Table 8.2.43-2).
    pub enum NodeType "Table 8.2.43-2" bits 4 {
        0 Mme "MME",
        1 SgwC "SGW-C",
        2 PgwCSmf "PGW-C/SMF",
        3 Epdg "ePDG",
        4 Twan "TWAN",
        5 PgwUSgwUUpf "PGW-U/SGW-U/UPF",
    }
    /// Flow Direction (Table 8.2.61-1).
    pub enum FlowDirection "Table 8.2.61-1" bits 3 {
        0 Unspecified "Unspecified",
        1 Downlink "Downlink (traffic to the UE)",
        2 Uplink "Uplink (traffic from the UE)",
        3 Bidirectional "Bidirectional",
    }
    /// Uplink/Downlink Time Unit (Table 8.2.63.1).
    pub enum TimeUnit "Table 8.2.63.1" bits 3 {
        0 Minute "minute",
        1 SixMinutes "6 minutes",
        2 Hour "hour",
        3 Day "day",
        4 Week "week",
    }
    /// Outer Header Removal Description (Table 8.2.64-1).
    pub enum OuterHeaderRemovalDescription "Table 8.2.64-1" bits 8 {
        0 GtpUUdpIpv4 "GTP-U/UDP/IPv4",
        1 GtpUUdpIpv6 "GTP-U/UDP/IPv6",
        2 UdpIpv4 "UDP/IPv4",
        3 UdpIpv6 "UDP/IPv6",
        4 Ipv4 "IPv4",
        5 Ipv6 "IPv6",
        6 GtpUUdpIp "GTP-U/UDP/IP",
        7 VlanTagPop "VLAN TAG POP (i.e. removal of one VLAN tag, S-TAG or C-TAG)",
        8 VlanTagsPopPop "VLAN TAGs POP-POP (i.e. removal of 2 VLAN tags, S-TAG and C-TAG)",
    }
    /// Header Type (Table 8.2.67-1).
    pub enum HeaderType "Table 8.2.67-1" bits 5 {
        0 Http "HTTP",
    }
    /// PDN Type (Table 8.2.79-1).
    pub enum PdnTypeValue "Table 8.2.79-1" bits 3 {
        1 Ipv4 "IPv4",
        2 Ipv6 "IPv6",
        3 Ipv4v6 "IPv4v6",
        4 NonIp "Non-IP",
        5 Ethernet "Ethernet",
    }
    /// Rule ID Type (Table 8.2.80-1).
    pub enum RuleIdType "Table 8.2.80-1" bits 5 {
        0 Pdr "PDR",
        1 Far "FAR",
        2 Qer "QER",
        3 Urr "URR",
        4 Bar "BAR",
        5 Mar "MAR",
        6 Srr "SRR",
    }
    /// Base Time Interval Type (Table 8.2.81-1).
    pub enum BaseTimeIntervalType "Table 8.2.81-1" bits 2 {
        0 Ctp "CTP",
        1 Dtp "DTP",
    }
    /// Interface Type value (Table 8.2.118-1).
    pub enum InterfaceTypeValue "Table 8.2.118-1" bits 6 {
        0 S1U "S1-U",
        1 S5S8U "S5 /S8-U",
        2 S4U "S4-U",
        3 S11U "S11-U",
        4 S12 "S12",
        5 GnGpU "Gn/Gp-U",
        6 S2aU "S2a-U",
        7 S2bU "S2b-U",
        8 EnodebGtpUInterfaceForDlDataForwarding "eNodeB GTP-U interface for DL data forwarding",
        9 EnodebGtpUInterfaceForUlDataForwarding "eNodeB GTP-U interface for UL data forwarding",
        10 SgwUpfGtpUInterfaceForDlDataForwarding "SGW/UPF GTP-U interface for DL data forwarding",
        11 N3ThreeGppAccess "N3 3GPP Access",
        12 N3TrustedNon3gppAccess "N3 Trusted Non-3GPP Access",
        13 N3UntrustedNon3gppAccess "N3 Untrusted Non-3GPP Access",
        14 N3ForDataForwarding "N3 for data forwarding",
        15 N9 "N9 (or N9 for non-roaming)",
        16 Sgi "SGi",
        17 N6 "N6",
        18 N19 "N19",
        19 S8U "S8-U",
        20 GpU "Gp-U",
        21 N9ForRoaming "N9 for roaming",
        22 IuU "Iu-U",
        23 N9ForDataForwarding "N9 for data forwarding",
        24 SxaU "Sxa-U",
        25 SxbU "Sxb-U",
        26 SxcU "Sxc-U",
        27 N4U "N4-U",
        28 SgwUpfGtpUInterfaceForUlDataForwarding "SGW/UPF GTP-U interface for UL data forwarding",
        29 N6mbNmb9 "N6mb/Nmb9",
        30 N3mb "N3mb",
        31 N19mb "N19mb",
    }
    /// Steering Functionality value (Table 8.2.124-1).
    pub enum SteeringFunctionalityValue "Table 8.2.124-1" bits 4 {
        0 AtsssLl "ATSSS-LL",
        1 Mptcp "MPTCP",
        2 MpquicUdp "MPQUIC-UDP",
        3 MpquicIp "MPQUIC-IP",
        4 MpquicE "MPQUIC-E",
    }
    /// Steering Mode value (Table 8.2.125-1).
    pub enum SteeringModeValue "Table 8.2.125-1" bits 4 {
        0 ActiveStandby "Active-Standby",
        1 SmallestDelay "Smallest Delay",
        2 LoadBalancing "Load Balancing",
        3 PriorityBased "Priority-based",
        4 Redundant "Redundant",
    }
    /// Priority value (Table 8.2.127-1).
    pub enum PriorityValue "Table 8.2.127-1" bits 4 {
        0 Active "Active",
        1 Standby "Standby",
        2 NoStandby "No Standby",
        3 High "High",
        4 Low "Low",
        5 Primary "Primary",
        6 Secondary "Secondary",
    }
    /// Access Type (Table 8.2.153-1).
    pub enum AccessType "Table 8.2.153-1" bits 2 {
        0 ThreeGppAccessType "3GPP access type",
        1 Non3GppAccessType "Non-3GPP access type",
    }
    /// Availability Status (Table 8.2.153-2).
    pub enum AvailabilityStatus "Table 8.2.153-2" bits 2 {
        0 AccessHasBecomeUnavailable "Access has become unavailable",
        1 AccessHasBecomeAvailable "Access has become available",
    }
    /// RAT Type values (Table 8.2.186-1).
    pub enum RatTypeValue "Table 8.2.186-1" bits 8 reserved [0] {
        1 Utran "UTRAN",
        2 Geran "GERAN",
        3 Wlan "WLAN",
        4 Gan "GAN",
        5 HspaEvolution "HSPA Evolution",
        6 Eutran "EUTRAN (WB-E-UTRAN)",
        7 Virtual "Virtual",
        8 EutranNbIot "EUTRAN-NB-IoT",
        9 LteM "LTE-M",
        10 Nr "NR",
        11 WbEUtranLeo "WB-E-UTRAN (LEO)",
        12 WbEUtranMeo "WB-E-UTRAN (MEO)",
        13 WbEUtranGeo "WB-E-UTRAN (GEO)",
        14 WbEUtranOthersat "WB-E-UTRAN (OTHERSAT)",
        15 EutranNbIotLeo "EUTRAN-NB-IoT (LEO)",
        16 EutranNbIotMeo "EUTRAN-NB-IoT (MEO)",
        17 EutranNbIotGeo "EUTRAN-NB-IoT (GEO)",
        18 EutranNbIotOthersat "EUTRAN-NB-IoT (OTHERSAT)",
        19 LteMLeo "LTE-M (LEO)",
        20 LteMMeo "LTE-M (MEO)",
        21 LteMGeo "LTE-M (GEO)",
        22 LteMOthersat "LTE-M (OTHERSAT)",
        23 NrLeo "NR (LEO)",
        24 NrMeo "NR (MEO)",
        25 NrGeo "NR (GEO)",
        26 NrOthersat "NR (OTHERSAT)",
        27 NrRedcap "NR-REDCAP",
        28 NrEredcap "NR-EREDCAP",
    }
    /// Transport Mode value (Table 8.2.227-1).
    pub enum TransportModeValue "Table 8.2.227-1" bits 4 {
        0 DatagramMode1 "Datagram mode 1",
        1 DatagramMode2 "Datagram mode 2",
        2 StreamMode "Stream mode",
    }
    /// Reporting Urgency value (Table 8.2.229-1).
    pub enum ReportingUrgencyValue "Table 8.2.229-1" bits 4 {
        0 DelayTolerant "Delay tolerant",
        1 NonDelayTolerant "Non delay tolerant",
    }
    /// Media Transport Protocol (Table 8.2.233-1).
    pub enum MediaTransportProtocolValue "Table 8.2.233-1" bits 4 {
        0 Unspecified "Unspecified",
        1 Rtp "RTP (Real-time Transport Protocol)",
        2 Srtp "SRTP (Secure Real-Time Protocol)",
        3 Moqt "MOQT (Media Over QUIC Transport protocol)",
    }
    /// RTP Header Extension Type (Table 8.2.234-1).
    pub enum RtpHeaderExtensionTypeValue "Table 8.2.234-1" bits 8 {
        1 PduSetMarking "RTP Header Extension for PDU Set Marking",
        2 DynamicallyChangingTrafficCharacteristics "RTP header extension for Dynamically changing traffic characteristics",
        3 ExpeditedTransferIndication "RTP header extension for Expedited Transfer Indication",
    }
    /// Payload Format (Table 8.2.237-1).
    pub enum PayloadFormat "Table 8.2.237-1" bits 8 {
        1 H264 "H.264",
        2 H265 "H.265",
    }
    /// Format field (Table 8.2.241-1).
    pub enum FormatField "Table 8.2.241-1" bits 2 {
        1 OneByte "1-byte (short) format is used",
        2 TwoByte "2-byte (long) format is used",
    }
    /// Job Type values (Table 8.2.245-1).
    pub enum JobType "Table 8.2.245-1" bits 8 reserved [0] {
        1 UeLevelMeasurementsOnly "5GC UE Level Measurements only",
        2 TraceAndUeLevelMeasurements "Trace and 5GC UE Level Measurements",
    }
    /// Measurement Type values (Table 8.2.245-2).
    pub enum MeasurementType "Table 8.2.245-2" bits 8 reserved [0] {
        1 DlDelayUe "Average DL packet delay between PSA UPF and UE for a QoS flow",
        2 UlDelayUeExcludingD1 "Average UL packet delay between PSA UPF and UE for a QoS flow (excluding D1)",
        3 UlDelayUeIncludingD1 "Average UL packet delay between PSA UPF and UE for a QoS flow (including D1)",
        4 UlDelayNgRan "Average UL packet delay between PSA UPF and NG-RAN for a QoS flow",
        5 DlDelayNgRan "Average DL packet delay between PSA UPF and NG-RAN for a QoS flow",
        6 RoundTripDelayNgRan "Average round-trip packet delay between PSA UPF and NG-RAN",
        7 RoundTripDelayNgRanSnssai "Average round-trip packet delay between PSA UPF and NG-RAN for a S-NSSAI",
        8 RoundTripDelayNgRanQfi "Average round-trip packet delay between PSA UPF and NG-RAN for a QFI",
        9 RoundTripDelayNgRanSnssaiQfi "Average round-trip packet delay between PSA UPF and NG-RAN for a S-NSSAI and QFI",
    }
    /// Action value (Table 8.2.255-2).
    pub enum ActionValue "Table 8.2.255-2" bits 4 {
        0 Detect "DETECT",
        1 Remove "REMOVE",
        2 Replace "REPLACE",
        3 Insert "INSERT",
    }
    /// Condition value (Table 8.2.258-2).
    pub enum ConditionValue "Table 8.2.258-2" bits 4 {
        0 EveryMatch "EVERY_MATCH",
        1 FirstMatchOnly "FIRST_MATCH_ONLY",
    }
    /// Signaling method (Table 8.2.261-1).
    pub enum SignalingMethod "Table 8.2.261-1" bits 3 {
        0 Unspecified "Unspecified",
        1 ConnectUdp "Connect-UDP",
    }
    /// Failure cause values (Table 8.2.263-1).
    pub enum FailureCause "Table 8.2.263-1" bits 8 {
        0 Unspecified "Unspecified",
        1 ConnectionEstablishmentFailure "Connection Establishment Failure",
        2 ConnectionLost "Connection Lost",
        3 AuthenticationFailure "Authentication Failure",
    }
    /// Transferring method (Table 8.2.271-1).
    pub enum TransferringMethod "Table 8.2.271-1" bits 4 {
        0 Unspecified "Unspecified",
        1 UdpOption "UDP Option (of outer UDP datagram)",
    }
    /// Remaining Data Reporting Indication value (Table 8.2.277-1).
    pub enum RemainingDataReportingIndicationValue "Table 8.2.277-1" bits 4 {
        0 DiscardTheCollectedData "Discard the collected data",
        1 SendTheCollectedDataToTheConsumer "Send the collected data to the consumer",
    }
}
