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

//! The registry: every IE type of Table 8.1.2-1, one line each, and the tables of
//! clause 7, one row each, which the macros expand into the types of the crate.


use crate::enums::CauseValue;
use crate::macros::{pfcp_ies, pfcp_table};
use crate::values::*;
use crate::values_gen::*;
use crate::values_hand::*;

// The conditions of the C rows that a scope alone shows (§7.6.6), beside their rows.

/// A Cause that rejects a request for an IE, which the Offending IE then names.
const OF_AN_IE: [CauseValue; 3] = [CauseValue::MandatoryIeMissing, CauseValue::ConditionalIeMissing, CauseValue::MandatoryIeIncorrect];

/// Whether the Cause is one of `values`.
fn cause_is(cause: &Option<Cause>, values: &[CauseValue]) -> bool {
    cause.as_ref().is_some_and(|cause| values.contains(&cause.value))
}

/// Whether the Measurement Method of a Create URR has a method.
fn method(urr: &CreateUrr, has: impl Fn(&MeasurementMethod) -> bool) -> bool {
    urr.measurement_method.as_ref().is_some_and(has)
}

/// Whether the Reporting Triggers of a Create URR have a trigger.
fn triggers(urr: &CreateUrr, has: impl Fn(&ReportingTriggers) -> bool) -> bool {
    urr.reporting_triggers.as_ref().is_some_and(has)
}

/// The form of an IE type in Table 8.1.2-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// A fixed set of fields of a fixed number of octets.
    Fixed,
    /// A fixed set of fields of a variable number of octets.
    Variable,
    /// Fields that a later release may add to.
    Extendable,
    /// A grouped IE, whose content is IEs (§7.2.3.3).
    Grouped,
}

/// An IE type as Table 8.1.2-1 has it.
#[derive(Debug, Clone, Copy)]
pub struct IeTypeInfo {
    /// The IE type.
    pub ie_type: u16,
    /// Its name.
    pub name: &'static str,
    /// Its form.
    pub form: Form,
    /// The number of fixed octets that the table gives it.
    pub fixed: Option<u16>,
    /// The clause of its layout, or the table of its content.
    pub clause: &'static str,
    /// The names of the flags and fields of its layout, as its tree has them: none for a
    /// grouped IE.
    pub fields: &'static [&'static str],
    /// The tables of its content, for a grouped IE: one, or one per place for an IE that
    /// has different content in different places.
    pub tables: &'static [&'static crate::table::Table],
}

/// The IE type of `ie_type`.
pub fn ie_type_info(ie_type: u16) -> Option<&'static IeTypeInfo> {
    IE_TYPES
        .binary_search_by_key(&ie_type, |info| info.ie_type)
        .ok()
        .map(|at| &IE_TYPES[at])
}

/// The name that Table 8.1.2-1 gives `ie_type`.
pub fn type_name(ie_type: u16) -> Option<&'static str> {
    ie_type_info(ie_type).map(|info| info.name)
}

pfcp_ies! {
    1 "Create PDR" grouped "7.5.2.2-1" => CreatePdr;
    2 "PDI" grouped "7.5.2.2-2" => Pdi;
    3 "Create FAR" grouped "7.5.2.3-1" => CreateFar;
    4 "Forwarding Parameters" grouped "7.5.2.3-2" => ForwardingParameters;
    5 "Duplicating Parameters" grouped "7.5.2.3-3" => DuplicatingParameters;
    6 "Create URR" grouped "7.5.2.4-1" => CreateUrr;
    7 "Create QER" grouped "7.5.2.5-1" => CreateQer;
    8 "Created PDR" grouped "7.5.3.2-1" => CreatedPdr;
    9 "Update PDR" grouped "7.5.4.2-1" => UpdatePdr;
    10 "Update FAR" grouped "7.5.4.3-1" => UpdateFar;
    11 "Update Forwarding Parameters" grouped "7.5.4.3-2" => UpdateForwardingParameters;
    12 "Update BAR (PFCP Session Report Response)" grouped "7.5.9.2-1" => UpdateBarReport;
    13 "Update URR" grouped "7.5.4.4-1" => UpdateUrr;
    14 "Update QER" grouped "7.5.4.5-1" => UpdateQer;
    15 "Remove PDR" grouped "7.5.4.6-1" => RemovePdr;
    16 "Remove FAR" grouped "7.5.4.7-1" => RemoveFar;
    17 "Remove URR" grouped "7.5.4.8-1" => RemoveUrr;
    18 "Remove QER" grouped "7.5.4.9-1" => RemoveQer;
    19 "Cause" fixed(1) "8.2.1" => Cause;
    20 "Source Interface" extendable(1) "8.2.2" => SourceInterface;
    21 "F-TEID" extendable(1) "8.2.3" => FTeid;
    22 "Network Instance" variable "8.2.4" => NetworkInstance;
    23 "SDF Filter" extendable(2) "8.2.5" => SdfFilter;
    24 "Application ID" variable "8.2.6" => ApplicationId;
    25 "Gate Status" extendable(1) "8.2.7" => GateStatus;
    26 "MBR" extendable(10) "8.2.8" => Mbr;
    27 "GBR" extendable(10) "8.2.9" => Gbr;
    28 "QER Correlation ID" extendable(4) "8.2.10" => QerCorrelationId;
    29 "Precedence" extendable(4) "8.2.11" => Precedence;
    30 "Transport Level Marking" extendable(2) "8.2.12" => TransportLevelMarking;
    31 "Volume Threshold" extendable(1) "8.2.13" => VolumeThreshold;
    32 "Time Threshold" extendable(4) "8.2.14" => TimeThreshold;
    33 "Monitoring Time" extendable(4) "8.2.15" => MonitoringTime;
    34 "Subsequent Volume Threshold" extendable(1) "8.2.16" => SubsequentVolumeThreshold;
    35 "Subsequent Time Threshold" extendable(4) "8.2.17" => SubsequentTimeThreshold;
    36 "Inactivity Detection Time" extendable(4) "8.2.18" => InactivityDetectionTime;
    37 "Reporting Triggers" extendable(2) "8.2.19" => ReportingTriggers;
    38 "Redirect Information" extendable(3) "8.2.20" => RedirectInformation;
    39 "Report Type" extendable(1) "8.2.21" => ReportType;
    40 "Offending IE" fixed(2) "8.2.22" => OffendingIe;
    41 "Forwarding Policy" extendable(1) "8.2.23" => ForwardingPolicy;
    42 "Destination Interface" extendable(1) "8.2.24" => DestinationInterface;
    43 "UP Function Features" extendable(1) "8.2.25" => UpFunctionFeatures;
    44 "Apply Action" extendable(1) "8.2.26" => ApplyAction;
    45 "Downlink Data Service Information" extendable(1) "8.2.27" => DownlinkDataServiceInformation;
    46 "Downlink Data Notification Delay" extendable(1) "8.2.28" => DownlinkDataNotificationDelay;
    47 "DL Buffering Duration" extendable(1) "8.2.29" => DlBufferingDuration;
    48 "DL Buffering Suggested Packet Count" variable "8.2.30" => DlBufferingSuggestedPacketCount;
    49 "PFCPSMReq-Flags" extendable(1) "8.2.31" => PFCPSMReqFlags;
    50 "PFCPSRRsp-Flags" extendable(1) "8.2.32" => PFCPSRRspFlags;
    51 "Load Control Information" grouped "7.5.3.3-1" => LoadControlInformation;
    52 "Sequence Number" fixed(4) "8.2.33" => SequenceNumber;
    53 "Metric" fixed(1) "8.2.34" => Metric;
    54 "Overload Control Information" grouped "7.5.3.4-1" => OverloadControlInformation;
    55 "Timer" extendable(1) "8.2.35" => Timer;
    56 "PDR ID" extendable(2) "8.2.36" => PdrId;
    57 "F-SEID" extendable(9) "8.2.37" => FSeid;
    58 "Application ID's PFDs" grouped "7.4.3.1-2" => ApplicationIDsPFDs;
    59 "PFD context" grouped "7.4.3.1-3" => PfdContext;
    60 "Node ID" extendable(1) "8.2.38" => NodeId;
    61 "PFD contents" extendable(2) "8.2.39" => PfdContents;
    62 "Measurement Method" extendable(1) "8.2.40" => MeasurementMethod;
    63 "Usage Report Trigger" extendable(2) "8.2.41" => UsageReportTrigger;
    64 "Measurement Period" extendable(4) "8.2.42" => MeasurementPeriod;
    65 "FQ-CSID" extendable(1) "8.2.43" => FqCsid;
    66 "Volume Measurement" extendable(1) "8.2.44" => VolumeMeasurement;
    67 "Duration Measurement" extendable(4) "8.2.45" => DurationMeasurement;
    68 "Application Detection Information" grouped "7.5.8.3-2" => ApplicationDetectionInformation;
    69 "Time of First Packet" extendable(4) "8.2.46" => TimeOfFirstPacket;
    70 "Time of Last Packet" extendable(4) "8.2.47" => TimeOfLastPacket;
    71 "Quota Holding Time" extendable(4) "8.2.48" => QuotaHoldingTime;
    72 "Dropped DL Traffic Threshold" extendable(1) "8.2.49" => DroppedDlTrafficThreshold;
    73 "Volume Quota" extendable(1) "8.2.50" => VolumeQuota;
    74 "Time Quota" extendable(4) "8.2.51" => TimeQuota;
    75 "Start Time" extendable(4) "8.2.52" => StartTime;
    76 "End Time" extendable(4) "8.2.53" => EndTime;
    77 "Query URR" grouped "7.5.4.10-1" => QueryUrr;
    78 "Usage Report (Session Modification Response)" grouped "7.5.5.2-1" => UsageReportModification;
    79 "Usage Report (Session Deletion Response)" grouped "7.5.7.2-1" => UsageReportDeletion;
    80 "Usage Report (Session Report Request)" grouped "7.5.8.3-1" => UsageReport;
    81 "URR ID" extendable(4) "8.2.54" => UrrId;
    82 "Linked URR ID" extendable(4) "8.2.55" => LinkedUrrId;
    83 "Downlink Data Report" grouped "7.5.8.2-1" => DownlinkDataReport;
    84 "Outer Header Creation" extendable(2) "8.2.56" => OuterHeaderCreation;
    85 "Create BAR" grouped "7.5.2.6-1" => CreateBar;
    86 "Update BAR (Session Modification Request)" grouped "7.5.4.11-1" => UpdateBar;
    87 "Remove BAR" grouped "7.5.4.12-1" => RemoveBar;
    88 "BAR ID" extendable(1) "8.2.57" => BarId;
    89 "CP Function Features" extendable(1) "8.2.58" => CpFunctionFeatures;
    90 "Usage Information" extendable(1) "8.2.59" => UsageInformation;
    91 "Application Instance ID" variable "8.2.60" => ApplicationInstanceId;
    92 "Flow Information" extendable(3) "8.2.61" => FlowInformation;
    93 "UE IP Address" extendable(1) "8.2.62" => UeIpAddress;
    94 "Packet Rate" extendable(1) "8.2.63" => PacketRate;
    95 "Outer Header Removal" extendable(1) "8.2.64" => OuterHeaderRemoval;
    96 "Recovery Time Stamp" extendable(4) "8.2.65" => RecoveryTimeStamp;
    97 "DL Flow Level Marking" extendable(1) "8.2.66" => DlFlowLevelMarking;
    98 "Header Enrichment" extendable(1) "8.2.67" => HeaderEnrichment;
    99 "Error Indication Report" grouped "7.5.8.4-1" => ErrorIndicationReport;
    100 "Measurement Information" extendable(1) "8.2.68" => MeasurementInformation;
    101 "Node Report Type" extendable(1) "8.2.69" => NodeReportType;
    102 "User Plane Path Failure Report" grouped "7.4.5.1.2-1" => UserPlanePathFailureReport;
    103 "Remote GTP-U Peer" extendable(1) "8.2.70" => RemoteGtpUPeer;
    104 "UR-SEQN" fixed(4) "8.2.71" => UrSeqn;
    105 "Update Duplicating Parameters" grouped "7.5.4.3-3" => UpdateDuplicatingParameters;
    106 "Activate Predefined Rules" variable "8.2.72" => ActivatePredefinedRules;
    107 "Deactivate Predefined Rules" variable "8.2.73" => DeactivatePredefinedRules;
    108 "FAR ID" extendable(4) "8.2.74" => FarId;
    109 "QER ID" extendable(4) "8.2.75" => QerId;
    110 "OCI Flags" extendable(1) "8.2.76" => OciFlags;
    111 "PFCP Association Release Request" extendable(1) "8.2.77" => PfcpAssociationReleaseRequest;
    112 "Graceful Release Period" extendable(1) "8.2.78" => GracefulReleasePeriod;
    113 "PDN Type" extendable(1) "8.2.79" => PdnType;
    114 "Failed Rule ID" extendable(1) "8.2.80" => FailedRuleId;
    115 "Time Quota Mechanism" extendable(1) "8.2.81" => TimeQuotaMechanism;
    117 "User Plane Inactivity Timer" extendable(4) "8.2.83" => UserPlaneInactivityTimer;
    118 "Aggregated URRs" grouped "7.5.2.4-2" => AggregatedURRs;
    119 "Multiplier" fixed(12) "8.2.84" => Multiplier;
    120 "Aggregated URR ID" fixed(4) "8.2.85" => AggregatedUrrId;
    121 "Subsequent Volume Quota" extendable(1) "8.2.86" => SubsequentVolumeQuota;
    122 "Subsequent Time Quota" extendable(4) "8.2.87" => SubsequentTimeQuota;
    123 "RQI" extendable(1) "8.2.88" => Rqi;
    124 "QFI" extendable(1) "8.2.89" => Qfi;
    125 "Query URR Reference" extendable(4) "8.2.90" => QueryUrrReference;
    126 "Additional Usage Reports Information" extendable(2) "8.2.91" => AdditionalUsageReportsInformation;
    127 "Create Traffic Endpoint" grouped "7.5.2.7-1" => CreateTrafficEndpoint;
    128 "Created Traffic Endpoint" grouped "7.5.3.5-1" => CreatedTrafficEndpoint;
    129 "Update Traffic Endpoint" grouped "7.5.4.13-1" => UpdateTrafficEndpoint;
    130 "Remove Traffic Endpoint" grouped "7.5.4.14-1" => RemoveTrafficEndpoint;
    131 "Traffic Endpoint ID" extendable(1) "8.2.92" => TrafficEndpointId;
    132 "Ethernet Packet Filter" grouped "7.5.2.2-3" => EthernetPacketFilter;
    133 "MAC address" extendable(1) "8.2.93" => MacAddress;
    134 "C-TAG" extendable(3) "8.2.94" => CTag;
    135 "S-TAG" extendable(3) "8.2.95" => STag;
    136 "Ethertype" extendable(2) "8.2.96" => Ethertype;
    137 "Proxying" extendable(1) "8.2.97" => Proxying;
    138 "Ethernet Filter ID" extendable(4) "8.2.98" => EthernetFilterId;
    139 "Ethernet Filter Properties" extendable(1) "8.2.99" => EthernetFilterProperties;
    140 "Suggested Buffering Packets Count" extendable(1) "8.2.100" => SuggestedBufferingPacketsCount;
    141 "User ID" extendable(1) "8.2.101" => UserId;
    142 "Ethernet PDU Session Information" extendable(1) "8.2.102" => EthernetPduSessionInformation;
    143 "Ethernet Traffic Information" grouped "7.5.8.3-3" => EthernetTrafficInformation;
    144 "MAC Addresses Detected" extendable(7) "8.2.103" => MacAddressesDetected;
    145 "MAC Addresses Removed" extendable(7) "8.2.104" => MacAddressesRemoved;
    146 "Ethernet Inactivity Timer" extendable(4) "8.2.105" => EthernetInactivityTimer;
    147 "Additional Monitoring Time" grouped "7.5.2.4-3" => AdditionalMonitoringTime;
    148 "Event Quota" extendable(4) "8.2.112" => EventQuota;
    149 "Event Threshold" extendable(4) "8.2.113" => EventThreshold;
    150 "Subsequent Event Quota" extendable(4) "8.2.106" => SubsequentEventQuota;
    151 "Subsequent Event Threshold" extendable(4) "8.2.107" => SubsequentEventThreshold;
    152 "Trace Information" extendable(7) "8.2.108" => TraceInformation;
    153 "Framed-Route" variable "8.2.109" => FramedRoute;
    154 "Framed-Routing" fixed(4) "8.2.110" => FramedRouting;
    155 "Framed-IPv6-Route" variable "8.2.111" => FramedIPv6Route;
    156 "Time Stamp" extendable(4) "8.2.114" => TimeStamp;
    157 "Averaging Window" extendable(4) "8.2.115" => AveragingWindow;
    158 "Paging Policy Indicator" extendable(1) "8.2.116" => PagingPolicyIndicator;
    159 "APN/DNN" variable "8.2.117" => ApnDnn;
    160 "3GPP Interface Type" extendable(1) "8.2.118" => InterfaceType3gpp;
    161 "PFCPSRReq-Flags" extendable(1) "8.2.119" => PFCPSRReqFlags;
    162 "PFCPAUReq-Flags" extendable(1) "8.2.120" => PFCPAUReqFlags;
    163 "Activation Time" extendable(4) "8.2.121" => ActivationTime;
    164 "Deactivation Time" extendable(4) "8.2.122" => DeactivationTime;
    165 "Create MAR" grouped "7.5.2.8-1" => CreateMar;
    166 "3GPP Access Forwarding Action Information" grouped "7.5.2.8-2" => ThreeGppAccessForwardingActionInformation;
    167 "Non-3GPP Access Forwarding Action Information" grouped "7.5.2.8-3" => NonThreeGppAccessForwardingActionInformation;
    168 "Remove MAR" grouped "7.5.4.15-1" => RemoveMar;
    169 "Update MAR" grouped "7.5.4.16-1" => UpdateMar;
    170 "MAR ID" extendable(2) "8.2.123" => MarId;
    171 "Steering Functionality" extendable(1) "8.2.124" => SteeringFunctionality;
    172 "Steering Mode" extendable(1) "8.2.125" => SteeringMode;
    173 "Weight" fixed(1) "8.2.126" => Weight;
    174 "Priority" extendable(1) "8.2.127" => Priority;
    175 "Update 3GPP Access Forwarding Action Information" grouped "7.5.4.16-2" => UpdateThreeGppAccessForwardingActionInformation;
    176 "Update Non 3GPP Access Forwarding Action Information" grouped "7.5.4.16-3" => UpdateNonThreeGppAccessForwardingActionInformation;
    177 "UE IP address Pool Identity" extendable(2) "8.2.128" => UeIpAddressPoolIdentity;
    178 "Alternative SMF IP Address" extendable(1) "8.2.129" => AlternativeSmfIpAddress;
    179 "Packet Replication and Detection Carry-On Information" extendable(1) "8.2.130" => PacketReplicationAndDetectionCarryOnInformation;
    180 "SMF Set ID" extendable(1) "8.2.131" => SmfSetId;
    181 "Quota Validity Time" extendable(4) "8.2.132" => QuotaValidityTime;
    182 "Number of Reports" fixed(2) "8.2.133" => NumberOfReports;
    183 "PFCP Session Retention Information (within PFCP Association Setup Request)" grouped "7.4.4.1-2" => PfcpSessionRetentionInformation;
    184 "PFCPASRsp-Flags" extendable(1) "8.2.134" => PFCPASRspFlags;
    185 "CP PFCP Entity IP Address" extendable(1) "8.2.135" => CpPfcpEntityIpAddress;
    186 "PFCPSEReq-Flags" extendable(1) "8.2.136" => PFCPSEReqFlags;
    187 "User Plane Path Recovery Report" grouped "7.4.5.1.3-1" => UserPlanePathRecoveryReport;
    188 "IP Multicast Addressing Info within PFCP Session Establishment Request" grouped "7.5.2.2-4" => IpMulticastAddressingInfo;
    189 "Join IP Multicast Information IE within Usage Report" grouped "7.5.8.3-4" => JoinIpMulticastInformation;
    190 "Leave IP Multicast Information IE within Usage Report" grouped "7.5.8.3-5" => LeaveIpMulticastInformation;
    191 "IP Multicast Address" extendable(1) "8.2.137" => IpMulticastAddress;
    192 "Source IP Address" extendable(1) "8.2.138" => SourceIpAddress;
    193 "Packet Rate Status" extendable(1) "8.2.139" => PacketRateStatus;
    194 "Create Bridge/Router Info" extendable(1) "8.2.140" => CreateBridgeRouterInfo;
    195 "Created Bridge/Router Info" grouped "7.5.3.6-1" => CreatedBridgeRouterInfo;
    196 "Port Number" fixed(4) "8.2.141" => PortNumber;
    197 "NW-TT Port Number" fixed(4) "8.2.142" => NwTtPortNumber;
    198 "5GS User Plane Node ID" extendable "8.2.143" => FiveGsUserPlaneNodeId;
    199 "TSC Management Information IE within PFCP Session Modification Request" grouped "7.5.4.18-1" => TscManagementInformation;
    200 "TSC Management Information IE within PFCP Session Modification Response" grouped "7.5.5.3-1" => TscManagementInformationResponse;
    201 "TSC Management Information IE within PFCP Session Report Request" grouped "7.5.8.5-1" => TscManagementInformationReport;
    202 "Port Management Information Container" variable "8.2.144" => PortManagementInformationContainer;
    203 "Clock Drift Control Information" grouped "7.4.4.1.2-1" => ClockDriftControlInformation;
    204 "Requested Clock Drift Information" extendable(1) "8.2.145" => RequestedClockDriftInformation;
    205 "Clock Drift Report" grouped "7.4.5.1.4-1" => ClockDriftReport;
    206 "Time Domain Number" extendable(1) "8.2.146" => TimeDomainNumber;
    207 "Time Offset Threshold" extendable(8) "8.2.147" => TimeOffsetThreshold;
    208 "Cumulative rateRatio Threshold" extendable(4) "8.2.148" => CumulativeRateRatioThreshold;
    209 "Time Offset Measurement" extendable(8) "8.2.149" => TimeOffsetMeasurement;
    210 "Cumulative rateRatio Measurement" extendable(4) "8.2.150" => CumulativeRateRatioMeasurement;
    211 "Remove SRR" grouped "7.5.4.19-1" => RemoveSrr;
    212 "Create SRR" grouped "7.5.2.9-1" => CreateSrr;
    213 "Update SRR" grouped "7.5.4.20-1" => UpdateSrr;
    214 "Session Report" grouped "7.5.7.3-1" => SessionReportDeletion, SessionReport;
    215 "SRR ID" extendable(1) "8.2.151" => SrrId;
    216 "Access Availability Control Information" grouped "7.5.2.9-2" => AccessAvailabilityControlInformation;
    217 "Requested Access Availability Information" extendable(1) "8.2.152" => RequestedAccessAvailabilityInformation;
    218 "Access Availability Report" grouped "7.5.8.6-2" => AccessAvailabilityReport;
    219 "Access Availability Information" extendable(1) "8.2.153" => AccessAvailabilityInformation;
    220 "Provide ATSSS Control Information" grouped "7.5.2.10-1" => ProvideAtsssControlInformation;
    221 "ATSSS Control Parameters" grouped "7.5.3.7-1" => AtsssControlParameters;
    222 "MPTCP Control Information" extendable(1) "8.2.154" => MptcpControlInformation;
    223 "ATSSS-LL Control Information" extendable(1) "8.2.155" => AtsssLlControlInformation;
    224 "PMF Control Information" extendable(1) "8.2.156" => PmfControlInformation;
    225 "MPTCP Parameters" grouped "7.5.3.7-2" => MptcpParameters;
    226 "ATSSS-LL Parameters" grouped "7.5.3.7-3" => AtsssLlParameters;
    227 "PMF Parameters" grouped "7.5.3.7-4" => PmfParameters;
    228 "MPTCP Address Information" extendable(4) "8.2.157" => MptcpAddressInformation;
    229 "Link-Specific Multipath IP Address" extendable(1) "8.2.158" => LinkSpecificMultipathIpAddress;
    230 "PMF Address Information" extendable(1) "8.2.159" => PmfAddressInformation;
    231 "ATSSS-LL Information" extendable(1) "8.2.160" => AtsssLlInformation;
    232 "Data Network Access Identifier" variable "8.2.161" => DataNetworkAccessIdentifier;
    233 "UE IP address Pool Information" grouped "7.4.4.1-3" => UeIpAddressPoolInformation;
    234 "Average Packet Delay" extendable(4) "8.2.162" => AveragePacketDelay;
    235 "Minimum Packet Delay" extendable(4) "8.2.163" => MinimumPacketDelay;
    236 "Maximum Packet Delay" extendable(4) "8.2.164" => MaximumPacketDelay;
    237 "QoS Report Trigger" extendable(1) "8.2.165" => QoSReportTrigger;
    238 "GTP-U Path QoS Control Information" grouped "7.4.4.1.3-1" => GtpUPathQoSControlInformation;
    239 "GTP-U Path QoS Report (PFCP Node Report Request)" grouped "7.4.5.1.5-1" => GtpuPathQosReport;
    240 "QoS Information in GTP-U Path QoS Report" grouped "7.4.5.1.6-1" => QoSInformation;
    241 "GTP-U Path Interface Type" extendable(1) "8.2.166" => GtpUPathInterfaceType;
    242 "QoS Monitoring per QoS flow Control Information" grouped "7.5.2.9-3" => QoSMonitoringPerQoSFlowControlInformation;
    243 "Requested QoS Monitoring" extendable(1) "8.2.167" => RequestedQoSMonitoring;
    244 "Reporting Frequency" extendable(1) "8.2.168" => ReportingFrequency;
    245 "Packet Delay Thresholds" extendable(1) "8.2.169" => PacketDelayThresholds;
    246 "Minimum Wait Time" extendable(4) "8.2.170" => MinimumWaitTime;
    247 "QoS Monitoring Report" grouped "7.5.8.6-3" => QoSMonitoringReport;
    248 "QoS Monitoring Measurement" extendable(1) "8.2.171" => QoSMonitoringMeasurement;
    249 "MT-EDT Control Information" extendable(1) "8.2.172" => MtEdtControlInformation;
    250 "DL Data Packets Size" extendable(2) "8.2.173" => DlDataPacketsSize;
    251 "QER Control Indications" extendable(1) "8.2.174" => QerControlIndications;
    252 "Packet Rate Status Report" grouped "7.5.7.1-2" => PacketRateStatusReport;
    253 "NF Instance ID" fixed(16) "8.2.175" => NfInstanceId;
    254 "Ethernet Context Information" grouped "7.5.4.21-1" => EthernetContextInformation;
    255 "Redundant Transmission Parameters" grouped "7.5.2.2-5" => RedundantTransmissionParameters;
    256 "Updated PDR" grouped "7.5.5.5-1" => UpdatedPdr;
    257 "S-NSSAI" fixed(4) "8.2.176" => SNssai;
    258 "IP version" extendable(1) "8.2.177" => IpVersion;
    259 "PFCPASReq-Flags" extendable(1) "8.2.178" => PFCPASReqFlags;
    260 "Data Status" extendable(1) "8.2.179" => DataStatus;
    261 "Provide RDS configuration information" grouped "7.5.2.11-1" => ProvideRdsConfigurationInformation;
    262 "RDS configuration information" extendable(1) "8.2.180" => RdsConfigurationInformation;
    263 "Query Packet Rate Status IE within PFCP Session Modification Request" grouped "7.5.4.22-1" => QueryPacketRateStatus;
    264 "Packet Rate Status Report IE within PFCP Session Modification Response" grouped "7.5.5.4-1" => PacketRateStatusReportModification;
    265 "Multipath Applicable Indication" extendable(1) "8.2.181" => MultipathApplicableIndication;
    266 "User Plane Node Management Information Container" variable "8.2.182" => UserPlaneNodeManagementInformationContainer;
    267 "UE IP Address Usage Information" grouped "7.4.4.3.1-1" => UeIpAddressUsageInformation;
    268 "Number of UE IP Addresses" extendable(1) "8.2.183" => NumberOfUeIpAddresses;
    269 "Validity Timer" extendable(2) "8.2.184" => ValidityTimer;
    270 "Redundant Transmission Forwarding Parameters" grouped "7.5.2.3-4" => RedundantTransmissionForwardingParameters;
    271 "Transport Delay Reporting" grouped "7.5.2.2-6" => TransportDelayReporting;
    272 "Partial Failure Information" grouped "7.5.3.1-2" => PartialFailureInformation;
    274 "Offending IE Information" variable "8.2.185" => OffendingIeInformation;
    275 "RAT Type" extendable(1) "8.2.186" => RatType;
    276 "L2TP Tunnel Information" grouped "7.5.2.1-2" => L2tpTunnelInformation;
    277 "L2TP Session Information" grouped "7.5.2.1-3" => L2tpSessionInformation;
    278 "L2TP User Authentication" extendable(1) "8.2.187" => L2tpUserAuthentication;
    279 "Created L2TP Session" grouped "7.5.3.1-3" => CreatedL2tpSession;
    280 "LNS Address" extendable(4) "8.2.188" => LnsAddress;
    281 "Tunnel Preference" fixed(3) "8.2.189" => TunnelPreference;
    282 "Calling Number" variable "8.2.190" => CallingNumber;
    283 "Called Number" variable "8.2.191" => CalledNumber;
    284 "L2TP Session Indications" extendable(1) "8.2.192" => L2tpSessionIndications;
    285 "DNS Server Address" extendable(4) "8.2.193" => DnsServerAddress;
    286 "NBNS Server Address" extendable(4) "8.2.194" => NbnsServerAddress;
    287 "Maximum Receive Unit" fixed(2) "8.2.195" => MaximumReceiveUnit;
    288 "Thresholds" extendable(1) "8.2.196" => Thresholds;
    289 "Steering Mode Indicator" extendable(1) "8.2.197" => SteeringModeIndicator;
    290 "PFCP Session Change Info" grouped "7.4.7.1-2" => PfcpSessionChangeInfo;
    291 "Group ID" variable "8.2.198" => GroupId;
    292 "CP IP Address" variable "8.2.199" => CpIpAddress;
    293 "IP Address and Port number Replacement" extendable(2) "8.2.200" => IpAddressAndPortNumberReplacement;
    294 "DNS Query/Response Filter" extendable(2) "8.2.201" => DnsQueryResponseFilter;
    295 "Direct Reporting Information" grouped "7.5.2.9-4" => DirectReportingInformation, DirectReportingInformationTsc;
    296 "Event Notification URI" variable "8.2.202" => EventNotificationUri;
    297 "Notification Correlation ID" variable "8.2.203" => NotificationCorrelationId;
    298 "Reporting Flags" extendable(1) "8.2.204" => ReportingFlags;
    299 "Predefined Rules Name" variable "8.2.205" => PredefinedRulesName;
    300 "MBS Session N4mb Control Information" grouped "7.5.2.1-4" => MbsSessionN4mbControlInformation;
    301 "MBS Multicast Parameters" grouped "7.5.2.3-5" => MbsMulticastParameters;
    302 "Add MBS Unicast Parameters" grouped "7.5.2.3-6" => AddMbsUnicastParameters;
    303 "MBS Session N4mb Information" grouped "7.5.3.1-4" => MbsSessionN4mbInformation;
    304 "Remove MBS Unicast Parameters" grouped "7.5.4.3-4" => RemoveMbsUnicastParameters;
    305 "MBS Session Identifier" extendable(1) "8.2.206" => MbsSessionIdentifier;
    306 "Multicast Transport Information" extendable(5) "8.2.207" => MulticastTransportInformation;
    307 "MBSN4mbReq-Flags" extendable(1) "8.2.208" => MBSN4mbReqFlags;
    308 "Local Ingress Tunnel" extendable(1) "8.2.209" => LocalIngressTunnel;
    309 "MBS Unicast Parameters ID" extendable(2) "8.2.210" => MbsUnicastParametersId;
    310 "MBS Session N4 Control Information" grouped "7.5.2.1-5" => MbsSessionN4ControlInformation;
    311 "MBS Session N4 Information" grouped "7.5.3.1-5" => MbsSessionN4Information;
    312 "MBSN4Resp-Flags" extendable(1) "8.2.211" => MBSN4RespFlags;
    313 "Tunnel Password" variable "8.2.212" => TunnelPassword;
    314 "Area Session ID" fixed(2) "8.2.213" => AreaSessionId;
    315 "Peer UP Restart Report" grouped "7.4.5.1.7-1" => PeerUpRestartReport;
    316 "DSCP to PPI Control Information" grouped "7.5.2.1-6" => DscpToPpiControlInformation;
    317 "DSCP to PPI Mapping Information" extendable(2) "8.2.214" => DscpToPpiMappingInformation;
    318 "PFCPSDRsp-Flags" extendable(1) "8.2.215" => PFCPSDRspFlags;
    319 "QER Indications" extendable(1) "8.2.216" => QerIndications;
    320 "Vendor-Specific Node Report Type" extendable(3) "8.2.217" => VendorSpecificNodeReportType;
    321 "Configured Time Domain" extendable(1) "8.2.218" => ConfiguredTimeDomain;
    322 "Metadata" variable "8.2.219" => Metadata;
    323 "Traffic Parameter Measurement Control Information" grouped "7.5.2.9-5" => TrafficParameterMeasurementControlInformation;
    324 "Traffic Parameter Measurement Report" grouped "7.5.8.6-4" => TrafficParameterMeasurementReport;
    325 "Traffic Parameter Threshold" extendable(1) "8.2.220" => TrafficParameterThreshold;
    326 "DL Periodicity" extendable(5) "8.2.221" => DlPeriodicity;
    327 "N6 Jitter Measurement" extendable(1) "8.2.222" => N6JitterMeasurement;
    328 "Traffic Parameter Measurement Indication" extendable(1) "8.2.223" => TrafficParameterMeasurementIndication;
    329 "UL Periodicity" extendable(5) "8.2.224" => UlPeriodicity;
    330 "MPQUIC Control Information" extendable(1) "8.2.225" => MpquicControlInformation;
    331 "MPQUIC Parameters" grouped "7.5.3.7-5" => MpquicParameters;
    332 "MPQUIC Address Information" extendable(4) "8.2.226" => MpquicAddressInformation;
    333 "Transport Mode" extendable(1) "8.2.227" => TransportMode;
    334 "Protocol Description" grouped "7.5.2.2-7" => ProtocolDescription;
    335 "Reporting Suggestion Info" extendable(1) "8.2.229" => ReportingSuggestionInfo;
    336 "TL-Container" variable "8.2.230" => TlContainer;
    337 "Measurement Indication" extendable(1) "8.2.231" => MeasurementIndication;
    338 "HPLMN S-NSSAI" fixed(4) "8.2.232" => HplmnSNssai;
    339 "Media Transport Protocol" extendable(1) "8.2.233" => MediaTransportProtocol;
    340 "RTP Header Extension Information" grouped "7.5.2.2-8" => RtpHeaderExtensionInformation;
    341 "RTP Payload Information" grouped "7.5.2.2-9" => RtpPayloadInformation;
    342 "RTP Header Extension Type" fixed(1) "8.2.234" => RtpHeaderExtensionType;
    343 "RTP Header Extension ID" fixed(1) "8.2.235" => RtpHeaderExtensionId;
    344 "RTP Payload Type" fixed(1) "8.2.236" => RtpPayloadType;
    345 "RTP Payload Format" fixed(1) "8.2.237" => RtpPayloadFormat;
    346 "Extended DL Buffering Notification Policy" extendable(1) "8.2.238" => ExtendedDlBufferingNotificationPolicy;
    347 "MT-SDT Control Information" extendable(1) "8.2.239" => MtSdtControlInformation;
    348 "Reporting Thresholds" extendable(1) "8.2.240" => ReportingThresholds;
    349 "RTP Header Extension Additional Information" extendable(2) "8.2.241" => RtpHeaderExtensionAdditionalInformation;
    350 "Mapped N6 IP Address" extendable(1) "8.2.242" => MappedN6IpAddress;
    351 "N6 Routing Information" extendable(1) "8.2.243" => N6RoutingInformation;
    352 "URI" variable "8.2.244" => Uri;
    353 "UE Level Measurements Configuration" extendable(2) "8.2.245" => UeLevelMeasurementsConfiguration;
    354 "N6 Delay Measurement Protocols" extendable(1) "8.2.246" => N6DelayMeasurementProtocols;
    355 "N6 Delay Measurement Control Information" grouped "7.4.4.1.4-1" => N6DelayMeasurementControlInformation;
    356 "N6 Delay Measurement Report (PFCP Node Report Request)" grouped "7.4.5.1.8-1" => N6DelayMeasurementReport;
    357 "N6 Delay Measurement Information" extendable(1) "8.2.247" => N6DelayMeasurementInformation;
    358 "Measurement Endpoint Address" extendable(1) "8.2.248" => MeasurementEndpointAddress;
    359 "Operator Configurable UPF Capability" variable "8.2.249" => OperatorConfigurableUpfCapability;
    360 "Packet Inspection functionality" extendable(1) "8.2.250" => PacketInspectionFunctionality;
    361 "Header Handling Control Rule" grouped "7.5.2.3-7" => HeaderHandlingControlRule;
    362 "Header Handling Reporting Control Info" grouped "7.5.2.3-8" => HeaderHandlingReportingControlInfo;
    363 "Header Handling Control information" grouped "7.5.2.3-9" => HeaderHandlingControlInformation;
    364 "Header Detection Reference" variable "8.2.251" => HeaderDetectionReference;
    365 "Header Detection Support Information" variable "8.2.252" => HeaderDetectionSupportInformation;
    366 "Reporting Endpoint ID" fixed(1) "8.2.253" => ReportingEndpointId;
    367 "Header Handling Control Reference" variable "8.2.254" => HeaderHandlingControlReference;
    368 "Header Handling Action" fixed(1) "8.2.255" => HeaderHandlingAction;
    369 "Header Information" variable "8.2.256" => HeaderInformation;
    370 "Header Value" variable "8.2.257" => HeaderValue;
    371 "Header Handling Condition" fixed(1) "8.2.258" => HeaderHandlingCondition;
    372 "Header Handling Control ID" fixed(1) "8.2.259" => HeaderHandlingControlId;
    373 "Header Handling Control Rule ID" fixed(1) "8.2.260" => HeaderHandlingControlRuleId;
    374 "On-path N6 Connection Information" extendable(1) "8.2.261" => OnPathN6ConnectionInformation;
    375 "Measurement Reporting Type" extendable(1) "8.2.262" => MeasurementReportingType;
    376 "N6 Delay Measurement Failure Information" extendable(1) "8.2.263" => N6DelayMeasurementFailureInformation;
    377 "N6 Delay Measurement Control Information ID" fixed(2) "8.2.264" => N6DelayMeasurementControlInformationId;
    378 "Protocol Specific Configuration Parameters" grouped "7.4.4.1.4-2" => ProtocolSpecificConfigurationParameters;
    379 "Measurement Endpoint Port Number" fixed(2) "8.2.265" => MeasurementEndpointPortNumber;
    380 "Header Handling Reporting Indication" extendable(1) "8.2.266" => HeaderHandlingReportingIndication;
    382 "SMF Change Reason" extendable(1) "8.2.267" => SmfChangeReason;
    383 "Extended Transport Level Marking" grouped "7.5.2.3-10" => ExtendedTransportLevelMarking;
    384 "PDU Set Importance" fixed(2) "8.2.268" => PduSetImportance;
    385 "MoQ Control Information" extendable(1) "8.2.269" => MoQControlInformation;
    386 "MoQ Information" grouped "7.5.3.1-6" => MoQInformation;
    387 "MoQ Relay IP Address" extendable(1) "8.2.270" => MoQRelayIpAddress;
    388 "Media Related Information Transfer Info" extendable(1) "8.2.271" => MediaRelatedInformationTransferInfo;
    389 "Reporting Control Information" extendable(1) "8.2.272" => ReportingControlInformation;
    390 "Security Mode (STAMP)" fixed(1) "8.2.273" => SecurityMode;
    391 "HMAC Key (STAMP)" variable "8.2.274" => HmacKeyStamp;
    392 "Security Mode (OWAMP or TWAMP)" fixed(4) "8.2.275" => SecurityModeValue;
    393 "Key ID and Shared Secret (OWAMP or TWAMP)" extendable(1) "8.2.276" => KeyIdAndSharedSecret;
    394 "Remaining Data Reporting Indication" extendable(1) "8.2.277" => RemainingDataReportingIndication;
    395 "Expedited Transfer Indication" fixed(1) "8.2.278" => ExpeditedTransferIndication;
    396 "Session Reflector Mode (STAMP)" fixed(1) "8.2.279" => SessionReflectorMode;
    397 "PFD Partial Failure Information" grouped "7.4.3.2-2" => PfdPartialFailureInformation;
    398 "Transport Level Marking Indications" fixed(1) "8.2.280" => TransportLevelMarkingIndications;
    399 "Redundant N3/N9 Transmission Information" grouped "7.5.8.6-5" => RedundantN3n9TransmissionInformation;
    400 "Local N3/N9 Tunnel Information" grouped "7.5.8.6-6" => LocalN3n9TunnelInformation;
    401 "Remote N3/N9 Tunnel Information" grouped "7.5.8.6-7" => RemoteN3n9TunnelInformation;
    402 "Binding Indication" variable "8.2.281" => BindingIndication;
    403 "PDU Set Importance for N6-unmarked PDUs" fixed(1) "8.2.282" => PduSetImportanceForN6UnmarkedPDUs;
}

pfcp_table! {
    /// PFCP Version Not Supported Response (§7.4.4.7): no IEs.
    message VersionNotSupportedResponse = 11, "PFCP Version Not Supported Response", "7.4.4.7" {
    }
}

pfcp_table! {
    /// PFCP Heartbeat Request (Table 7.4.2.1-1).
    message HeartbeatRequest = 1, "PFCP Heartbeat Request", "7.4.2.1-1" {
        recovery_time_stamp: "Recovery Time Stamp" M RecoveryTimeStamp [SXA SXB SXC N4 N4MB],
        source_ip_address: "Source IP Address" O SourceIpAddress [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// PFCP Heartbeat Response (Table 7.4.2.2-1).
    message HeartbeatResponse = 2, "PFCP Heartbeat Response", "7.4.2.2-1" {
        recovery_time_stamp: "Recovery Time Stamp" M RecoveryTimeStamp [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// PFCP PFD Management Request (Table 7.4.3.1-1).
    message PfdManagementRequest = 3, "PFCP PFD Management Request", "7.4.3.1-1" {
        application_ids_pfds: "Application ID's PFDs" C* ApplicationIDsPFDs [SXB SXC N4],
        node_id: "Node ID" O NodeId [SXB SXC N4],
    }
}

pfcp_table! {
    /// PFCP PFD Management Response (Table 7.4.3.2-1).
    message PfdManagementResponse = 4, "PFCP PFD Management Response", "7.4.3.2-1" {
        cause: "Cause" M Cause [SXB SXC N4],
        offending_ie: "Offending IE" C OffendingIe [SXB SXC N4] if |s| cause_is(&s.cause, &OF_AN_IE),
        node_id: "Node ID" O NodeId [SXB SXC N4],
        pfd_partial_failure_information: "PFD Partial Failure Information" C* PfdPartialFailureInformation [SXB SXC N4] if |s| cause_is(&s.cause, &[CauseValue::RequestPartiallyAccepted]),
    }
}

pfcp_table! {
    /// PFCP Association Setup Request (Table 7.4.4.1-1).
    message AssociationSetupRequest = 5, "PFCP Association Setup Request", "7.4.4.1-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        recovery_time_stamp: "Recovery Time Stamp" M RecoveryTimeStamp [SXA SXB SXC N4 N4MB],
        up_function_features: "UP Function Features" C UpFunctionFeatures [SXA SXB SXC N4 N4MB],
        cp_function_features: "CP Function Features" C CpFunctionFeatures [SXA SXB SXC N4 N4MB],
        alternative_smf_ip_address: "Alternative SMF IP Address" O* AlternativeSmfIpAddress [N4 N4MB],
        smf_set_id: "SMF Set ID" C SmfSetId [N4 N4MB],
        pfcp_session_retention_information: "PFCP Session Retention Information" O PfcpSessionRetentionInformation [SXA SXB SXC N4 N4MB],
        ue_ip_address_pool_information: "UE IP address Pool Information" O* UeIpAddressPoolInformation [SXB N4],
        gtp_u_path_qos_control_information: "GTP-U Path QoS Control Information" C* GtpUPathQoSControlInformation [N4],
        clock_drift_control_information: "Clock Drift Control Information" O* ClockDriftControlInformation [N4],
        upf_instance_id: "UPF Instance ID" C NfInstanceId [N4 N4MB],
        pfcpasreq_flags: "PFCPASReq-Flags" O PFCPASReqFlags [N4],
        n6_delay_measurement_control_information: "N6 Delay Measurement Control Information" C* N6DelayMeasurementControlInformation [N4],
        n6_delay_measurement_protocols: "N6 Delay Measurement Protocols" C N6DelayMeasurementProtocols [N4],
        operator_configurable_upf_capability: "Operator Configurable UPF Capability" O* OperatorConfigurableUpfCapability [N4],
        packet_inspection_functionality: "Packet Inspection functionality" O PacketInspectionFunctionality [N4],
    }
}

pfcp_table! {
    /// PFCP Association Setup Response (Table 7.4.4.2-1).
    message AssociationSetupResponse = 6, "PFCP Association Setup Response", "7.4.4.2-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        cause: "Cause" M Cause [SXA SXB SXC N4 N4MB],
        recovery_time_stamp: "Recovery Time Stamp" M RecoveryTimeStamp [SXA SXB SXC N4 N4MB],
        up_function_features: "UP Function Features" C UpFunctionFeatures [SXA SXB SXC N4 N4MB],
        cp_function_features: "CP Function Features" C CpFunctionFeatures [SXA SXB SXC N4 N4MB],
        alternative_smf_ip_address: "Alternative SMF IP Address" O* AlternativeSmfIpAddress [N4 N4MB],
        smf_set_id: "SMF Set ID" C SmfSetId [N4 N4MB],
        pfcpasrsp_flags: "PFCPASRsp-Flags" O PFCPASRspFlags [SXA SXB SXC N4 N4MB],
        clock_drift_control_information: "Clock Drift Control Information" C* ClockDriftControlInformation [N4],
        ue_ip_address_pool_information: "UE IP address Pool Information" O* UeIpAddressPoolInformation [SXB N4],
        gtp_u_path_qos_control_information: "GTP-U Path QoS Control Information" C* GtpUPathQoSControlInformation [N4],
        upf_instance_id: "UPF Instance ID" C NfInstanceId [N4 N4MB],
        n6_delay_measurement_control_information: "N6 Delay Measurement Control Information" C* N6DelayMeasurementControlInformation [N4],
        n6_delay_measurement_protocols: "N6 Delay Measurement Protocols" C N6DelayMeasurementProtocols [N4],
        operator_configurable_upf_capability: "Operator Configurable UPF Capability" O* OperatorConfigurableUpfCapability [N4],
        packet_inspection_functionality: "Packet Inspection functionality" O PacketInspectionFunctionality [N4],
    }
}

pfcp_table! {
    /// PFCP Association Update Request (Table 7.4.4.3-1).
    message AssociationUpdateRequest = 7, "PFCP Association Update Request", "7.4.4.3-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        up_function_features: "UP Function Features" O UpFunctionFeatures [SXA SXB SXC N4 N4MB],
        cp_function_features: "CP Function Features" O CpFunctionFeatures [SXA SXB SXC N4 N4MB],
        pfcp_association_release_request: "PFCP Association Release Request" C PfcpAssociationReleaseRequest [SXA SXB SXC N4 N4MB],
        graceful_release_period: "Graceful Release Period" C GracefulReleasePeriod [SXA SXB SXC N4 N4MB],
        pfcpaureq_flags: "PFCPAUReq-Flags" O PFCPAUReqFlags [SXA SXB SXC N4],
        alternative_smf_ip_address: "Alternative SMF IP Address" O* AlternativeSmfIpAddress [N4 N4MB],
        smf_set_id: "SMF Set ID" O SmfSetId [N4 N4MB],
        clock_drift_control_information: "Clock Drift Control Information" C* ClockDriftControlInformation [N4],
        ue_ip_address_pool_information: "UE IP address Pool Information" O* UeIpAddressPoolInformation [SXB N4],
        gtp_u_path_qos_control_information: "GTP-U Path QoS Control Information" C* GtpUPathQoSControlInformation [N4],
        ue_ip_address_usage_information: "UE IP Address Usage Information" O* UeIpAddressUsageInformation [SXB N4],
        n6_delay_measurement_control_information: "N6 Delay Measurement Control Information" C* N6DelayMeasurementControlInformation [N4],
        n6_delay_measurement_protocols: "N6 Delay Measurement Protocols" C N6DelayMeasurementProtocols [N4],
        operator_configurable_upf_capability: "Operator Configurable UPF Capability" C* OperatorConfigurableUpfCapability [N4],
        packet_inspection_functionality: "Packet Inspection functionality" O PacketInspectionFunctionality [N4],
    }
}

pfcp_table! {
    /// PFCP Association Update Response (Table 7.4.4.4-1).
    message AssociationUpdateResponse = 8, "PFCP Association Update Response", "7.4.4.4-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        cause: "Cause" M Cause [SXA SXB SXC N4 N4MB],
        up_function_features: "UP Function Features" O UpFunctionFeatures [SXA SXB SXC N4 N4MB],
        cp_function_features: "CP Function Features" O CpFunctionFeatures [SXA SXB SXC N4 N4MB],
        ue_ip_address_usage_information: "UE IP Address Usage Information" O* UeIpAddressUsageInformation [SXB N4],
        n6_delay_measurement_protocols: "N6 Delay Measurement Protocols" O N6DelayMeasurementProtocols [N4],
        operator_configurable_upf_capability: "Operator Configurable UPF Capability" C* OperatorConfigurableUpfCapability [N4],
        packet_inspection_functionality: "Packet Inspection functionality" O PacketInspectionFunctionality [N4],
    }
}

pfcp_table! {
    /// PFCP Association Release Request (Table 7.4.4.5-1).
    message AssociationReleaseRequest = 9, "PFCP Association Release Request", "7.4.4.5-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// PFCP Association Release Response (Table 7.4.4.6-1).
    message AssociationReleaseResponse = 10, "PFCP Association Release Response", "7.4.4.6-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        cause: "Cause" M Cause [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// PFCP Node Report Request (Table 7.4.5.1.1-1).
    message NodeReportRequest = 12, "PFCP Node Report Request", "7.4.5.1.1-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        node_report_type: "Node Report Type" M NodeReportType [SXA SXB SXC N4 N4MB],
        vendor_specific_node_report_type: "Vendor-Specific Node Report Type" C VendorSpecificNodeReportType [SXA SXB SXC N4 N4MB] if |s| s.node_report_type.as_ref().is_some_and(|t| t.vsr),
        user_plane_path_failure_report: "User Plane Path Failure Report" C UserPlanePathFailureReport [SXA SXB N4 N4MB] if |s| s.node_report_type.as_ref().is_some_and(|t| t.upfr),
        user_plane_path_recovery_report: "User Plane Path Recovery Report" C UserPlanePathRecoveryReport [SXA SXB N4 N4MB] if |s| s.node_report_type.as_ref().is_some_and(|t| t.uprr),
        clock_drift_report: "Clock Drift Report" C* ClockDriftReport [N4] if |s| s.node_report_type.as_ref().is_some_and(|t| t.ckdr),
        gtp_u_path_qos_report: "GTP-U Path QoS Report" C* GtpuPathQosReport [N4] if |s| s.node_report_type.as_ref().is_some_and(|t| t.gpqr),
        peer_up_restart_report: "Peer UP Restart Report" C PeerUpRestartReport [SXA SXB N4] if |s| s.node_report_type.as_ref().is_some_and(|t| t.purr),
        n6_delay_measurement_report: "N6 Delay Measurement Report" C* N6DelayMeasurementReport [N4] if |s| s.node_report_type.as_ref().is_some_and(|t| t.n6dr),
    }
}

pfcp_table! {
    /// PFCP Node Report Response (Table 7.4.5.2.1-1).
    message NodeReportResponse = 13, "PFCP Node Report Response", "7.4.5.2.1-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        cause: "Cause" M Cause [SXA SXB SXC N4 N4MB],
        offending_ie: "Offending IE" C OffendingIe [SXA SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &OF_AN_IE),
    }
}

pfcp_table! {
    /// PFCP Session Set Deletion Request (Table 7.4.6.1-1).
    message SessionSetDeletionRequest = 14, "PFCP Session Set Deletion Request", "7.4.6.1-1" {
        node_id: "Node ID" M NodeId [SXA SXB N4],
        fq_csid: "FQ-CSID" C*6 FqCsid [SXA SXB N4]
            roles ["SGW-C FQ-CSID" C [SXA SXB], "PGW-C/SMF FQ-CSID" C [SXA SXB N4], "PGW-U/SGW-U/ UPF FQ-CSID" C [SXA SXB N4], "TWAN FQ-CSID" C [SXB], "ePDG FQ-CSID" C [SXB], "MME FQ-CSID" C [SXA SXB]],
    }
}

pfcp_table! {
    /// PFCP Session Set Deletion Response (Table 7.4.6.2-1).
    message SessionSetDeletionResponse = 15, "PFCP Session Set Deletion Response", "7.4.6.2-1" {
        node_id: "Node ID" M NodeId [SXA SXB N4],
        cause: "Cause" M Cause [SXA SXB N4],
        offending_ie: "Offending IE" C OffendingIe [SXA SXB N4] if |s| cause_is(&s.cause, &OF_AN_IE),
    }
}

pfcp_table! {
    /// PFCP Session Set Modification Request (Table 7.4.7.1-1).
    message SessionSetModificationRequest = 16, "PFCP Session Set Modification Request", "7.4.7.1-1" {
        node_id: "Node ID" M NodeId [SXB N4],
        pfcp_session_change_info: "PFCP Session Change Info" M* PfcpSessionChangeInfo [SXB N4],
    }
}

pfcp_table! {
    /// PFCP Session Set Modification Response (Table 7.4.7.2-1, which V19.6.0 numbers
    /// 7.4.2.2-1, as the table of Heartbeat Response).
    message SessionSetModificationResponse = 17, "PFCP Session Set Modification Response", "7.4.7.2-1" {
        node_id: "Node ID" M NodeId [SXB N4],
        cause: "Cause" M Cause [SXB N4],
        offending_ie: "Offending IE" C OffendingIe [SXB N4] if |s| cause_is(&s.cause, &OF_AN_IE),
    }
}

pfcp_table! {
    /// PFCP Session Establishment Request (Table 7.5.2.1-1).
    message SessionEstablishmentRequest = 50, "PFCP Session Establishment Request", "7.5.2.1-1" by [SXA SXB SXC N4 N4MB] {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        cp_f_seid: "CP F-SEID" M FSeid [SXA SXB SXC N4 N4MB],
        create_pdr: "Create PDR" M* CreatePdr [SXA SXB SXC N4 N4MB],
        create_far: "Create FAR" M* CreateFar [SXA SXB SXC N4 N4MB],
        create_urr: "Create URR" C* CreateUrr [SXA SXB SXC N4 N4MB],
        create_qer: "Create QER" C* CreateQer [SXB SXC N4 N4MB],
        create_bar: "Create BAR" O CreateBar [SXA N4],
        create_traffic_endpoint: "Create Traffic Endpoint" C* CreateTrafficEndpoint [SXA SXB SXC N4 N4MB],
        pdn_type: "PDN Type" C PdnType [SXA SXB N4],
        fq_csid: "FQ-CSID" C*5 FqCsid [SXA SXB N4]
            roles ["SGW-C FQ-CSID" C [SXA SXB], "MME FQ-CSID" C [SXA SXB], "PGW-C/SMF FQ-CSID" C [SXA SXB N4], "ePDG FQ-CSID" C [SXB], "TWAN FQ-CSID" C [SXB]],
        user_plane_inactivity_timer: "User Plane Inactivity Timer" O UserPlaneInactivityTimer [SXB SXC N4 N4MB],
        user_id: "User ID" O UserId [SXA SXB SXC N4],
        trace_information: "Trace Information" O TraceInformation [SXA SXB SXC N4],
        apn_dnn: "APN/DNN" O ApnDnn [SXA SXB N4 N4MB],
        create_mar: "Create MAR" C* CreateMar [N4],
        pfcpsereq_flags: "PFCPSEReq-Flags" C PFCPSEReqFlags [SXA SXB N4],
        create_bridge_router_info: "Create Bridge/Router Info" C CreateBridgeRouterInfo [N4],
        create_srr: "Create SRR" O* CreateSrr [N4],
        provide_atsss_control_information: "Provide ATSSS Control Information" C ProvideAtsssControlInformation [N4],
        recovery_time_stamp: "Recovery Time Stamp" O RecoveryTimeStamp [SXA SXB SXC N4],
        s_nssai: "S-NSSAI" O SNssai [N4 N4MB],
        hplmn_s_nssai: "HPLMN S-NSSAI" C HplmnSNssai [N4],
        provide_rds_configuration_information: "Provide RDS configuration information" O ProvideRdsConfigurationInformation [SXB N4],
        rat_type: "RAT Type" O RatType [SXA SXB N4],
        l2tp_tunnel_information: "L2TP Tunnel Information" C* L2tpTunnelInformation [SXB N4],
        l2tp_session_information: "L2TP Session Information" C L2tpSessionInformation [SXB N4],
        group_id: "Group Id" O GroupId [SXB N4],
        mbs_session_n4mb_control_information: "MBS Session N4mb Control Information" M MbsSessionN4mbControlInformation [N4MB],
        mbs_session_n4_control_information: "MBS Session N4 Control Information" C* MbsSessionN4ControlInformation [N4],
        dscp_to_ppi_control_information: "DSCP to PPI Control Information" O* DscpToPpiControlInformation [N4],
        tl_container: "TL-Container" C TlContainer [N4],
        trace_collection_entity_uri: "Trace Collection Entity URI" O Uri [SXA SXB SXC N4],
        ue_level_measurements_configuration: "UE Level Measurements Configuration" O UeLevelMeasurementsConfiguration [N4],
        alternative_smf_ip_address: "Alternative SMF IP Address" O AlternativeSmfIpAddress [N4],
        moq_control_information: "MoQ Control Information" C MoQControlInformation [N4],
    }
}

pfcp_table! {
    /// PFCP Session Establishment Response (Table 7.5.3.1-1).
    message SessionEstablishmentResponse = 51, "PFCP Session Establishment Response", "7.5.3.1-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        cause: "Cause" M Cause [SXA SXB SXC N4 N4MB],
        offending_ie: "Offending IE" C OffendingIe [SXA SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &OF_AN_IE),
        up_f_seid: "UP F-SEID" C FSeid [SXA SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &[CauseValue::RequestAccepted]),
        created_pdr: "Created PDR" C* CreatedPdr [SXA SXB N4 N4MB],
        load_control_information: "Load Control Information" O LoadControlInformation [SXA SXB SXC N4 N4MB],
        overload_control_information: "Overload Control Information" O OverloadControlInformation [SXA SXB SXC N4 N4MB],
        pgw_u_sgw_u_upf_fq_csid: "PGW-U/SGW-U /UPF FQ-CSID" C FqCsid [SXA SXB N4],
        failed_rule_id: "Failed Rule ID" C FailedRuleId [SXA SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &[CauseValue::RuleCreationModificationFailure]),
        created_traffic_endpoint: "Created Traffic Endpoint" C* CreatedTrafficEndpoint [SXA SXB N4 N4MB],
        created_bridge_router_info: "Created Bridge/Router Info" C CreatedBridgeRouterInfo [N4],
        atsss_control_parameters: "ATSSS Control Parameters" C AtsssControlParameters [N4],
        rds_configuration_information: "RDS configuration information" O RdsConfigurationInformation [SXB N4],
        partial_failure_information: "Partial Failure Information" C* PartialFailureInformation [SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &[CauseValue::RequestPartiallyAccepted]),
        created_l2tp_session: "Created L2TP Session" O CreatedL2tpSession [SXB N4],
        mbs_session_n4mb_information: "MBS Session N4mb Information" C MbsSessionN4mbInformation [N4MB],
        mbs_session_n4_information: "MBS Session N4 Information" C* MbsSessionN4Information [N4],
        tl_container: "TL-Container" C TlContainer [N4],
        moq_information: "MoQ Information" C MoQInformation [N4],
    }
}

pfcp_table! {
    /// PFCP Session Modification Request (Table 7.5.4.1-1).
    message SessionModificationRequest = 52, "PFCP Session Modification Request", "7.5.4.1-1" {
        cp_f_seid: "CP F-SEID" C FSeid [SXA SXB SXC N4 N4MB],
        remove_pdr: "Remove PDR" C* RemovePdr [SXA SXB SXC N4 N4MB],
        remove_far: "Remove FAR" C* RemoveFar [SXA SXB SXC N4 N4MB],
        remove_urr: "Remove URR" C* RemoveUrr [SXA SXB SXC N4 N4MB],
        remove_qer: "Remove QER" C* RemoveQer [SXB SXC N4 N4MB],
        remove_bar: "Remove BAR" C RemoveBar [SXA N4],
        remove_traffic_endpoint: "Remove Traffic Endpoint" C* RemoveTrafficEndpoint [SXA SXB SXC N4 N4MB],
        create_pdr: "Create PDR" C* CreatePdr [SXA SXB SXC N4 N4MB],
        create_far: "Create FAR" C* CreateFar [SXA SXB SXC N4 N4MB],
        create_urr: "Create URR" C* CreateUrr [SXA SXB SXC N4 N4MB],
        create_qer: "Create QER" C* CreateQer [SXB SXC N4 N4MB],
        create_bar: "Create BAR" C CreateBar [SXA N4],
        create_traffic_endpoint: "Create Traffic Endpoint" C* CreateTrafficEndpoint [SXA SXB SXC N4 N4MB],
        update_pdr: "Update PDR" C* UpdatePdr [SXA SXB SXC N4 N4MB],
        update_far: "Update FAR" C* UpdateFar [SXA SXB SXC N4 N4MB],
        update_urr: "Update URR" C* UpdateUrr [SXA SXB SXC N4 N4MB],
        update_qer: "Update QER" C* UpdateQer [SXB SXC N4 N4MB],
        update_bar: "Update BAR" C UpdateBar [SXA N4],
        update_traffic_endpoint: "Update Traffic Endpoint" C* UpdateTrafficEndpoint [SXA SXB SXC N4 N4MB],
        pfcpsmreq_flags: "PFCPSMReq-Flags" C PFCPSMReqFlags [SXA SXB SXC N4 N4MB],
        query_urr: "Query URR" C* QueryUrr [SXA SXB SXC N4 N4MB],
        fq_csid: "FQ-CSID" C*5 FqCsid [SXA SXB N4]
            roles ["PGW-C/SMF FQ-CSID" C [SXA SXB N4], "SGW-C FQ-CSID" C [SXA SXB], "MME FQ-CSID" C [SXA SXB], "ePDG FQ-CSID" C [SXB], "TWAN FQ-CSID" C [SXB]],
        user_plane_inactivity_timer: "User Plane Inactivity Timer" C UserPlaneInactivityTimer [SXB SXC N4 N4MB],
        query_urr_reference: "Query URR Reference" O QueryUrrReference [SXA SXB SXC N4 N4MB],
        trace_information: "Trace Information" O TraceInformation [SXA SXB SXC N4],
        remove_mar: "Remove MAR" C* RemoveMar [N4],
        update_mar: "Update MAR" C* UpdateMar [N4],
        create_mar: "Create MAR" C* CreateMar [N4],
        node_id: "Node ID" C NodeId [N4 N4MB],
        tsc_management_information: "TSC Management Information" C* TscManagementInformation [N4],
        remove_srr: "Remove SRR" C* RemoveSrr [N4],
        create_srr: "Create SRR" C* CreateSrr [N4],
        update_srr: "Update SRR" C* UpdateSrr [N4],
        provide_atsss_control_information: "Provide ATSSS Control Information" C ProvideAtsssControlInformation [N4],
        ethernet_context_information: "Ethernet Context Information" C EthernetContextInformation [N4],
        access_availability_information: "Access Availability Information" O*2 AccessAvailabilityInformation [N4],
        query_packet_rate_status: "Query Packet Rate Status" C* QueryPacketRateStatus [SXB N4],
        s_nssai: "S-NSSAI" O SNssai [N4 N4MB],
        hplmn_s_nssai: "HPLMN S-NSSAI" C HplmnSNssai [N4],
        dnn: "DNN" C ApnDnn [N4],
        group_id: "Group Id" C GroupId [SXB N4],
        mbs_session_n4_control_information: "MBS Session N4 Control Information" C* MbsSessionN4ControlInformation [N4],
        dscp_to_ppi_control_information: "DSCP to PPI Control Information" C DscpToPpiControlInformation [N4],
        tl_container: "TL-Container" C* TlContainer [N4],
        trace_collection_entity_uri: "Trace Collection Entity URI" O Uri [SXA SXB SXC N4],
        ue_level_measurements_configuration: "UE Level Measurements Configuration" O UeLevelMeasurementsConfiguration [N4],
        alternative_smf_ip_address: "Alternative SMF IP Address" O AlternativeSmfIpAddress [N4],
        moq_control_information: "MoQ Control Information" C MoQControlInformation [N4],
    }
}

pfcp_table! {
    /// PFCP Session Modification Response (Table 7.5.5.1-1).
    message SessionModificationResponse = 53, "PFCP Session Modification Response", "7.5.5.1-1" {
        cause: "Cause" M Cause [SXA SXB SXC N4 N4MB],
        offending_ie: "Offending IE" C OffendingIe [SXA SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &OF_AN_IE),
        created_pdr: "Created PDR" C* CreatedPdr [SXA SXB N4 N4MB],
        load_control_information: "Load Control Information" O LoadControlInformation [SXA SXB SXC N4 N4MB],
        overload_control_information: "Overload Control Information" O OverloadControlInformation [SXA SXB SXC N4 N4MB],
        usage_report: "Usage Report" C* UsageReportModification [SXA SXB SXC N4 N4MB],
        failed_rule_id: "Failed Rule ID" C FailedRuleId [SXA SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &[CauseValue::RuleCreationModificationFailure]),
        additional_usage_reports_information: "Additional Usage Reports Information" C AdditionalUsageReportsInformation [SXA SXB SXC N4 N4MB],
        created_updated_traffic_endpoint: "Created/Updated Traffic Endpoint" C* CreatedTrafficEndpoint [SXA SXB N4 N4MB],
        tsc_management_information: "TSC Management Information" C* TscManagementInformationResponse [N4],
        atsss_control_parameters: "ATSSS Control Parameters" C AtsssControlParameters [N4],
        updated_pdr: "Updated PDR" C* UpdatedPdr [SXB N4],
        packet_rate_status_report: "Packet Rate Status Report" C* PacketRateStatusReportModification [SXB N4],
        partial_failure_information: "Partial Failure Information" C* PartialFailureInformation [SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &[CauseValue::RequestPartiallyAccepted]),
        mbs_session_n4_information: "MBS Session N4 Information" C* MbsSessionN4Information [N4],
        tl_container: "TL-Container" C* TlContainer [N4],
        moq_information: "MoQ Information" C MoQInformation [N4],
    }
}

pfcp_table! {
    /// PFCP Session Deletion Request (Table 7.5.6-1).
    message SessionDeletionRequest = 54, "PFCP Session Deletion Request", "7.5.6-1" {
        tl_container: "TL-Container" C* TlContainer [N4],
        node_id: "Node ID" C NodeId [N4 N4MB],
        cp_f_seid: "CP F-SEID" C FSeid [N4 N4MB],
    }
}

pfcp_table! {
    /// PFCP Session Deletion Response (Table 7.5.7.1-1).
    message SessionDeletionResponse = 55, "PFCP Session Deletion Response", "7.5.7.1-1" {
        cause: "Cause" M Cause [SXA SXB SXC N4 N4MB],
        offending_ie: "Offending IE" C OffendingIe [SXA SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &OF_AN_IE),
        load_control_information: "Load Control Information" O LoadControlInformation [SXA SXB SXC N4 N4MB],
        overload_control_information: "Overload Control Information" O OverloadControlInformation [SXA SXB SXC N4 N4MB],
        usage_report: "Usage Report" C* UsageReportDeletion [SXA SXB SXC N4 N4MB],
        additional_usage_reports_information: "Additional Usage Reports Information" C AdditionalUsageReportsInformation [SXA SXB SXC N4 N4MB],
        packet_rate_status_report: "Packet Rate Status Report" C PacketRateStatusReport [SXB N4],
        mbs_session_n4_information: "MBS Session N4 Information" C* MbsSessionN4Information [N4],
        pfcpsdrsp_flags: "PFCPSDRsp-Flags" C PFCPSDRspFlags [SXA SXB SXC N4],
        tl_container: "TL-Container" C* TlContainer [N4],
        session_report: "Session Report" O* SessionReportDeletion [N4],
    }
}

pfcp_table! {
    /// PFCP Session Report Request (Table 7.5.8.1-1).
    message SessionReportRequest = 56, "PFCP Session Report Request", "7.5.8.1-1" {
        report_type: "Report Type" M ReportType [SXA SXB SXC N4 N4MB],
        downlink_data_report: "Downlink Data Report" C DownlinkDataReport [SXA N4 N4MB] if |s| s.report_type.as_ref().is_some_and(|t| t.dldr),
        usage_report: "Usage Report" C* UsageReport [SXA SXB SXC N4 N4MB] if |s| s.report_type.as_ref().is_some_and(|t| t.usar),
        error_indication_report: "Error Indication Report" C ErrorIndicationReport [SXA SXB N4 N4MB] if |s| s.report_type.as_ref().is_some_and(|t| t.erir),
        load_control_information: "Load Control Information" O LoadControlInformation [SXA SXB SXC N4 N4MB],
        overload_control_information: "Overload Control Information" O OverloadControlInformation [SXA SXB SXC N4 N4MB],
        additional_usage_reports_information: "Additional Usage Reports Information" C AdditionalUsageReportsInformation [SXA SXB SXC N4 N4MB],
        pfcpsrreq_flags: "PFCPSRReq-Flags" C PFCPSRReqFlags [SXA SXB SXC N4 N4MB],
        old_cp_f_seid: "Old CP F-SEID" C FSeid [N4 N4MB],
        smf_change_reason: "SMF Change Reason" O SmfChangeReason [N4 N4MB],
        packet_rate_status_report: "Packet Rate Status Report" C PacketRateStatusReport [SXB N4],
        tsc_management_information: "TSC Management Information" C* TscManagementInformationReport [N4] if |s| s.report_type.as_ref().is_some_and(|t| t.tmir),
        session_report: "Session Report" C* SessionReport [N4] if |s| s.report_type.as_ref().is_some_and(|t| t.sesr),
        cause: "Cause" O Cause [SXB N4],
    }
}

pfcp_table! {
    /// PFCP Session Report Response (Table 7.5.9.1-1).
    message SessionReportResponse = 57, "PFCP Session Report Response", "7.5.9.1-1" {
        cause: "Cause" M Cause [SXA SXB SXC N4 N4MB],
        offending_ie: "Offending IE" C OffendingIe [SXA SXB SXC N4 N4MB] if |s| cause_is(&s.cause, &OF_AN_IE),
        update_bar: "Update BAR" C UpdateBarReport [SXA N4],
        pfcpsrrsp_flags: "PFCPSRRsp-Flags" C PFCPSRRspFlags [SXA N4],
        cp_f_seid: "CP F-SEID" O FSeid [N4 N4MB],
        n4_u_f_teid: "N4-u F-TEID" O FTeid [N4],
        alternative_smf_ip_address: "Alternative SMF IP Address" O*2 AlternativeSmfIpAddress [N4 N4MB]
            roles ["Alternative SMF IP Address" O [N4 N4MB], "Alternative SMF IP Address" O [N4]],
        pgw_c_smf_fq_csid: "PGW-C/SMF FQ-CSID" O FqCsid [SXB N4],
        group_id: "Group Id" C GroupId [SXB N4],
        node_id: "Node ID" C NodeId [N4 N4MB],
    }
}

pfcp_table! {
    /// Application ID's PFDs (Table 7.4.3.1-2).
    group ApplicationIDsPFDs = 58, "Application ID's PFDs", "7.4.3.1-2" {
        application_id: "Application ID" M ApplicationId [SXB SXC N4],
        pfd_context: "PFD context" C* PfdContext [SXB SXC N4],
    }
}

pfcp_table! {
    /// PFD context (Table 7.4.3.1-3).
    group PfdContext = 59, "PFD context", "7.4.3.1-3" {
        pfd_contents: "PFD Contents" M* PfdContents [SXB SXC N4],
    }
}

pfcp_table! {
    /// PFD Partial Failure Information within PFCP PFD Management Response (Table 7.4.3.2-2).
    group PfdPartialFailureInformation = 397, "PFD Partial Failure Information", "7.4.3.2-2" {
        application_id: "Application ID" M ApplicationId [SXB SXC N4],
        failure_cause: "Failure Cause" M Cause [SXB SXC N4],
    }
}

pfcp_table! {
    /// PFCP Session Retention Information IE within PFCP Association Setup Request (Table 7.4.4.1-2).
    group PfcpSessionRetentionInformation = 183, "PFCP Session Retention Information", "7.4.4.1-2" {
        cp_pfcp_entity_ip_address: "CP PFCP Entity IP Address" O* CpPfcpEntityIpAddress [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// UE IP address Pool Information IE within PFCP Association Setup Request (Table 7.4.4.1-3).
    group UeIpAddressPoolInformation = 233, "UE IP address Pool Information", "7.4.4.1-3" {
        ue_ip_address_pool_identity: "UE IP address Pool Identity" M* UeIpAddressPoolIdentity [SXB N4],
        network_instance: "Network Instance" O NetworkInstance [SXB N4],
        s_nssai: "S-NSSAI" O* SNssai [N4],
        ip_version: "IP version" O IpVersion [N4],
    }
}

pfcp_table! {
    /// Clock Drift Control Information within PFCP Association Setup Request (Table 7.4.4.1.2-1).
    group ClockDriftControlInformation = 203, "Clock Drift Control Information", "7.4.4.1.2-1" {
        requested_clock_drift_information: "Requested Clock Drift Information" M RequestedClockDriftInformation [N4],
        time_domain_number: "Time Domain Number" C* TimeDomainNumber [N4],
        configured_time_domain: "Configured Time Domain" C ConfiguredTimeDomain [N4],
        time_offset_threshold: "Time Offset Threshold" C TimeOffsetThreshold [N4],
        cumulative_rateratio_threshold: "Cumulative rateRatio Threshold" C CumulativeRateRatioThreshold [N4],
    }
}

pfcp_table! {
    /// GTP-U Path QoS Control Information within PFCP Association Setup Request (Table 7.4.4.1.3-1).
    group GtpUPathQoSControlInformation = 238, "GTP-U Path QoS Control Information", "7.4.4.1.3-1" {
        remote_gtp_u_peer: "Remote GTP-U Peer" C* RemoteGtpUPeer [N4],
        gtp_u_path_interface_type: "GTP-U Path Interface Type" C GtpUPathInterfaceType [N4],
        qos_report_trigger: "QoS Report Trigger" M QoSReportTrigger [N4],
        dscp: "DSCP" C* TransportLevelMarking [N4],
        measurement_period: "Measurement Period" C MeasurementPeriod [N4],
        average_packet_delay_threshold: "Average Packet Delay Threshold" C AveragePacketDelay [N4],
        minimum_packet_delay_threshold: "Minimum Packet Delay Threshold" C MinimumPacketDelay [N4],
        maximum_packet_delay_threshold: "Maximum Packet Delay Threshold" C MaximumPacketDelay [N4],
        minimum_waiting_time: "Minimum Waiting Time" C Timer [N4],
    }
}

pfcp_table! {
    /// N6 Delay Measurement Control Information within PFCP Association Setup Request (Table 7.4.4.1.4-1).
    group N6DelayMeasurementControlInformation = 355, "N6 Delay Measurement Control Information", "7.4.4.1.4-1" {
        n6_delay_measurement_control_information_id: "N6 Delay Measurement Control Information ID" M N6DelayMeasurementControlInformationId [N4],
        measurement_endpoint_address: "Measurement Endpoint Address" M* MeasurementEndpointAddress [N4],
        network_instance: "Network Instance" M NetworkInstance [N4],
        measurement_protocols: "Measurement Protocols" M* N6DelayMeasurementProtocols [N4],
        protocol_specific_configuration_parameters: "Protocol Specific Configuration Parameters" O ProtocolSpecificConfigurationParameters [N4],
        measurement_reporting_type: "Measurement Reporting Type" M MeasurementReportingType [N4],
        measurement_period: "Measurement Period" C MeasurementPeriod [N4],
        average_packet_delay_threshold: "Average Packet Delay Threshold" O AveragePacketDelay [N4],
        minimum_packet_delay_threshold: "Minimum Packet Delay Threshold" O MinimumPacketDelay [N4],
        maximum_packet_delay_threshold: "Maximum Packet Delay Threshold" O MaximumPacketDelay [N4],
        minimum_waiting_time: "Minimum Waiting Time" O Timer [N4],
    }
}

pfcp_table! {
    /// Protocol Specific Configuration Parameters (Table 7.4.4.1.4-2).
    group ProtocolSpecificConfigurationParameters = 378, "Protocol Specific Configuration Parameters", "7.4.4.1.4-2" {
        measurement_protocol: "Measurement Protocol" M N6DelayMeasurementProtocols [N4],
        measurement_endpoint_port_number: "Measurement EndPoint Port Number" O MeasurementEndpointPortNumber [N4],
        security_mode_stamp: "Security Mode (STAMP)" O SecurityMode [N4],
        hmac_key_stamp: "HMAC Key / (STAMP)" O HmacKeyStamp [N4],
        session_reflector_mode_stamp: "Session Reflector Mode (STAMP)" O SessionReflectorMode [N4],
        security_mode_owamp_or_twamp: "Security Mode / (OWAMP or TWAMP)" O SecurityModeValue [N4],
        key_id_and_shared_secret_owamp_or_twamp: "Key ID and Shared Secret / (OWAMP or TWAMP)" O* KeyIdAndSharedSecret [N4],
    }
}

pfcp_table! {
    /// UE IP Address Usage Information IE within PFCP Association Update Request (Table 7.4.4.3.1-1).
    group UeIpAddressUsageInformation = 267, "UE IP Address Usage Information", "7.4.4.3.1-1" {
        ue_ip_address_usage_sequence_number: "UE IP Address Usage Sequence Number" M SequenceNumber [SXB N4],
        ue_ip_address_usage_metric: "UE IP Address Usage Metric" M Metric [SXB N4],
        validity_timer: "Validity Timer" M ValidityTimer [SXB N4],
        number_of_ue_ip_addresses: "Number of UE IP Addresses" M NumberOfUeIpAddresses [SXB N4],
        network_instance: "Network Instance" M NetworkInstance [SXB N4],
        ue_ip_address_pool_id: "UE IP Address Pool Id" O UeIpAddressPoolIdentity [SXB N4],
        s_nssai: "S-NSSAI" O SNssai [SXB N4],
    }
}

pfcp_table! {
    /// User Plane Path Failure Report IE within PFCP Node Report Request (Table 7.4.5.1.2-1).
    group UserPlanePathFailureReport = 102, "User Plane Path Failure Report", "7.4.5.1.2-1" {
        remote_gtp_u_peer: "Remote GTP-U Peer" M* RemoteGtpUPeer [SXA SXB N4 N4MB],
    }
}

pfcp_table! {
    /// User Plane Path Recovery Report IE within PFCP Node Report Request (Table 7.4.5.1.3-1).
    group UserPlanePathRecoveryReport = 187, "User Plane Path Recovery Report", "7.4.5.1.3-1" {
        remote_gtp_u_peer: "Remote GTP-U Peer" M* RemoteGtpUPeer [SXA SXB N4 N4MB],
    }
}

pfcp_table! {
    /// Clock Drift Report IE within PFCP Node Report Request (Table 7.4.5.1.4-1).
    group ClockDriftReport = 205, "Clock Drift Report", "7.4.5.1.4-1" {
        time_domain_number: "Time Domain Number" M TimeDomainNumber [N4],
        time_offset_measurement: "Time Offset Measurement" O TimeOffsetMeasurement [N4],
        cumulative_rateratio_measurement: "Cumulative rateRatio Measurement" O CumulativeRateRatioMeasurement [N4],
        time_stamp: "Time Stamp" O TimeStamp [N4],
        network_instance: "Network Instance" C NetworkInstance [N4],
        apn_dnn: "APN/DNN" C ApnDnn [N4],
        s_nssai: "S-NSSAI" C SNssai [N4],
    }
}

pfcp_table! {
    /// GTP-U Path QoS Report IE within PFCP Node Report Request (Table 7.4.5.1.5-1).
    group GtpuPathQosReport = 239, "GTP-U Path QoS Report", "7.4.5.1.5-1" {
        remote_gtp_u_peer: "Remote GTP-U Peer" M RemoteGtpUPeer [N4],
        gtp_u_path_interface_type: "GTP-U Path Interface Type" C GtpUPathInterfaceType [N4],
        qos_report_trigger: "QoS Report Trigger" M QoSReportTrigger [N4],
        time_stamp: "Time Stamp" M TimeStamp [N4],
        start_time: "Start Time" C StartTime [N4],
        qos_information: "QoS Information" M* QoSInformation [N4],
    }
}

pfcp_table! {
    /// QoS Information in GTP-U Path QoS Report IE (Table 7.4.5.1.6-1).
    group QoSInformation = 240, "QoS Information", "7.4.5.1.6-1" {
        average_packet_delay: "Average Packet Delay" M AveragePacketDelay [N4],
        minimum_packet_delay: "Minimum Packet Delay" C MinimumPacketDelay [N4],
        maximum_packet_delay: "Maximum Packet Delay" C MaximumPacketDelay [N4],
        dscp: "DSCP" C TransportLevelMarking [N4],
    }
}

pfcp_table! {
    /// Peer UP Restart Report IE within PFCP Node Report Request (Table 7.4.5.1.7-1).
    group PeerUpRestartReport = 315, "Peer UP Restart Report", "7.4.5.1.7-1" {
        remote_gtp_u_peer: "Remote GTP-U Peer" M* RemoteGtpUPeer [SXA SXB N4 N4MB],
    }
}

pfcp_table! {
    /// N6 Delay Measurement Report IE within PFCP Node Report Request (Table 7.4.5.1.8-1).
    group N6DelayMeasurementReport = 356, "N6 Delay Measurement Report", "7.4.5.1.8-1" {
        measurement_endpoint_address: "Measurement EndPoint Address" M MeasurementEndpointAddress [N4],
        network_instance: "Network Instance" M NetworkInstance [N4],
        measurement_reporting_type: "Measurement Reporting Type" M MeasurementReportingType [N4],
        time_stamp: "Time Stamp" M TimeStamp [N4],
        start_time: "Start Time" C StartTime [N4],
        n6_delay_measurement_information: "N6 Delay Measurement Information" C N6DelayMeasurementInformation [N4],
        n6_delay_measurement_failure_information: "N6 Delay Measurement Failure Information" C N6DelayMeasurementFailureInformation [N4],
        measurement_endpoint_port_number: "Measurement EndPoint Port Number" O MeasurementEndpointPortNumber [N4],
    }
}

pfcp_table! {
    /// PFCP Session Change Info IE within PFCP Session Set Modification Request (Table 7.4.7.1-2).
    group PfcpSessionChangeInfo = 290, "PFCP Session Change Info", "7.4.7.1-2" {
        pgw_c_smf_fq_csid: "PGW-C/SMF FQ-CSID" C* FqCsid [SXB N4],
        group_id: "Group Id" C* GroupId [SXB N4],
        cp_ip_address: "CP IP Address" C* CpIpAddress [SXB N4],
        alternative_smf_pgw_c_ip_address: "Alternative SMF/PGW-C IP Address" M AlternativeSmfIpAddress [SXB N4],
    }
}

pfcp_table! {
    /// L2TP Tunnel Information IE in the PFCP Session Establishment Request message (Table 7.5.2.1-2).
    group L2tpTunnelInformation = 276, "L2TP Tunnel Information", "7.5.2.1-2" {
        lns_address: "LNS Address" M LnsAddress [SXB N4],
        tunnel_password: "Tunnel Password" O TunnelPassword [SXB N4],
        tunnel_preference: "Tunnel Preference" C TunnelPreference [SXB N4],
    }
}

pfcp_table! {
    /// L2TP Session Information IE in the PFCP Session Establishment Request message (Table 7.5.2.1-3).
    group L2tpSessionInformation = 277, "L2TP Session Information", "7.5.2.1-3" {
        calling_number: "Calling Number" O CallingNumber [SXB N4],
        called_number: "Called Number" O CalledNumber [SXB N4],
        maximum_receive_unit: "Maximum Receive Unit" O MaximumReceiveUnit [SXB N4],
        l2tp_session_indications: "L2TP Session Indications" C L2tpSessionIndications [SXB N4],
        l2tp_user_authentication: "L2TP User Authentication" O L2tpUserAuthentication [SXB N4],
    }
}

pfcp_table! {
    /// MBS Session N4mb Control Information IE within PFCP Session Establishment Request (Table 7.5.2.1-4).
    group MbsSessionN4mbControlInformation = 300, "MBS Session N4mb Control Information", "7.5.2.1-4" {
        mbs_session_identifier: "MBS Session Identifier" M MbsSessionIdentifier [N4MB],
        area_session_id: "Area Session ID" C AreaSessionId [N4MB],
        mbsn4mbreq_flags: "MBSN4mbReq-Flags" C MBSN4mbReqFlags [N4MB],
        multicast_transport_information_for_n3mb_and_or_n19mb: "Multicast Transport Information for N3mb and/or N19mb" C MulticastTransportInformation [N4MB],
    }
}

pfcp_table! {
    /// MBS Session N4 Control Information IE within PFCP Session Establishment Request (Table 7.5.2.1-5).
    group MbsSessionN4ControlInformation = 310, "MBS Session N4 Control Information", "7.5.2.1-5" {
        mbs_session_identifier: "MBS Session Identifier" M MbsSessionIdentifier [N4],
        area_session_id: "Area Session ID" C AreaSessionId [N4],
        multicast_transport_information: "Multicast Transport Information" C MulticastTransportInformation [N4],
    }
}

pfcp_table! {
    /// DSCP to PPI Control Information IE within PFCP Session Establishment Request (Table 7.5.2.1-6).
    group DscpToPpiControlInformation = 316, "DSCP to PPI Control Information", "7.5.2.1-6" {
        dscp_to_ppi_mapping_information: "DSCP to PPI Mapping Information" M* DscpToPpiMappingInformation [N4],
        qfi: "QFI" O* Qfi [N4],
    }
}

pfcp_table! {
    /// Create PDR IE within PFCP Session Establishment Request (Table 7.5.2.2-1).
    group CreatePdr = 1, "Create PDR", "7.5.2.2-1" by [SXA SXB SXC N4 N4MB] {
        pdr_id: "PDR ID" M PdrId [SXA SXB SXC N4 N4MB],
        precedence: "Precedence" M Precedence [SXB SXC N4 N4MB],
        pdi: "PDI" M Pdi [SXA SXB SXC N4 N4MB],
        outer_header_removal: "Outer Header Removal" C OuterHeaderRemoval [SXA SXB N4 N4MB],
        far_id: "FAR ID" C FarId [SXA SXB SXC N4 N4MB],
        urr_id: "URR ID" C* UrrId [SXA SXB SXC N4],
        qer_id: "QER ID" C* QerId [SXB SXC N4 N4MB],
        activate_predefined_rules: "Activate Predefined Rules" C* ActivatePredefinedRules [SXB SXC N4],
        activation_time: "Activation Time" O ActivationTime [SXB SXC N4],
        deactivation_time: "Deactivation Time" O DeactivationTime [SXB SXC N4],
        mar_id: "MAR ID" C MarId [N4],
        packet_replication_and_detection_carry_on_information: "Packet Replication and Detection Carry-On Information" C PacketReplicationAndDetectionCarryOnInformation [N4],
        ip_multicast_addressing_info: "IP Multicast Addressing Info" O* IpMulticastAddressingInfo [N4],
        ue_ip_address_pool_identity: "UE IP address Pool Identity" O*2 UeIpAddressPoolIdentity [SXB N4],
        multipath_applicable_indication: "Multipath Applicable Indication" C MultipathApplicableIndication [N4],
        transport_delay_reporting: "Transport Delay Reporting" C TransportDelayReporting [N4],
        rat_type: "RAT Type" O RatType [N4],
    }
}

pfcp_table! {
    /// PDI IE within PFCP Session Establishment Request (Table 7.5.2.2-2).
    group Pdi = 2, "PDI", "7.5.2.2-2" {
        source_interface: "Source Interface" M SourceInterface [SXA SXB SXC N4 N4MB],
        local_f_teid: "Local F-TEID" O FTeid [SXA SXB N4],
        local_ingress_tunnel: "Local Ingress Tunnel" C LocalIngressTunnel [N4MB],
        network_instance: "Network Instance" O NetworkInstance [SXA SXB SXC N4 N4MB],
        redundant_transmission_detection_parameters: "Redundant Transmission Detection Parameters" O RedundantTransmissionParameters [N4],
        ue_ip_address: "UE IP address" O* UeIpAddress [SXB SXC N4],
        mapped_n6_ip_address: "Mapped N6 IP Address" O MappedN6IpAddress [N4],
        n6_routing_information: "N6 Routing Information" O N6RoutingInformation [N4],
        traffic_endpoint_id: "Traffic Endpoint ID" C* TrafficEndpointId [SXA SXB SXC N4 N4MB],
        sdf_filter: "SDF Filter" O* SdfFilter [SXB SXC N4 N4MB],
        application_id: "Application ID" O ApplicationId [SXB SXC N4 N4MB],
        ethernet_pdu_session_information: "Ethernet PDU Session Information" O EthernetPduSessionInformation [N4],
        ethernet_packet_filter: "Ethernet Packet Filter" O* EthernetPacketFilter [N4],
        qfi: "QFI" O* Qfi [N4],
        framed_route: "Framed-Route" O* FramedRoute [SXB N4],
        framed_routing: "Framed-Routing" O FramedRouting [SXB N4],
        framed_ipv6_route: "Framed-IPv6-Route" O* FramedIPv6Route [SXB N4],
        source_interface_type: "Source Interface Type" C InterfaceType3gpp [SXA SXB N4 N4MB],
        ip_multicast_addressing_info: "IP Multicast Addressing Info" O* IpMulticastAddressingInfo [N4 N4MB],
        dns_query_response_filter: "DNS Query/Response Filter" O* DnsQueryResponseFilter [N4]
            roles ["DNS Query Filter" O [N4], "DNS Response Filter" O [N4]],
        mbs_session_identifier: "MBS Session Identifier" C MbsSessionIdentifier [N4],
        area_session_id: "Area Session ID" C AreaSessionId [N4],
        protocol_description: "Protocol Description" O ProtocolDescription [N4],
        expedited_transfer_indication: "Expedited Transfer Indication" O ExpeditedTransferIndication [N4],
    }
}

pfcp_table! {
    /// Ethernet Packet Filter IE within PFCP Session Establishment Request (Table 7.5.2.2-3).
    group EthernetPacketFilter = 132, "Ethernet Packet Filter", "7.5.2.2-3" {
        ethernet_filter_id: "Ethernet Filter ID" C EthernetFilterId [N4],
        ethernet_filter_properties: "Ethernet Filter Properties" C EthernetFilterProperties [N4],
        mac_address: "MAC address" O*16 MacAddress [N4],
        ethertype: "Ethertype" O Ethertype [N4],
        c_tag: "C-TAG" O CTag [N4],
        s_tag: "S-TAG" O STag [N4],
        sdf_filter: "SDF Filter" O* SdfFilter [N4],
    }
}

pfcp_table! {
    /// IP Multicast Addressing Info IE within PFCP Session Establishment Request (Table 7.5.2.2-4).
    group IpMulticastAddressingInfo = 188, "IP Multicast Addressing Info", "7.5.2.2-4" {
        ip_multicast_address: "IP Multicast Address" M IpMulticastAddress [N4 N4MB],
        source_ip_address: "Source IP Address" C* SourceIpAddress [N4 N4MB]
            roles ["Source IP Address" O [N4], "Source IP Address" M [N4MB]],
    }
}

pfcp_table! {
    /// Redundant Transmission Detection Parameters IE in PDI (Table 7.5.2.2-5).
    group RedundantTransmissionParameters = 255, "Redundant Transmission Parameters", "7.5.2.2-5" {
        local_f_teid_for_redundant_transmission: "Local F-TEID for Redundant Transmission" M FTeid [N4],
        network_instance_for_redundant_transmission: "Network Instance for Redundant Transmission" C NetworkInstance [N4],
    }
}

pfcp_table! {
    /// Transport Delay Reporting IE in Create PDR IE (Table 7.5.2.2-6).
    group TransportDelayReporting = 271, "Transport Delay Reporting", "7.5.2.2-6" {
        preceding_ul_gtp_u_peer: "Preceding UL GTP-U Peer" M RemoteGtpUPeer [N4],
        dscp: "DSCP" O TransportLevelMarking [N4],
    }
}

pfcp_table! {
    /// Protocol Description IE (Table 7.5.2.2-7).
    group ProtocolDescription = 334, "Protocol Description", "7.5.2.2-7" {
        transport_protocol: "Transport Protocol" O MediaTransportProtocol [N4],
        rtp_header_extension_information: "RTP Header Extension Information" C* RtpHeaderExtensionInformation [N4],
        rtp_payload_information: "RTP Payload Information" O* RtpPayloadInformation [N4],
        media_related_information_transfer_info: "Media Related Information Transfer Info" O MediaRelatedInformationTransferInfo [N4],
    }
}

pfcp_table! {
    /// RTP Header Extension Information IE (Table 7.5.2.2-8).
    group RtpHeaderExtensionInformation = 340, "RTP Header Extension Information", "7.5.2.2-8" {
        rtp_header_extension_type: "RTP Header Extension Type" C RtpHeaderExtensionType [N4],
        rtp_header_extension_id: "RTP Header Extension ID" C RtpHeaderExtensionId [N4],
        rtp_header_extension_additional_information: "RTP Header Extension Additional Information" O RtpHeaderExtensionAdditionalInformation [N4],
    }
}

pfcp_table! {
    /// RTP Payload Information IE (Table 7.5.2.2-9).
    group RtpPayloadInformation = 341, "RTP Payload Information", "7.5.2.2-9" {
        rtp_payload_type: "RTP Payload Type" C* RtpPayloadType [N4],
        rtp_payload_format: "RTP Payload Format" O RtpPayloadFormat [N4],
    }
}

pfcp_table! {
    /// Create FAR IE within PFCP Session Establishment Request (Table 7.5.2.3-1).
    group CreateFar = 3, "Create FAR", "7.5.2.3-1" {
        far_id: "FAR ID" M FarId [SXA SXB SXC N4 N4MB],
        apply_action: "Apply Action" M ApplyAction [SXA SXB SXC N4 N4MB],
        forwarding_parameters: "Forwarding Parameters" Ci ForwardingParameters [SXA SXB SXC N4] if |s| s.apply_action.as_ref().is_some_and(|a| a.forw),
        duplicating_parameters: "Duplicating Parameters" C* DuplicatingParameters [SXA SXB] if |s| s.apply_action.as_ref().is_some_and(|a| a.dupl),
        bar_id: "BAR ID" O BarId [SXA N4],
        // V19.6.0 marks no interface for this row; its row in Update FAR (Table
        // 7.5.4.3-1) and clause 5.24 have it on N4.
        redundant_transmission_forwarding_parameters: "Redundant Transmission Forwarding Parameters" C RedundantTransmissionForwardingParameters [N4],
        mbs_multicast_parameters: "MBS Multicast Parameters" C MbsMulticastParameters [N4MB] if |s| s.apply_action.as_ref().is_some_and(|a| a.fssm),
        add_mbs_unicast_parameters: "Add MBS Unicast Parameters" C* AddMbsUnicastParameters [N4MB] if |s| s.apply_action.as_ref().is_some_and(|a| a.mbsu),
    }
}

pfcp_table! {
    /// Forwarding Parameters IE in FAR (Table 7.5.2.3-2).
    group ForwardingParameters = 4, "Forwarding Parameters", "7.5.2.3-2" {
        destination_interface: "Destination Interface" M DestinationInterface [SXA SXB SXC N4],
        network_instance: "Network Instance" O NetworkInstance [SXA SXB SXC N4],
        redirect_information: "Redirect Information" C RedirectInformation [SXB SXC N4],
        outer_header_creation: "Outer Header Creation" C OuterHeaderCreation [SXA SXB N4],
        transport_level_marking: "Transport Level Marking" C TransportLevelMarking [SXA SXB N4],
        extended_transport_level_marking: "Extended Transport Level Marking" C* ExtendedTransportLevelMarking [N4],
        transport_level_marking_indications: "Transport Level Marking Indications" C TransportLevelMarkingIndications [N4],
        forwarding_policy: "Forwarding Policy" C ForwardingPolicy [SXB SXC N4],
        metadata: "Metadata" O Metadata [N4],
        header_enrichment: "Header Enrichment" O HeaderEnrichment [SXB SXC N4],
        linked_traffic_endpoint_id: "Linked Traffic Endpoint ID" C TrafficEndpointId [SXA SXB N4],
        proxying: "Proxying" C Proxying [N4],
        destination_interface_type: "Destination Interface Type" C InterfaceType3gpp [SXA SXB N4],
        data_network_access_identifier: "Data Network Access Identifier" C DataNetworkAccessIdentifier [],
        ip_address_and_port_number_replacement: "IP Address and Port Number Replacement" C IpAddressAndPortNumberReplacement [N4],
        n6_routing_information: "N6 Routing Information" O N6RoutingInformation [N4],
        header_handling_control_rule: "Header Handling Control Rule" C* HeaderHandlingControlRule [N4],
        on_path_n6_connection_information: "On-path N6 Connection Information" O OnPathN6ConnectionInformation [N4],
    }
}

pfcp_table! {
    /// Duplicating Parameters IE in FAR (Table 7.5.2.3-3).
    group DuplicatingParameters = 5, "Duplicating Parameters", "7.5.2.3-3" {
        destination_interface: "Destination Interface" M DestinationInterface [SXA SXB],
        outer_header_creation: "Outer Header Creation" C OuterHeaderCreation [SXA SXB],
        transport_level_marking: "Transport Level marking" C TransportLevelMarking [SXA SXB],
        forwarding_policy: "Forwarding Policy" C ForwardingPolicy [SXA SXB],
    }
}

pfcp_table! {
    /// Redundant Transmission Forwarding Parameters IE in FAR (Table 7.5.2.3-4).
    group RedundantTransmissionForwardingParameters = 270, "Redundant Transmission Forwarding Parameters", "7.5.2.3-4" {
        outer_header_creation: "Outer Header Creation" M OuterHeaderCreation [N4],
        network_instance_for_redundant_transmission: "Network Instance for Redundant Transmission" C NetworkInstance [N4],
    }
}

pfcp_table! {
    /// MBS Multicast Parameters IE in the Create FAR IE (Table 7.5.2.3-5).
    group MbsMulticastParameters = 301, "MBS Multicast Parameters", "7.5.2.3-5" {
        destination_interface: "Destination Interface" M DestinationInterface [N4MB],
        network_instance: "Network Instance" O NetworkInstance [N4MB],
        outer_header_creation: "Outer Header Creation" M OuterHeaderCreation [N4MB],
        transport_level_marking: "Transport Level marking" C TransportLevelMarking [N4MB],
        destination_interface_type: "Destination Interface Type" O* InterfaceType3gpp [N4MB],
    }
}

pfcp_table! {
    /// Add MBS Unicast Parameters IE in the Create FAR IE (Table 7.5.2.3-6).
    group AddMbsUnicastParameters = 302, "Add MBS Unicast Parameters", "7.5.2.3-6" {
        destination_interface: "Destination Interface" M DestinationInterface [N4MB],
        mbs_unicast_parameters_id: "MBS Unicast Parameters ID" M MbsUnicastParametersId [N4MB],
        network_instance: "Network Instance" O NetworkInstance [N4MB],
        outer_header_creation: "Outer Header Creation" M OuterHeaderCreation [N4MB],
        transport_level_marking: "Transport Level marking" C TransportLevelMarking [N4MB],
        destination_interface_type: "Destination Interface Type" O InterfaceType3gpp [N4MB],
    }
}

pfcp_table! {
    /// Header Handling Control Rule IE in Forwarding Parameters (Table 7.5.2.3-7).
    group HeaderHandlingControlRule = 361, "Header Handling Control Rule", "7.5.2.3-7" {
        header_handling_control_rule_id: "Header Handling Control Rule ID" M HeaderHandlingControlRuleId [N4],
        header_detection_reference: "Header Detection Reference" M HeaderDetectionReference [N4],
        header_detection_support_information: "Header Detection Support Information" O HeaderDetectionSupportInformation [N4],
        header_handling_reporting_control_info: "Header Handling Reporting Control Info" O* HeaderHandlingReportingControlInfo [N4],
        header_handling_control_information: "Header Handling Control information" M* HeaderHandlingControlInformation [N4],
    }
}

pfcp_table! {
    /// Header Handling Reporting Control Info IE in Header Handling Control Rule (Table 7.5.2.3-8).
    group HeaderHandlingReportingControlInfo = 362, "Header Handling Reporting Control Info", "7.5.2.3-8" {
        reporting_endpoint_id: "Reporting Endpoint ID" M ReportingEndpointId [N4],
        minimum_wait_time: "Minimum Wait Time" C MinimumWaitTime [N4],
        reporting_suggestion_info: "Reporting Suggestion Info" O ReportingSuggestionInfo [N4],
        event_notification_uri: "Event Notification URI" M EventNotificationUri [N4],
        notification_binding_indication: "Notification Binding Indication" C BindingIndication [N4],
        notification_correlation_id: "Notification Correlation ID" M NotificationCorrelationId [N4],
        header_handling_reporting_indication: "Header Handling Reporting Indication" C HeaderHandlingReportingIndication [N4],
    }
}

pfcp_table! {
    /// Header Handling Control information IE in Header Handling Control Rule (Table 7.5.2.3-9).
    group HeaderHandlingControlInformation = 363, "Header Handling Control information", "7.5.2.3-9" {
        header_handling_control_id: "Header Handling Control ID" M HeaderHandlingControlId [N4],
        header_handling_control_reference: "Header Handling Control Reference" C HeaderHandlingControlReference [N4],
        header_handling_action: "Header Handling Action" C HeaderHandlingAction [N4],
        header_information: "Header Information" C HeaderInformation [N4],
        header_value: "Header Value" C HeaderValue [N4],
        header_handling_condition: "Header Handling Condition" C HeaderHandlingCondition [N4],
        header_handling_reporting: "Header Handling Reporting" C* ReportingEndpointId [N4],
    }
}

pfcp_table! {
    /// Extended Transport Level Marking IE in Forwarding Parameters IE (Table 7.5.2.3-10).
    group ExtendedTransportLevelMarking = 383, "Extended Transport Level Marking", "7.5.2.3-10" {
        transport_level_marking: "Transport Level Marking" M TransportLevelMarking [N4],
        associated_pdu_set_importance_values: "Associated PDU Set Importance values" M PduSetImportance [N4],
    }
}

pfcp_table! {
    /// Create URR IE within PFCP Session Establishment Request (Table 7.5.2.4-1).
    group CreateUrr = 6, "Create URR", "7.5.2.4-1" {
        urr_id: "URR ID" M UrrId [SXA SXB SXC N4 N4MB],
        measurement_method: "Measurement Method" M MeasurementMethod [SXA SXB SXC N4 N4MB],
        reporting_triggers: "Reporting Triggers" M ReportingTriggers [SXA SXB SXC N4 N4MB],
        measurement_period: "Measurement Period" C MeasurementPeriod [SXA SXB SXC N4 N4MB] if |s| triggers(s, |t| t.perio),
        volume_threshold: "Volume Threshold" C VolumeThreshold [SXA SXB SXC N4 N4MB] if |s| method(s, |m| m.volum) && triggers(s, |t| t.volth),
        volume_quota: "Volume Quota" C VolumeQuota [SXB SXC N4] if |s| method(s, |m| m.volum) && triggers(s, |t| t.volqu),
        event_threshold: "Event Threshold" C EventThreshold [SXB SXC N4] if |s| method(s, |m| m.event) && triggers(s, |t| t.eveth),
        event_quota: "Event Quota" C EventQuota [SXB SXC N4] if |s| method(s, |m| m.event) && triggers(s, |t| t.evequ),
        time_threshold: "Time Threshold" C TimeThreshold [SXA SXB SXC N4] if |s| method(s, |m| m.durat) && triggers(s, |t| t.timth),
        time_quota: "Time Quota" C TimeQuota [SXB SXC N4] if |s| method(s, |m| m.durat) && triggers(s, |t| t.timqu),
        quota_holding_time: "Quota Holding Time" C QuotaHoldingTime [SXB SXC N4] if |s| triggers(s, |t| t.quhti),
        dropped_dl_traffic_threshold: "Dropped DL Traffic Threshold" C DroppedDlTrafficThreshold [SXA N4] if |s| triggers(s, |t| t.droth),
        quota_validity_time: "Quota Validity Time" C QuotaValidityTime [SXB N4] if |s| triggers(s, |t| t.quvti),
        monitoring_time: "Monitoring Time" O MonitoringTime [SXA SXB SXC N4],
        subsequent_volume_threshold: "Subsequent Volume Threshold" O SubsequentVolumeThreshold [SXA SXB SXC N4],
        subsequent_time_threshold: "Subsequent Time Threshold" O SubsequentTimeThreshold [SXA SXB SXC N4],
        subsequent_volume_quota: "Subsequent Volume Quota" O SubsequentVolumeQuota [SXB SXC N4],
        subsequent_time_quota: "Subsequent Time Quota" O SubsequentTimeQuota [SXB SXC N4],
        subsequent_event_threshold: "Subsequent Event Threshold" O SubsequentEventThreshold [SXB SXC N4],
        subsequent_event_quota: "Subsequent Event Quota" O SubsequentEventQuota [SXB SXC N4],
        inactivity_detection_time: "Inactivity Detection Time" C InactivityDetectionTime [SXB SXC N4],
        linked_urr_id: "Linked URR ID" C* LinkedUrrId [SXB SXC N4 N4MB] if |s| triggers(s, |t| t.liusa),
        measurement_information: "Measurement Information" C MeasurementInformation [SXA SXB SXC N4],
        time_quota_mechanism: "Time Quota Mechanism" C TimeQuotaMechanism [SXB],
        aggregated_urrs: "Aggregated URRs" C* AggregatedURRs [SXB],
        far_id_for_quota_action: "FAR ID for Quota Action" C FarId [SXB SXC N4],
        ethernet_inactivity_timer: "Ethernet Inactivity Timer" C EthernetInactivityTimer [N4],
        additional_monitoring_time: "Additional Monitoring Time" O* AdditionalMonitoringTime [SXA SXB SXC N4],
        number_of_reports: "Number of Reports" O NumberOfReports [SXA SXB SXC N4],
        exempted_application_id_for_quota_action: "Exempted Application ID for Quota Action" O* ApplicationId [SXB SXC N4],
        exempted_sdf_filter_for_quota_action: "Exempted SDF Filter for Quota Action" O* SdfFilter [SXB SXC N4],
        user_plane_inactivity_timer: "User Plane Inactivity Timer" C UserPlaneInactivityTimer [N4],
    }
}

pfcp_table! {
    /// Aggregated URRs (Table 7.5.2.4-2).
    group AggregatedURRs = 118, "Aggregated URRs", "7.5.2.4-2" {
        aggregated_urr_id: "Aggregated URR ID" M AggregatedUrrId [SXB],
        multiplier: "Multiplier" M Multiplier [SXB],
    }
}

pfcp_table! {
    /// Additional Monitoring Time (Table 7.5.2.4-3).
    group AdditionalMonitoringTime = 147, "Additional Monitoring Time", "7.5.2.4-3" {
        monitoring_time: "Monitoring Time" M MonitoringTime [SXA SXB SXC N4],
        subsequent_volume_threshold: "Subsequent Volume Threshold" O SubsequentVolumeThreshold [SXA SXB SXC N4],
        subsequent_time_threshold: "Subsequent Time Threshold" O SubsequentTimeThreshold [SXA SXB SXC N4],
        subsequent_volume_quota: "Subsequent Volume Quota" O SubsequentVolumeQuota [SXB SXC N4],
        subsequent_time_quota: "Subsequent Time Quota" O SubsequentTimeQuota [SXB SXC N4],
        subsequent_event_threshold: "Subsequent Event Threshold" O EventThreshold [SXB SXC N4],
        subsequent_event_quota: "Subsequent Event Quota" O EventQuota [SXB SXC N4],
    }
}

pfcp_table! {
    /// Create QER IE within PFCP Session Establishment Request (Table 7.5.2.5-1).
    group CreateQer = 7, "Create QER", "7.5.2.5-1" {
        qer_id: "QER ID" M QerId [SXB SXC N4 N4MB],
        qer_correlation_id: "QER Correlation ID" C QerCorrelationId [SXB N4],
        gate_status: "Gate Status" M GateStatus [SXB SXC N4 N4MB],
        maximum_bitrate: "Maximum Bitrate" C Mbr [SXB SXC N4 N4MB],
        guaranteed_bitrate: "Guaranteed Bitrate" C Gbr [SXB SXC N4 N4MB],
        packet_rate: "Packet Rate" C PacketRate [SXB N4],
        packet_rate_status: "Packet Rate Status" C PacketRateStatus [SXB N4],
        dl_flow_level_marking: "DL Flow Level Marking" C DlFlowLevelMarking [SXB SXC],
        qos_flow_identifier: "QoS flow identifier" C Qfi [N4 N4MB],
        reflective_qos: "Reflective QoS" C Rqi [N4],
        paging_policy_indicator: "Paging Policy Indicator" C PagingPolicyIndicator [N4],
        averaging_window: "Averaging Window" O AveragingWindow [N4],
        qer_control_indications: "QER Control Indications" C QerControlIndications [SXB N4],
        qer_indications: "QER Indications" C QerIndications [N4 N4MB],
        pdu_set_importance_for_n6_unmarked_pdus: "PDU Set Importance for N6-unmarked PDUs" C PduSetImportanceForN6UnmarkedPDUs [N4],
    }
}

pfcp_table! {
    /// Create BAR IE within PFCP Session Establishment Request (Table 7.5.2.6-1).
    group CreateBar = 85, "Create BAR", "7.5.2.6-1" {
        bar_id: "BAR ID" M BarId [SXA N4],
        downlink_data_notification_delay: "Downlink Data Notification Delay" C DownlinkDataNotificationDelay [SXA],
        suggested_buffering_packets_count: "Suggested Buffering Packets Count" C SuggestedBufferingPacketsCount [SXB SXC N4],
        mt_edt_control_information: "MT-EDT Control Information" O MtEdtControlInformation [SXA],
        mt_sdt_control_information: "MT-SDT Control Information" O MtSdtControlInformation [N4],
        dl_buffering_duration: "DL Buffering Duration" C DlBufferingDuration [SXA N4],
        dl_buffering_suggested_packet_count: "DL Buffering Suggested Packet Count" O DlBufferingSuggestedPacketCount [SXA N4],
    }
}

pfcp_table! {
    /// Create Traffic Endpoint IE within PFCP Session Establishment Request (Table 7.5.2.7-1).
    group CreateTrafficEndpoint = 127, "Create Traffic Endpoint", "7.5.2.7-1" {
        traffic_endpoint_id: "Traffic Endpoint ID" M TrafficEndpointId [SXA SXB SXC N4 N4MB],
        local_f_teid: "Local F-TEID" O FTeid [SXA SXB N4],
        network_instance: "Network Instance" O NetworkInstance [SXA SXB SXC N4 N4MB],
        redundant_transmission_detection_parameters: "Redundant Transmission Detection Parameters" O RedundantTransmissionParameters [N4],
        ue_ip_address: "UE IP address" O* UeIpAddress [SXB SXC N4],
        mapped_n6_ip_address: "Mapped N6 IP Address" O MappedN6IpAddress [N4],
        n6_routing_information: "N6 Routing Information" O N6RoutingInformation [N4],
        ethernet_pdu_session_information: "Ethernet PDU Session Information" O EthernetPduSessionInformation [N4],
        framed_route: "Framed-Route" O* FramedRoute [SXB N4],
        framed_routing: "Framed-Routing" O FramedRouting [SXB N4],
        framed_ipv6_route: "Framed-IPv6-Route" O* FramedIPv6Route [SXB N4],
        qfi: "QFI" O* Qfi [N4],
        source_interface_type: "Source Interface Type" C InterfaceType3gpp [SXA SXB N4 N4MB],
        local_ingress_tunnel: "Local Ingress Tunnel" C LocalIngressTunnel [N4MB],
        ip_multicast_addressing_info: "IP Multicast Addressing Info" C IpMulticastAddressingInfo [N4MB],
        mbs_session_identifier: "MBS Session Identifier" C MbsSessionIdentifier [N4],
        area_session_id: "Area Session ID" C AreaSessionId [N4],
        rat_type: "RAT Type" O RatType [N4],
    }
}

pfcp_table! {
    /// Create MAR IE within PFCP Session Establishment Request (Table 7.5.2.8-1).
    group CreateMar = 165, "Create MAR", "7.5.2.8-1" {
        mar_id: "MAR ID" M MarId [N4],
        steering_functionality: "Steering Functionality" M SteeringFunctionality [N4],
        steering_mode: "Steering Mode" M SteeringMode [N4],
        n3gpp_access_forwarding_action_information: "3GPP Access Forwarding Action Information" C ThreeGppAccessForwardingActionInformation [N4],
        non_3gpp_access_forwarding_action_information: "Non-3GPP Access Forwarding Action Information" C NonThreeGppAccessForwardingActionInformation [N4],
        threshold_values: "Threshold Values" C Thresholds [N4],
        steering_mode_indicator: "Steering Mode Indicator" C SteeringModeIndicator [N4],
        transport_mode: "Transport Mode" C TransportMode [N4],
    }
}

pfcp_table! {
    /// 3GPP Access Forwarding Action Information IE in the Create MAR IE (Table 7.5.2.8-2).
    group ThreeGppAccessForwardingActionInformation = 166, "3GPP Access Forwarding Action Information", "7.5.2.8-2" {
        far_id: "FAR ID" M FarId [N4],
        weight: "Weight" C Weight [N4],
        priority: "Priority" C Priority [N4],
        urr_id: "URR ID" C* UrrId [N4],
        rat_type: "RAT Type" O RatType [N4],
    }
}

pfcp_table! {
    /// Non-3GPP Access Forwarding Action Information IE in the Create MAR IE (Table 7.5.2.8-3).
    group NonThreeGppAccessForwardingActionInformation = 167, "Non-3GPP Access Forwarding Action Information", "7.5.2.8-3" {
        far_id: "FAR ID" M FarId [N4],
        weight: "Weight" C Weight [N4],
        priority: "Priority" C Priority [N4],
        urr_id: "URR ID" C* UrrId [N4],
        rat_type: "RAT Type" O RatType [N4],
    }
}

pfcp_table! {
    /// Create SRR IE within PFCP Session Establishment Request (Table 7.5.2.9-1).
    group CreateSrr = 212, "Create SRR", "7.5.2.9-1" {
        srr_id: "SRR ID" M SrrId [N4],
        access_availability_control_information: "Access Availability Control Information" C AccessAvailabilityControlInformation [N4],
        qos_monitoring_per_qos_flow_control_information: "QoS Monitoring per QoS flow Control Information" C* QoSMonitoringPerQoSFlowControlInformation [N4],
        direct_reporting_information: "Direct Reporting Information" C DirectReportingInformation [N4],
        traffic_parameter_measurement_control_information: "Traffic Parameter Measurement Control Information" C* TrafficParameterMeasurementControlInformation [N4],
        reporting_control_information: "Reporting Control Information" C ReportingControlInformation [N4],
    }
}

pfcp_table! {
    /// Access Availability Control Information (Table 7.5.2.9-2).
    group AccessAvailabilityControlInformation = 216, "Access Availability Control Information", "7.5.2.9-2" {
        requested_access_availability_information: "Requested Access Availability Information" M RequestedAccessAvailabilityInformation [N4],
    }
}

pfcp_table! {
    /// QoS Monitoring per QoS flow Control Information (Table 7.5.2.9-3).
    group QoSMonitoringPerQoSFlowControlInformation = 242, "QoS Monitoring per QoS flow Control Information", "7.5.2.9-3" {
        qfi: "QFI" M* Qfi [N4],
        requested_qos_monitoring: "Requested QoS Monitoring" M RequestedQoSMonitoring [N4],
        reporting_frequency: "Reporting Frequency" M ReportingFrequency [N4],
        packet_delay_thresholds: "Packet Delay Thresholds" C PacketDelayThresholds [N4],
        minimum_wait_time: "Minimum Wait Time" C MinimumWaitTime [N4],
        measurement_period: "Measurement Period" C MeasurementPeriod [N4],
        reporting_suggestion_info: "Reporting Suggestion Info" C ReportingSuggestionInfo [N4],
        measurement_indication: "Measurement Indication" C MeasurementIndication [N4],
        reporting_thresholds: "Reporting Thresholds" C ReportingThresholds [N4],
        remaining_data_reporting_indication: "Remaining Data Reporting Indication" O RemainingDataReportingIndication [N4],
    }
}

pfcp_table! {
    /// Direct Reporting Information (Table 7.5.2.9-4).
    group DirectReportingInformation = 295, "Direct Reporting Information", "7.5.2.9-4" {
        event_notification_uri: "Event Notification URI" M EventNotificationUri [N4],
        notification_correlation_id: "Notification Correlation ID" C NotificationCorrelationId [N4],
        notification_binding_indication: "Notification Binding Indication" C BindingIndication [N4],
        reporting_flags: "Reporting Flags" C ReportingFlags [N4],
    }
}

pfcp_table! {
    /// Traffic Parameter Measurement Control Information IE (Table 7.5.2.9-5).
    group TrafficParameterMeasurementControlInformation = 323, "Traffic Parameter Measurement Control Information", "7.5.2.9-5" {
        qfi: "QFI" M* Qfi [N4],
        traffic_parameter_measurement_indication: "Traffic Parameter Measurement Indication" M TrafficParameterMeasurementIndication [N4],
        measurement_period: "Measurement Period" C MeasurementPeriod [N4],
        dl_periodicity: "DL Periodicity" C DlPeriodicity [N4],
        traffic_parameter_threshold: "Traffic Parameter Threshold" C TrafficParameterThreshold [N4],
    }
}

pfcp_table! {
    /// Provide ATSSS Control Information IE within PFCP Session Establishment Request (Table 7.5.2.10-1).
    group ProvideAtsssControlInformation = 220, "Provide ATSSS Control Information", "7.5.2.10-1" {
        mptcp_control_information: "MPTCP Control Information" C MptcpControlInformation [N4],
        atsss_ll_control_information: "ATSSS-LL Control Information" C AtsssLlControlInformation [N4],
        pmf_control_information: "PMF Control Information" C PmfControlInformation [N4],
        mpquic_control_information: "MPQUIC Control Information" C MpquicControlInformation [N4],
    }
}

pfcp_table! {
    /// Provide RDS Configuration Information IE within PFCP Session Establishment Request (Table 7.5.2.11-1).
    group ProvideRdsConfigurationInformation = 261, "Provide RDS configuration information", "7.5.2.11-1" {
        rds_configuration_information: "RDS Configuration Information" O RdsConfigurationInformation [SXB N4],
    }
}

pfcp_table! {
    /// Information Elements in a Partial Failure Information (Table 7.5.3.1-2).
    group PartialFailureInformation = 272, "Partial Failure Information", "7.5.3.1-2" {
        failed_rule_id: "Failed Rule ID" M FailedRuleId [SXB SXC N4 N4MB],
        failure_cause: "Failure Cause" M Cause [SXB SXC N4 N4MB],
        offending_ie_information: "Offending IE Information" M* OffendingIeInformation [SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Created L2TP Session IE in the PFCP Session Establishment Response message (Table 7.5.3.1-3).
    group CreatedL2tpSession = 279, "Created L2TP Session", "7.5.3.1-3" {
        dns_server_address: "DNS Server Address" O* DnsServerAddress [SXB N4],
        nbns_server_address: "NBNS Server Address" O* NbnsServerAddress [SXB N4],
        lns_address: "LNS Address" O LnsAddress [SXB N4],
    }
}

pfcp_table! {
    /// MBS Session N4mb Information IE within PFCP Session Establishment Response (Table 7.5.3.1-4).
    group MbsSessionN4mbInformation = 303, "MBS Session N4mb Information", "7.5.3.1-4" {
        multicast_transport_information: "Multicast Transport Information" C MulticastTransportInformation [N4MB],
    }
}

pfcp_table! {
    /// MBS Session N4 Information IE within PFCP Session Establishment Response (Table 7.5.3.1-5).
    group MbsSessionN4Information = 311, "MBS Session N4 Information", "7.5.3.1-5" {
        mbs_session_identifier: "MBS Session Identifier" M MbsSessionIdentifier [N4],
        area_session_id: "Area Session ID" C AreaSessionId [N4],
        n19mb_dl_tunnel_id: "N19mb DL Tunnel ID" C FTeid [N4],
        mbsn4resp_flags: "MBSN4Resp-Flags" C MBSN4RespFlags [N4],
    }
}

pfcp_table! {
    /// MoQ Information IE within PFCP Session Establishment Response (Table 7.5.3.1-6).
    group MoQInformation = 386, "MoQ Information", "7.5.3.1-6" {
        moq_relay_address: "MoQ Relay Address" C MoQRelayIpAddress [N4],
    }
}

pfcp_table! {
    /// Created PDR IE within PFCP Session Establishment Response (Table 7.5.3.2-1).
    group CreatedPdr = 8, "Created PDR", "7.5.3.2-1" {
        pdr_id: "PDR ID" M PdrId [SXA SXB N4 N4MB],
        f_teid: "F-TEID" C*2 FTeid [SXA SXB N4]
            roles ["Local F-TEID" C [SXA SXB N4], "Local F-TEID for Redundant Transmission" C [N4]],
        ue_ip_address: "UE IP Address" C* UeIpAddress [SXB N4],
        mapped_n6_ip_address: "Mapped N6 IP Address" C MappedN6IpAddress [N4],
        local_ingress_tunnel: "Local Ingress Tunnel" C LocalIngressTunnel [N4MB],
    }
}

pfcp_table! {
    /// Load Control Information IE within PFCP Session Establishment Response (Table 7.5.3.3-1).
    group LoadControlInformation = 51, "Load Control Information", "7.5.3.3-1" {
        load_control_sequence_number: "Load Control Sequence Number" M SequenceNumber [SXA SXB SXC N4 N4MB],
        load_metric: "Load Metric" M Metric [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Overload Control Information IE within PFCP Session Establishment Response (Table 7.5.3.4-1).
    group OverloadControlInformation = 54, "Overload Control Information", "7.5.3.4-1" {
        overload_control_sequence_number: "Overload Control Sequence Number" M SequenceNumber [SXA SXB SXC N4 N4MB],
        overload_reduction_metric: "Overload Reduction Metric" M Metric [SXA SXB SXC N4 N4MB],
        period_of_validity: "Period of Validity" M Timer [SXA SXB SXC N4 N4MB],
        overload_control_information_flags: "Overload Control Information Flags" C OciFlags [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Created Traffic Endpoint IE within PFCP Session Establishment Response (Table 7.5.3.5-1).
    group CreatedTrafficEndpoint = 128, "Created Traffic Endpoint", "7.5.3.5-1" {
        traffic_endpoint_id: "Traffic Endpoint ID" M TrafficEndpointId [SXA SXB N4 N4MB],
        f_teid: "F-TEID" C*2 FTeid [SXA SXB N4]
            roles ["Local F-TEID" C [SXA SXB N4], "Local F-TEID for Redundant Transmission" C [N4]],
        ue_ip_address: "UE IP Address" C* UeIpAddress [SXB N4],
        mapped_n6_ip_address: "Mapped N6 IP Address" C MappedN6IpAddress [N4],
        local_ingress_tunnel: "Local Ingress Tunnel" C LocalIngressTunnel [N4MB],
    }
}

pfcp_table! {
    /// Created Bridge/Router Info IE within PFCP Session Establishment Response (Table 7.5.3.6-1).
    group CreatedBridgeRouterInfo = 195, "Created Bridge/Router Info", "7.5.3.6-1" {
        port_number: "Port Number" C PortNumber [N4],
        n5gs_user_plane_node_id: "5GS User Plane Node ID" C FiveGsUserPlaneNodeId [N4],
    }
}

pfcp_table! {
    /// ATSSS Control Parameters IE within PFCP Session Establishment Response (Table 7.5.3.7-1).
    group AtsssControlParameters = 221, "ATSSS Control Parameters", "7.5.3.7-1" {
        mptcp_parameters: "MPTCP Parameters" C MptcpParameters [N4],
        atsss_ll_parameters: "ATSSS-LL Parameters" C AtsssLlParameters [N4],
        pmf_parameters: "PMF Parameters" C* PmfParameters [N4],
        mpquic_parameters: "MPQUIC Parameters" C MpquicParameters [N4],
    }
}

pfcp_table! {
    /// MPTCP Parameters IE within PFCP Session Establishment Response (Table 7.5.3.7-2).
    group MptcpParameters = 225, "MPTCP Parameters", "7.5.3.7-2" {
        mptcp_address_information: "MPTCP Address Information" M MptcpAddressInformation [N4],
        mptcp_link_specific_ip_address: "MPTCP Link-Specific IP Address" M LinkSpecificMultipathIpAddress [N4],
    }
}

pfcp_table! {
    /// ATSSS-LL Parameters IE within PFCP Session Establishment Response (Table 7.5.3.7-3).
    group AtsssLlParameters = 226, "ATSSS-LL Parameters", "7.5.3.7-3" {
        atsss_ll_information: "ATSSS-LL Information" M AtsssLlInformation [N4],
    }
}

pfcp_table! {
    /// PMF Parameters IE within PFCP Session Establishment Response (Table 7.5.3.7-4).
    group PmfParameters = 227, "PMF Parameters", "7.5.3.7-4" {
        pmf_address_information: "PMF Address Information" M PmfAddressInformation [N4],
        qos_flow_identifier: "QoS flow identifier" O Qfi [N4],
    }
}

pfcp_table! {
    /// MPQUIC Parameters IE within PFCP Session Establishment Response (Table 7.5.3.7-5).
    group MpquicParameters = 331, "MPQUIC Parameters", "7.5.3.7-5" {
        mpquic_address_information: "MPQUIC Address Information" M*2 MpquicAddressInformation [N4],
        mpquic_link_specific_ip_address: "MPQUIC Link-Specific IP Address" M LinkSpecificMultipathIpAddress [N4],
    }
}

pfcp_table! {
    /// Update PDR IE within PFCP Session Modification Request (Table 7.5.4.2-1).
    group UpdatePdr = 9, "Update PDR", "7.5.4.2-1" {
        pdr_id: "PDR ID" M PdrId [SXA SXB SXC N4 N4MB],
        outer_header_removal: "Outer Header Removal" C OuterHeaderRemoval [SXA SXB N4 N4MB],
        precedence: "Precedence" C Precedence [SXB SXC N4 N4MB],
        pdi: "PDI" C Pdi [SXA SXB SXC N4 N4MB],
        far_id: "FAR ID" C FarId [SXA SXB SXC N4 N4MB],
        urr_id: "URR ID" C* UrrId [SXA SXB SXC N4],
        qer_id: "QER ID" C* QerId [SXB SXC N4 N4MB],
        activate_predefined_rules: "Activate Predefined Rules" C* ActivatePredefinedRules [SXB SXC N4],
        deactivate_predefined_rules: "Deactivate Predefined Rules" C* DeactivatePredefinedRules [SXB SXC N4],
        activation_time: "Activation Time" O ActivationTime [SXB SXC N4],
        deactivation_time: "Deactivation Time" O DeactivationTime [SXB SXC N4],
        ip_multicast_addressing_info: "IP Multicast Addressing Info" O* IpMulticastAddressingInfo [N4],
        transport_delay_reporting: "Transport Delay Reporting" C TransportDelayReporting [N4],
        rat_type: "RAT Type" O RatType [N4],
    }
}

pfcp_table! {
    /// Update FAR IE within PFCP Session Modification Request (Table 7.5.4.3-1).
    group UpdateFar = 10, "Update FAR", "7.5.4.3-1" {
        far_id: "FAR ID" M FarId [SXA SXB SXC N4 N4MB],
        apply_action: "Apply Action" C ApplyAction [SXA SXB SXC N4 N4MB],
        update_forwarding_parameters: "Update Forwarding parameters" Ci UpdateForwardingParameters [SXA SXB SXC N4],
        update_duplicating_parameters: "Update Duplicating Parameters" C* UpdateDuplicatingParameters [SXA SXB],
        redundant_transmission_forwarding_parameters: "Redundant Transmission Forwarding Parameters" C RedundantTransmissionForwardingParameters [N4],
        bar_id: "BAR ID" C BarId [SXA N4],
        add_mbs_unicast_parameters: "Add MBS Unicast Parameters" C* AddMbsUnicastParameters [N4MB],
        remove_mbs_unicast_parameters: "Remove MBS Unicast Parameters" C* RemoveMbsUnicastParameters [N4MB],
    }
}

pfcp_table! {
    /// Update Forwarding Parameters IE in the Update FAR IE (Table 7.5.4.3-2).
    group UpdateForwardingParameters = 11, "Update Forwarding Parameters", "7.5.4.3-2" {
        destination_interface: "Destination Interface" C DestinationInterface [SXA SXB SXC N4],
        network_instance: "Network instance" C NetworkInstance [SXA SXB SXC N4],
        redirect_information: "Redirect Information" C RedirectInformation [SXB SXC N4],
        outer_header_creation: "Outer Header Creation" C OuterHeaderCreation [SXA SXB N4],
        transport_level_marking: "Transport Level Marking" C TransportLevelMarking [SXA SXB N4],
        extended_transport_level_marking: "Extended Transport Level Marking" C ExtendedTransportLevelMarking [N4],
        transport_level_marking_indications: "Transport Level Marking Indications" C TransportLevelMarkingIndications [N4],
        forwarding_policy: "Forwarding Policy" C ForwardingPolicy [SXB SXC N4],
        metadata: "Metadata" C Metadata [N4],
        header_enrichment: "Header Enrichment" C HeaderEnrichment [SXB SXC N4],
        pfcpsmreq_flags: "PFCPSMReq-Flags" C PFCPSMReqFlags [SXA SXB N4],
        linked_traffic_endpoint_id: "Linked Traffic Endpoint ID" C TrafficEndpointId [SXA SXB N4],
        destination_interface_type: "Destination Interface Type" C InterfaceType3gpp [SXA SXB N4],
        data_network_access_identifier: "Data Network Access Identifier" C DataNetworkAccessIdentifier [],
        ip_address_and_port_number_replacement: "IP Address and Port Number Replacement" C IpAddressAndPortNumberReplacement [N4],
        header_handling_control_rule: "Header Handling Control Rule" C HeaderHandlingControlRule [N4],
    }
}

pfcp_table! {
    /// Update Duplicating Parameters IE in the Update FAR IE (Table 7.5.4.3-3).
    group UpdateDuplicatingParameters = 105, "Update Duplicating Parameters", "7.5.4.3-3" {
        destination_interface: "Destination Interface" C DestinationInterface [SXA SXB],
        outer_header_creation: "Outer Header Creation" C OuterHeaderCreation [SXA SXB],
        transport_level_marking: "Transport Level Marking" C TransportLevelMarking [SXA SXB],
        forwarding_policy: "Forwarding Policy" C ForwardingPolicy [SXB],
    }
}

pfcp_table! {
    /// Remove MBS Unicast Parameters IE in the Update FAR IE (Table 7.5.4.3-4).
    group RemoveMbsUnicastParameters = 304, "Remove MBS Unicast Parameters", "7.5.4.3-4" {
        mbs_unicast_parameters_id: "MBS Unicast Parameters ID" M MbsUnicastParametersId [N4MB],
    }
}

pfcp_table! {
    /// Update URR IE within PFCP Session Modification Request (Table 7.5.4.4-1).
    group UpdateUrr = 13, "Update URR", "7.5.4.4-1" by [SXA SXB SXC N4 N4MB] {
        urr_id: "URR ID" M UrrId [SXA SXB SXC N4],
        measurement_method: "Measurement Method" C MeasurementMethod [SXA SXB SXC N4],
        reporting_triggers: "Reporting Triggers" C ReportingTriggers [SXA SXB SXC N4 N4MB],
        measurement_period: "Measurement Period" C MeasurementPeriod [SXA SXB SXC N4 N4MB],
        volume_threshold: "Volume Threshold" C VolumeThreshold [SXA SXB SXC N4 N4MB],
        volume_quota: "Volume Quota" C VolumeQuota [SXB SXC N4],
        time_threshold: "Time Threshold" C TimeThreshold [SXA SXB SXC N4],
        time_quota: "Time Quota" C TimeQuota [SXB SXC N4],
        event_threshold: "Event Threshold" C EventThreshold [SXB SXC N4],
        event_quota: "Event Quota" C EventQuota [SXB SXC N4],
        quota_holding_time: "Quota Holding Time" C QuotaHoldingTime [SXB SXC N4],
        dropped_dl_traffic_threshold: "Dropped DL Traffic Threshold" C DroppedDlTrafficThreshold [SXA N4],
        quota_validity_time: "Quota Validity Time" C QuotaValidityTime [SXB N4],
        monitoring_time: "Monitoring Time" C MonitoringTime [SXA SXB SXC N4],
        subsequent_volume_threshold: "Subsequent Volume Threshold" C SubsequentVolumeThreshold [SXA SXB SXC N4],
        subsequent_time_threshold: "Subsequent Time Threshold" C SubsequentTimeThreshold [SXA SXB SXC N4],
        subsequent_volume_quota: "Subsequent Volume Quota" C SubsequentVolumeQuota [SXB SXC N4],
        subsequent_time_quota: "Subsequent Time Quota" C SubsequentTimeQuota [SXB SXC N4],
        subsequent_event_threshold: "Subsequent Event Threshold" O SubsequentEventThreshold [SXB SXC N4],
        subsequent_event_quota: "Subsequent Event Quota" O SubsequentEventQuota [SXB SXC N4],
        inactivity_detection_time: "Inactivity Detection Time" C InactivityDetectionTime [SXB SXC N4],
        linked_urr_id: "Linked URR ID" C* LinkedUrrId [SXB SXC N4 N4MB],
        measurement_information: "Measurement Information" C MeasurementInformation [SXA SXB SXC N4],
        time_quota_mechanism: "Time Quota Mechanism" C TimeQuotaMechanism [SXB],
        aggregated_urrs: "Aggregated URRs" C* AggregatedURRs [SXB],
        far_id_for_quota_action: "FAR ID for Quota Action" C FarId [SXB SXC N4],
        ethernet_inactivity_timer: "Ethernet Inactivity Timer" C EthernetInactivityTimer [N4],
        additional_monitoring_time: "Additional Monitoring Time" O AdditionalMonitoringTime [SXA SXB SXC N4],
        number_of_reports: "Number of Reports" O NumberOfReports [SXA SXB SXC N4],
        exempted_application_id_for_quota_action: "Exempted Application ID for Quota Action" C* ApplicationId [SXB SXC N4],
        exempted_sdf_filter_for_quota_action: "Exempted SDF Filter for Quota Action" C* SdfFilter [SXB SXC N4],
        user_plane_inactivity_timer: "User Plane Inactivity Timer" C UserPlaneInactivityTimer [N4],
    }
}

pfcp_table! {
    /// Update QER IE within PFCP Session Modification Request (Table 7.5.4.5-1).
    group UpdateQer = 14, "Update QER", "7.5.4.5-1" {
        qer_id: "QER ID" M QerId [SXB SXC N4 N4MB],
        qer_correlation_id: "QER Correlation ID" C QerCorrelationId [SXB N4],
        gate_status: "Gate Status" C GateStatus [SXB SXC N4 N4MB],
        maximum_bitrate: "Maximum Bitrate" C Mbr [SXB SXC N4 N4MB],
        guaranteed_bitrate: "Guaranteed Bitrate" C Gbr [SXB SXC N4 N4MB],
        packet_rate: "Packet Rate" C PacketRate [SXB N4],
        dl_flow_level_marking: "DL Flow Level Marking" C DlFlowLevelMarking [SXB SXC],
        qos_flow_identifier: "QoS flow identifier" C Qfi [N4 N4MB],
        reflective_qos: "Reflective QoS" C Rqi [N4],
        paging_policy_indicator: "Paging Policy Indicator" C PagingPolicyIndicator [N4],
        averaging_window: "Averaging Window" O AveragingWindow [N4],
        qer_control_indications: "QER Control Indications" C QerControlIndications [SXB N4],
        qer_indications: "QER Indications" C QerIndications [N4],
        pdu_set_importance_for_n6_unmarked_pdus: "PDU Set Importance for N6-unmarked PDUs" C PduSetImportanceForN6UnmarkedPDUs [N4],
    }
}

pfcp_table! {
    /// Remove PDR IE within PFCP Session Modification Request (Table 7.5.4.6-1).
    group RemovePdr = 15, "Remove PDR", "7.5.4.6-1" {
        pdr_id: "PDR ID" M PdrId [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Remove FAR IE within PFCP Session Modification Request (Table 7.5.4.7-1).
    group RemoveFar = 16, "Remove FAR", "7.5.4.7-1" {
        far_id: "FAR ID" M FarId [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Remove URR IE within PFCP Session Modification Request (Table 7.5.4.8-1).
    group RemoveUrr = 17, "Remove URR", "7.5.4.8-1" {
        urr_id: "URR ID" M UrrId [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Remove QER IE PFCP Session Modification Request (Table 7.5.4.9-1).
    group RemoveQer = 18, "Remove QER", "7.5.4.9-1" {
        qer_id: "QER ID" M QerId [SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Query URR IE within PFCP Session Modification Request (Table 7.5.4.10-1).
    group QueryUrr = 77, "Query URR", "7.5.4.10-1" {
        urr_id: "URR ID" M UrrId [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Update BAR IE within PFCP Session Modification Request (Table 7.5.4.11-1).
    group UpdateBar = 86, "Update BAR", "7.5.4.11-1" {
        bar_id: "BAR ID" M BarId [SXA N4],
        downlink_data_notification_delay: "Downlink Data Notification Delay" C DownlinkDataNotificationDelay [SXA],
        suggested_buffering_packets_count: "Suggested Buffering Packets Count" C SuggestedBufferingPacketsCount [SXB SXC N4],
        dl_buffering_duration: "DL Buffering Duration" C DlBufferingDuration [SXA N4],
        dl_buffering_suggested_packet_count: "DL Buffering Suggested Packet Count" O DlBufferingSuggestedPacketCount [SXA N4],
        mt_edt_control_information: "MT-EDT Control Information" O MtEdtControlInformation [SXA],
        mt_sdt_control_information: "MT-SDT Control Information" O MtSdtControlInformation [N4],
        extended_dl_buffering_notification_policy: "Extended DL Buffering Notification Policy" C ExtendedDlBufferingNotificationPolicy [N4],
    }
}

pfcp_table! {
    /// Remove BAR IE within PFCP Session Modification Request (Table 7.5.4.12-1).
    group RemoveBar = 87, "Remove BAR", "7.5.4.12-1" {
        bar_id: "BAR ID" M BarId [SXA N4],
    }
}

pfcp_table! {
    /// Update Traffic Endpoint IE within PFCP Session Modification Request (Table 7.5.4.13-1).
    group UpdateTrafficEndpoint = 129, "Update Traffic Endpoint", "7.5.4.13-1" {
        traffic_endpoint_id: "Traffic Endpoint ID" M TrafficEndpointId [SXA SXB SXC N4 N4MB],
        local_f_teid: "Local F-TEID" C FTeid [SXA N4],
        network_instance: "Network Instance" O NetworkInstance [SXA SXB SXC N4 N4MB],
        redundant_transmission_detection_parameters: "Redundant Transmission Detection Parameters" C RedundantTransmissionParameters [N4],
        ue_ip_address: "UE IP address" C* UeIpAddress [SXB SXC N4],
        framed_route: "Framed-Route" C* FramedRoute [SXB N4],
        framed_routing: "Framed-Routing" C FramedRouting [SXB N4],
        framed_ipv6_route: "Framed-IPv6-Route" C* FramedIPv6Route [SXB N4],
        qfi: "QFI" C* Qfi [N4],
        source_interface_type: "Source Interface Type" C InterfaceType3gpp [SXA SXB N4 N4MB],
        rat_type: "RAT Type" O RatType [N4],
    }
}

pfcp_table! {
    /// Remove Traffic Endpoint IE within PFCP Session Modification Request (Table 7.5.4.14-1).
    group RemoveTrafficEndpoint = 130, "Remove Traffic Endpoint", "7.5.4.14-1" {
        traffic_endpoint_id: "Traffic Endpoint ID" M TrafficEndpointId [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Remove MAR IE within PFCP Session Modification Request (Table 7.5.4.15-1).
    group RemoveMar = 168, "Remove MAR", "7.5.4.15-1" {
        mar_id: "MAR ID" M MarId [N4],
    }
}

pfcp_table! {
    /// Update MAR IE within PFCP Session Modification Request (Table 7.5.4.16-1).
    group UpdateMar = 169, "Update MAR", "7.5.4.16-1" {
        mar_id: "MAR ID" M MarId [N4],
        steering_functionality: "Steering Functionality" C SteeringFunctionality [N4],
        steering_mode: "Steering Mode" C SteeringMode [N4],
        update_3gpp_access_forwarding_action_information: "Update 3GPP Access Forwarding Action Information" C UpdateThreeGppAccessForwardingActionInformation [N4],
        update_non_3gpp_access_forwarding_action_information: "Update Non-3GPP Access Forwarding Action Information" C UpdateNonThreeGppAccessForwardingActionInformation [N4],
        n3gpp_access_forwarding_action_information: "3GPP Access Forwarding Action Information" C ThreeGppAccessForwardingActionInformation [N4],
        non_3gpp_access_forwarding_action_information: "Non-3GPP Access Forwarding Action Information" C NonThreeGppAccessForwardingActionInformation [N4],
        threshold_values: "Threshold values" C Thresholds [N4],
        steering_mode_indicator: "Steering Mode Indicator" C SteeringModeIndicator [N4],
        transport_mode: "Transport Mode" C TransportMode [N4],
    }
}

pfcp_table! {
    /// Update 3GPP Access Forwarding Action Information IE in Update MAR IE (Table 7.5.4.16-2).
    group UpdateThreeGppAccessForwardingActionInformation = 175, "Update 3GPP Access Forwarding Action Information", "7.5.4.16-2" {
        far_id: "FAR ID" C FarId [N4],
        weight: "Weight" C Weight [N4],
        priority: "Priority" C Priority [N4],
        urr_id: "URR ID" C* UrrId [N4],
        rat_type: "RAT Type" O RatType [N4],
    }
}

pfcp_table! {
    /// Update Non-3GPP Access Forwarding Action Information IE in Update MAR IE (Table 7.5.4.16-3).
    group UpdateNonThreeGppAccessForwardingActionInformation = 176, "Update Non 3GPP Access Forwarding Action Information", "7.5.4.16-3" {
        far_id: "FAR ID" C FarId [N4],
        weight: "Weight" C Weight [N4],
        priority: "Priority" C Priority [N4],
        urr_id: "URR ID" C* UrrId [N4],
        rat_type: "RAT Type" O RatType [N4],
    }
}

pfcp_table! {
    /// TSC Management Information IE within PFCP Session Modification Request (Table 7.5.4.18-1).
    group TscManagementInformation = 199, "TSC Management Information", "7.5.4.18-1" {
        port_management_information_container: "Port Management Information Container" O PortManagementInformationContainer [N4],
        user_plane_node_management_information_container: "User Plane Node Management Information Container" O UserPlaneNodeManagementInformationContainer [N4],
        nw_tt_port_number: "NW-TT Port Number" C NwTtPortNumber [N4],
        direct_reporting_information: "Direct Reporting Information" C DirectReportingInformationTsc [N4],
    }
}

pfcp_table! {
    /// Direct Reporting Information (Table 7.5.4.18-2).
    group DirectReportingInformationTsc = 295, "Direct Reporting Information", "7.5.4.18-2" {
        event_notification_uri: "Event Notification URI" M EventNotificationUri [N4],
        notification_correlation_id: "Notification Correlation ID" C NotificationCorrelationId [N4],
        notification_binding_indication: "Notification Binding Indication" C BindingIndication [N4],
    }
}

pfcp_table! {
    /// Remove SRR IE within PFCP Session Modification Request (Table 7.5.4.19-1).
    group RemoveSrr = 211, "Remove SRR", "7.5.4.19-1" {
        srr_id: "SRR ID" M SrrId [N4],
    }
}

pfcp_table! {
    /// Update SRR IE within PFCP Session Modification Request (Table 7.5.4.20-1).
    group UpdateSrr = 213, "Update SRR", "7.5.4.20-1" {
        srr_id: "SRR ID" M SrrId [N4],
        access_availability_control_information: "Access Availability Control Information" C AccessAvailabilityControlInformation [N4],
        qos_monitoring_per_qos_flow_control_information: "QoS Monitoring per QoS flow Control Information" C* QoSMonitoringPerQoSFlowControlInformation [N4],
        direct_reporting_information: "Direct Reporting Information" C DirectReportingInformationTsc [N4],
        traffic_parameter_measurement_control_information: "Traffic Parameter Measurement Control Information" C* TrafficParameterMeasurementControlInformation [N4],
    }
}

pfcp_table! {
    /// Ethernet Context Information IE within PFCP Session Modification Request (Table 7.5.4.21-1).
    group EthernetContextInformation = 254, "Ethernet Context Information", "7.5.4.21-1" {
        mac_addresses_detected: "MAC Addresses Detected" M* MacAddressesDetected [N4],
    }
}

pfcp_table! {
    /// Query Packet Rate Status IE within PFCP Session Modification Request (Table 7.5.4.22-1).
    group QueryPacketRateStatus = 263, "Query Packet Rate Status", "7.5.4.22-1" {
        qer_id: "QER ID" M QerId [SXB N4],
    }
}

pfcp_table! {
    /// Usage Report IE within PFCP Session Modification Response (Table 7.5.5.2-1).
    group UsageReportModification = 78, "Usage Report", "7.5.5.2-1" {
        urr_id: "URR ID" M UrrId [SXA SXB SXC N4 N4MB],
        ur_seqn: "UR-SEQN" M UrSeqn [SXA SXB SXC N4 N4MB],
        usage_report_trigger: "Usage Report Trigger" M UsageReportTrigger [SXA SXB SXC N4 N4MB],
        start_time: "Start Time" C StartTime [SXA SXB SXC N4 N4MB],
        end_time: "End Time" C EndTime [SXA SXB SXC N4 N4MB],
        volume_measurement: "Volume Measurement" C VolumeMeasurement [SXA SXB SXC N4 N4MB],
        duration_measurement: "Duration Measurement" C DurationMeasurement [SXA SXB SXC N4],
        time_of_first_packet: "Time of First Packet" C TimeOfFirstPacket [SXB SXC N4 N4MB],
        time_of_last_packet: "Time of Last Packet" C TimeOfLastPacket [SXB SXC N4 N4MB],
        usage_information: "Usage Information" C UsageInformation [SXA SXB SXC N4],
        query_urr_reference: "Query URR Reference" C QueryUrrReference [SXA SXB SXC N4 N4MB],
        ethernet_traffic_information: "Ethernet Traffic Information" C EthernetTrafficInformation [N4],
    }
}

pfcp_table! {
    /// TSC Management Information IE within PFCP Session Modification Response (Table 7.5.5.3-1).
    group TscManagementInformationResponse = 200, "TSC Management Information", "7.5.5.3-1" {
        port_management_information_container: "Port Management Information Container" O PortManagementInformationContainer [N4],
        user_plane_node_management_information_container: "User Plane Node Management Information Container" O UserPlaneNodeManagementInformationContainer [N4],
        nw_tt_port_number: "NW-TT Port Number" C NwTtPortNumber [N4],
    }
}

pfcp_table! {
    /// Packet Rate Status Report IE within PFCP Session Modification Response message (Table 7.5.5.4-1).
    group PacketRateStatusReportModification = 264, "Packet Rate Status Report", "7.5.5.4-1" {
        qer_id: "QER ID" M QerId [SXB N4],
        packet_rate_status: "Packet Rate Status" M PacketRateStatus [SXB N4],
    }
}

pfcp_table! {
    /// Updated PDR IE in PFCP Session Modification Response (Table 7.5.5.5-1).
    group UpdatedPdr = 256, "Updated PDR", "7.5.5.5-1" by [SXB N4] {
        pdr_id: "PDR ID" M PdrId [N4],
        f_teid: "F-TEID" C*2 FTeid [SXB N4]
            roles ["Local F-TEID for Redundant Transmission" C [N4], "Local F-TEID" C [SXB]],
        ue_ip_address: "UE IP Address" C* UeIpAddress [SXB N4],
    }
}

pfcp_table! {
    /// Packet Rate Status Report IE within PFCP Session Deletion Response message (Table 7.5.7.1-2).
    group PacketRateStatusReport = 252, "Packet Rate Status Report", "7.5.7.1-2" {
        qer_id: "QER ID" M QerId [SXB N4],
        packet_rate_status: "Packet Rate Status" M PacketRateStatus [SXB N4],
    }
}

pfcp_table! {
    /// Usage Report IE within PFCP Session Deletion Response (Table 7.5.7.2-1).
    group UsageReportDeletion = 79, "Usage Report", "7.5.7.2-1" {
        urr_id: "URR ID" M UrrId [SXA SXB SXC N4 N4MB],
        ur_seqn: "UR-SEQN" M UrSeqn [SXA SXB SXC N4 N4MB],
        usage_report_trigger: "Usage Report Trigger" M UsageReportTrigger [SXA SXB SXC N4 N4MB],
        start_time: "Start Time" C StartTime [SXA SXB SXC N4 N4MB],
        end_time: "End Time" C EndTime [SXA SXB SXC N4 N4MB],
        volume_measurement: "Volume Measurement" C VolumeMeasurement [SXA SXB SXC N4 N4MB],
        duration_measurement: "Duration Measurement" C DurationMeasurement [SXA SXB SXC N4],
        time_of_first_packet: "Time of First Packet" C TimeOfFirstPacket [SXB SXC N4 N4MB],
        time_of_last_packet: "Time of Last Packet" C TimeOfLastPacket [SXB SXC N4 N4MB],
        usage_information: "Usage Information" C UsageInformation [SXA SXB SXC N4],
        ethernet_traffic_information: "Ethernet Traffic Information" C EthernetTrafficInformation [N4],
    }
}

pfcp_table! {
    /// Session Report IE within PFCP Session Deletion Response (Table 7.5.7.3-1).
    group SessionReportDeletion = 214, "Session Report", "7.5.7.3-1" {
        srr_id: "SRR ID" M SrrId [N4],
        qos_monitoring_report: "QoS Monitoring Report" C* QoSMonitoringReport [N4],
    }
}

pfcp_table! {
    /// Downlink Data Report IE within PFCP Session Report Request (Table 7.5.8.2-1).
    group DownlinkDataReport = 83, "Downlink Data Report", "7.5.8.2-1" {
        pdr_id: "PDR ID" M* PdrId [SXA N4 N4MB],
        downlink_data_service_information: "Downlink Data Service Information" C* DownlinkDataServiceInformation [SXA N4],
        dl_data_packets_size: "DL Data Packets Size" O DlDataPacketsSize [SXA],
        dl_data_status: "DL Data Status" O DataStatus [N4],
    }
}

pfcp_table! {
    /// Usage Report IE within PFCP Session Report Request (Table 7.5.8.3-1).
    group UsageReport = 80, "Usage Report", "7.5.8.3-1" {
        urr_id: "URR ID" M UrrId [SXA SXB SXC N4 N4MB],
        ur_seqn: "UR-SEQN" M UrSeqn [SXA SXB SXC N4 N4MB],
        usage_report_trigger: "Usage Report Trigger" M UsageReportTrigger [SXA SXB SXC N4 N4MB],
        start_time: "Start Time" C StartTime [SXA SXB SXC N4 N4MB],
        end_time: "End Time" C EndTime [SXA SXB SXC N4 N4MB],
        volume_measurement: "Volume Measurement" C VolumeMeasurement [SXA SXB SXC N4 N4MB],
        duration_measurement: "Duration Measurement" C DurationMeasurement [SXA SXB SXC N4],
        application_detection_information: "Application Detection Information" C ApplicationDetectionInformation [SXB SXC N4],
        ue_ip_address: "UE IP address" C UeIpAddress [SXC N4],
        network_instance: "Network Instance" C NetworkInstance [SXC N4],
        time_of_first_packet: "Time of First Packet" C TimeOfFirstPacket [SXB SXC N4 N4MB],
        time_of_last_packet: "Time of Last Packet" C TimeOfLastPacket [SXB SXC N4 N4MB],
        usage_information: "Usage Information" C UsageInformation [SXA SXB SXC N4],
        query_urr_reference: "Query URR Reference" C QueryUrrReference [SXA SXB SXC N4 N4MB],
        event_time_stamp: "Event Time Stamp" C* TimeStamp [SXB SXC N4],
        ethernet_traffic_information: "Ethernet Traffic Information" C EthernetTrafficInformation [N4],
        join_ip_muticast_information: "Join IP Muticast Information" C* JoinIpMulticastInformation [N4],
        leave_ip_muticast_information: "Leave IP Muticast Information" C* LeaveIpMulticastInformation [N4],
        predefined_rules_name: "Predefined Rules Name" O* PredefinedRulesName [SXB N4],
    }
}

pfcp_table! {
    /// Application Detection Information IE within Usage Report IE (Table 7.5.8.3-2).
    group ApplicationDetectionInformation = 68, "Application Detection Information", "7.5.8.3-2" {
        application_id: "Application ID" M ApplicationId [SXB SXC N4],
        application_instance_id: "Application Instance ID" C ApplicationInstanceId [SXB SXC N4],
        flow_information: "Flow Information" C FlowInformation [SXB SXC N4],
        pdr_id: "PDR ID" O PdrId [SXB SXC N4],
    }
}

pfcp_table! {
    /// Ethernet Traffic Information IE within Usage Report IE (Table 7.5.8.3-3).
    group EthernetTrafficInformation = 143, "Ethernet Traffic Information", "7.5.8.3-3" {
        mac_addresses_detected: "MAC Addresses Detected" C* MacAddressesDetected [N4],
        mac_addresses_removed: "MAC Addresses Removed" C* MacAddressesRemoved [N4],
    }
}

pfcp_table! {
    /// Join IP Multicast Information IE within Usage Report IE (Table 7.5.8.3-4).
    group JoinIpMulticastInformation = 189, "Join IP Multicast Information", "7.5.8.3-4" {
        ip_multicast_address: "IP Multicast Address" M IpMulticastAddress [N4],
        source_ip_address: "Source IP Address" C* SourceIpAddress [N4],
    }
}

pfcp_table! {
    /// Leave IP Multicast Information IE within Usage Report IE (Table 7.5.8.3-5).
    group LeaveIpMulticastInformation = 190, "Leave IP Multicast Information", "7.5.8.3-5" {
        ip_multicast_address: "IP Multicast Address" M IpMulticastAddress [N4],
        source_ip_address: "Source IP Address" C* SourceIpAddress [N4],
    }
}

pfcp_table! {
    /// Error Indication Report IE within PFCP Session Report Request (Table 7.5.8.4-1).
    group ErrorIndicationReport = 99, "Error Indication Report", "7.5.8.4-1" {
        remote_f_teid: "Remote F-TEID" M* FTeid [SXA SXB N4 N4MB],
    }
}

pfcp_table! {
    /// TSC Management Information IE within PFCP Session Report Request (Table 7.5.8.5-1).
    group TscManagementInformationReport = 201, "TSC Management Information", "7.5.8.5-1" {
        port_management_information_container: "Port Management Information Container" O PortManagementInformationContainer [N4],
        user_plane_node_management_information_container: "User Plane Node Management Information Container" O UserPlaneNodeManagementInformationContainer [N4],
        nw_tt_port_number: "NW-TT Port Number" C NwTtPortNumber [N4],
    }
}

pfcp_table! {
    /// Session Report IE within PFCP Session Report Request (Table 7.5.8.6-1).
    group SessionReport = 214, "Session Report", "7.5.8.6-1" {
        srr_id: "SRR ID" M SrrId [N4],
        access_availability_report: "Access Availability Report" C AccessAvailabilityReport [N4],
        qos_monitoring_report: "QoS Monitoring Report" C* QoSMonitoringReport [N4],
        traffic_parameter_measurement_report: "Traffic Parameter Measurement Report" C* TrafficParameterMeasurementReport [N4],
    }
}

pfcp_table! {
    /// Access Availability Report IE (Table 7.5.8.6-2).
    group AccessAvailabilityReport = 218, "Access Availability Report", "7.5.8.6-2" {
        access_availability_information: "Access Availability Information" M*2 AccessAvailabilityInformation [N4],
    }
}

pfcp_table! {
    /// QoS Monitoring Report IE (Table 7.5.8.6-3).
    group QoSMonitoringReport = 247, "QoS Monitoring Report", "7.5.8.6-3" {
        qfi: "QFI" M Qfi [N4],
        qos_monitoring_measurement: "QoS Monitoring Measurement" M QoSMonitoringMeasurement [N4],
        redundant_n3_n9_transmission_information: "Redundant N3/N9 Transmission Information" C RedundantN3n9TransmissionInformation [N4],
        time_stamp: "Time Stamp" M TimeStamp [N4],
        start_time: "Start Time" O StartTime [N4],
    }
}

pfcp_table! {
    /// Traffic Parameter Measurement Report IE (Table 7.5.8.6-4).
    group TrafficParameterMeasurementReport = 324, "Traffic Parameter Measurement Report", "7.5.8.6-4" {
        qfi: "QFI" M Qfi [N4],
        n6_jitter_measurement: "N6 Jitter Measurement" C N6JitterMeasurement [N4],
        ul_periodicity: "UL Periodicity" C UlPeriodicity [N4],
        time_stamp: "Time Stamp" M TimeStamp [N4],
        start_time: "Start Time" O StartTime [N4],
    }
}

pfcp_table! {
    /// Redundant N3/N9 Transmission Information IE (Table 7.5.8.6-5).
    group RedundantN3n9TransmissionInformation = 399, "Redundant N3/N9 Transmission Information", "7.5.8.6-5" {
        local_n3_n9_tunnel_information: "Local N3/N9 Tunnel Information" M LocalN3n9TunnelInformation [N4],
        remote_n3_n9_tunnel_information: "Remote N3/N9 Tunnel Information" M RemoteN3n9TunnelInformation [N4],
    }
}

pfcp_table! {
    /// Local N3/N9 Tunnel Information IE (Table 7.5.8.6-6).
    group LocalN3n9TunnelInformation = 400, "Local N3/N9 Tunnel Information", "7.5.8.6-6" {
        f_teid: "F-TEID" M FTeid [N4],
        network_instance: "Network Instance" O NetworkInstance [N4],
    }
}

pfcp_table! {
    /// Remote N3/N9 Tunnel Information IE (Table 7.5.8.6-7).
    group RemoteN3n9TunnelInformation = 401, "Remote N3/N9 Tunnel Information", "7.5.8.6-7" {
        f_teid: "F-TEID" M FTeid [N4],
        network_instance: "Network Instance" O NetworkInstance [N4],
    }
}

pfcp_table! {
    /// Update BAR IE in PFCP Session Report Response (Table 7.5.9.2-1).
    group UpdateBarReport = 12, "Update BAR", "7.5.9.2-1" {
        bar_id: "BAR ID" M BarId [SXA N4],
        downlink_data_notification_delay: "Downlink Data Notification Delay" C DownlinkDataNotificationDelay [SXA],
        dl_buffering_duration: "DL Buffering Duration" C DlBufferingDuration [SXA N4],
        dl_buffering_suggested_packet_count: "DL Buffering Suggested Packet Count" O DlBufferingSuggestedPacketCount [SXA N4],
        suggested_buffering_packets_count: "Suggested Buffering Packets Count" C SuggestedBufferingPacketsCount [SXB SXC N4],
        extended_dl_buffering_notification_policy: "Extended DL Buffering Notification Policy" C ExtendedDlBufferingNotificationPolicy [N4],
    }
}

