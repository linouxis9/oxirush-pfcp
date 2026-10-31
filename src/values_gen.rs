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

//! The values of the layouts of clause 8.2 that are numbers, octets of bits, or octets:
//! written from the figures by a script, then reviewed.

use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;
use crate::check::Check;
use crate::enums::*;
use crate::ie::{Codec, listed_value};
use crate::macros::{pfcp_bits, pfcp_layout};
use crate::octets::Octets;
use crate::values::*;
use crate::values_hand::{DigitsLv8, TextLv8};

pfcp_number! {
    /// Cause (§8.2.1).
    Cause(CauseValue) "Cause value" "8.2.1";
    /// Offending IE (§8.2.22).
    OffendingIe(u16) "Type of the offending IE" "8.2.22";
    /// Downlink Data Notification Delay (§8.2.28).
    DownlinkDataNotificationDelay(u8) "Delay Value in integer multiples of 50 millisecs, or zero" "8.2.28";
    /// Sequence Number (§8.2.33).
    SequenceNumber(u32) "Sequence Number" "8.2.33";
    /// Metric (§8.2.34): a percentage, the Load Metric or the Overload Reduction Metric.
    Metric(Percent) "Metric" "8.2.34";
    /// Duration Measurement (§8.2.45).
    DurationMeasurement(u32) "Duration value" "8.2.45";
    /// Time of First Packet (§8.2.46).
    TimeOfFirstPacket(u32) "Time of First Packet" "8.2.46";
    /// Time of Last Packet (§8.2.47).
    TimeOfLastPacket(u32) "Time of Last Packet" "8.2.47";
    /// Start Time (§8.2.52).
    StartTime(u32) "Start Time" "8.2.52";
    /// End Time (§8.2.53).
    EndTime(u32) "End Time" "8.2.53";
    /// Recovery Time Stamp (§8.2.65).
    RecoveryTimeStamp(u32) "Recovery Time Stamp value" "8.2.65";
    /// UR-SEQN (§8.2.71).
    UrSeqn(u32) "UR-SEQN" "8.2.71";
    /// User Plane Inactivity Timer (§8.2.83).
    UserPlaneInactivityTimer(u32) "User Plane Inactivity Timer" "8.2.83";
    /// Aggregated URR ID (§8.2.85).
    AggregatedUrrId(u32) "URR ID value" "8.2.85";
    /// Subsequent Time Quota (§8.2.87).
    SubsequentTimeQuota(u32) "Time Quota value" "8.2.87";
    /// Query URR Reference (§8.2.90).
    QueryUrrReference(u32) "Query URR Reference value" "8.2.90";
    /// Traffic Endpoint ID (§8.2.92).
    TrafficEndpointId(u8) "Traffic Endpoint ID value" "8.2.92";
    /// Ethertype (§8.2.96).
    Ethertype(u16) "Ethertype" "8.2.96";
    /// Ethernet Filter ID (§8.2.98).
    EthernetFilterId(u32) "Ethernet Filter ID value" "8.2.98";
    /// Suggested Buffering Packets Count (§8.2.100).
    SuggestedBufferingPacketsCount(u8) "Packet Count value" "8.2.100";
    /// Ethernet Inactivity Timer (§8.2.105).
    EthernetInactivityTimer(u32) "Ethernet Inactivity Timer" "8.2.105";
    /// Event Quota (§8.2.112).
    EventQuota(u32) "Event Quota" "8.2.112";
    /// Event Threshold (§8.2.113).
    EventThreshold(u32) "Event Threshold" "8.2.113";
    /// Subsequent Event Quota (§8.2.106).
    SubsequentEventQuota(u32) "Subsequent Event Quota" "8.2.106";
    /// Subsequent Event Threshold (§8.2.107).
    SubsequentEventThreshold(u32) "Subsequent Event Threshold" "8.2.107";
    /// Framed-Routing (§8.2.110).
    FramedRouting(u32) "Framed-Routing" "8.2.110";
    /// Time Stamp (§8.2.114).
    TimeStamp(u32) "Time Stamp" "8.2.114";
    /// Activation Time (§8.2.121).
    ActivationTime(u32) "Activation Time" "8.2.121";
    /// Deactivation Time (§8.2.122).
    DeactivationTime(u32) "Deactivation Time" "8.2.122";
    /// MAR ID (§8.2.123).
    MarId(u16) "MAR ID value" "8.2.123";
    /// Weight (§8.2.126).
    Weight(Percent) "Weight Value" "8.2.126";
    /// Quota Validity Time (§8.2.132).
    QuotaValidityTime(u32) "Validity Time value" "8.2.132";
    /// Number of Reports (§8.2.133).
    NumberOfReports(u16) "Number of Reports" "8.2.133";
    /// Port Number (§8.2.141).
    PortNumber(u32) "Port Number value" "8.2.141";
    /// NW-TT Port Number (§8.2.142).
    NwTtPortNumber(u32) "Port Number value" "8.2.142";
    /// Time Domain Number (§8.2.146).
    TimeDomainNumber(u8) "Time Domain Number value" "8.2.146";
    /// Time Offset Threshold (§8.2.147).
    TimeOffsetThreshold(i64) "Time Offset Threshold" "8.2.147";
    /// Cumulative rateRatio Threshold (§8.2.148).
    CumulativeRateRatioThreshold(i32) "Cumulative rateRatio Threshold" "8.2.148";
    /// Time Offset Measurement (§8.2.149).
    TimeOffsetMeasurement(i64) "Time Offset Measurement" "8.2.149";
    /// Cumulative rateRatio Measurement (§8.2.150).
    CumulativeRateRatioMeasurement(i32) "Cumulative rateRatio Measurement" "8.2.150";
    /// SRR ID (§8.2.151).
    SrrId(u8) "SRR ID value" "8.2.151";
    /// Average Packet Delay (§8.2.162).
    AveragePacketDelay(u32) "Delay Value in milliseconds" "8.2.162";
    /// Minimum Packet Delay (§8.2.163).
    MinimumPacketDelay(u32) "Delay Value in milliseconds" "8.2.163";
    /// Maximum Packet Delay (§8.2.164).
    MaximumPacketDelay(u32) "Delay Value in milliseconds" "8.2.164";
    /// Minimum Wait Time (§8.2.170).
    MinimumWaitTime(u32) "Minimum Wait Time" "8.2.170";
    /// DL Data Packets Size (§8.2.173).
    DlDataPacketsSize(u16) "DL Data Packets Size" "8.2.173";
    /// NF Instance ID (§8.2.175).
    NfInstanceId(OctetArray16) "NF Instance ID" "8.2.175";
    /// Validity Timer (§8.2.184).
    ValidityTimer(u16) "Validity Timer" "8.2.184";
    /// Tunnel Preference (§8.2.189).
    TunnelPreference(U24) "Tunnel Preference value" "8.2.189";
    /// DNS Server Address (§8.2.193).
    DnsServerAddress(u32) "DNS Server Address value" "8.2.193";
    /// NBNS Server Address (§8.2.194).
    NbnsServerAddress(u32) "NBNS Server Address value" "8.2.194";
    /// Maximum Receive Unit (§8.2.195).
    MaximumReceiveUnit(u16) "Maximum Receive Unit value" "8.2.195";
    /// MBS Unicast Parameters ID (§8.2.210).
    MbsUnicastParametersId(u16) "MBS Unicast Parameters ID value" "8.2.210";
    /// Area Session ID (§8.2.213).
    AreaSessionId(u16) "Area Session ID value" "8.2.213";
    /// RTP Header Extension Type (§8.2.234).
    RtpHeaderExtensionType(RtpHeaderExtensionTypeValue) "RTP Header Extension Type" "8.2.234";
    /// RTP Header Extension ID (§8.2.235).
    RtpHeaderExtensionId(u8) "RTP Header Extension ID" "8.2.235";
    /// RTP Payload Type (§8.2.236).
    RtpPayloadType(u8) "Payload Type" "8.2.236";
    /// RTP Payload Format (§8.2.237).
    RtpPayloadFormat(PayloadFormat) "Payload Format" "8.2.237";
    /// Reporting Endpoint ID (§8.2.253).
    ReportingEndpointId(u8) "Reporting Endpoint ID" "8.2.253";
    /// Header Handling Control ID (§8.2.259).
    HeaderHandlingControlId(u8) "Header Handling Control ID" "8.2.259";
    /// Header Handling Control Rule ID (§8.2.260).
    HeaderHandlingControlRuleId(u8) "Header Handling Control Rule ID" "8.2.260";
    /// N6 Delay Measurement Failure Information (§8.2.263).
    N6DelayMeasurementFailureInformation(FailureCause) "Failure cause" "8.2.263";
    /// N6 Delay Measurement Control Information ID (§8.2.264).
    N6DelayMeasurementControlInformationId(u16) "N6 Delay Measurement Control Information ID" "8.2.264";
    /// Measurement Endpoint Port Number (§8.2.265).
    MeasurementEndpointPortNumber(u16) "Port Number value" "8.2.265";
    /// Security Mode (OWAMP or TWAMP) (§8.2.275).
    SecurityModeValue(u32) "Mode" "8.2.275";
}

pfcp_fields! {
    /// Multiplier (§8.2.84): the Value-Digits (Integer64) and the Exponent (Integer32) of the
    /// Unit-Value AVP of TS 32.299.
    pub struct Multiplier "8.2.84" { value_digits "Value-Digits": i64, exponent "Exponent": i32 }
    /// S-NSSAI (§8.2.176).
    pub struct SNssai "8.2.176" { sst "SST": u8, sd "SD": U24 }
    /// DL Periodicity (§8.2.221).
    pub struct DlPeriodicity "8.2.221" { spare_field "Spare": Spare, dl_periodicity "DL Periodicity": u32 }
    /// UL Periodicity (§8.2.224).
    pub struct UlPeriodicity "8.2.224" { spare_field "Spare": Spare, ul_periodicity "UL Periodicity": u32 }
    /// HPLMN S-NSSAI (§8.2.232).
    pub struct HplmnSNssai "8.2.232" { sst "SST": u8, sd "SD": U24 }
}

pfcp_bits! {
    /// Report Type (§8.2.21).
    pub struct ReportType "8.2.21" octets 1 min 1 {
        uisr "UISR": 0 7 1, sesr "SESR": 0 6 1, tmir "TMIR": 0 5 1, upir "UPIR": 0 4 1, erir "ERIR": 0 3 1, usar "USAR": 0 2 1, dldr "DLDR": 0 1 1,
    }
}

pfcp_bits! {
    /// DL Buffering Duration (§8.2.29).
    pub struct DlBufferingDuration "8.2.29" octets 1 min 1 {
        timer_unit "Timer unit": 0 6 3 as TimerUnit, timer_value "Timer value": 0 1 5,
    }
}

pfcp_bits! {
    /// PFCPSMReq-Flags (§8.2.31).
    pub struct PFCPSMReqFlags "8.2.31" octets 1 min 1 {
        hrsbom "HRSBOM": 0 7 1, deteid "DETEID": 0 6 1, rumuc "RUMUC": 0 5 1, sumpc "SUMPC": 0 4 1, qaurr "QAURR": 0 3 1, sndem "SNDEM": 0 2 1, drobu "DROBU": 0 1 1,
    }
}

pfcp_bits! {
    /// PFCPSRRsp-Flags (§8.2.32).
    pub struct PFCPSRRspFlags "8.2.32" octets 1 min 1 {
        drobu "DROBU": 0 1 1,
    }
}

pfcp_bits! {
    /// Timer (§8.2.35).
    pub struct Timer "8.2.35" octets 1 min 1 {
        timer_unit "Timer unit": 0 6 3 as TimerUnit, timer_value "Timer value": 0 1 5,
    }
}

pfcp_bits! {
    /// Usage Report Trigger (§8.2.41).
    pub struct UsageReportTrigger "8.2.41" octets 3 min 2 {
        immer "IMMER": 0 8 1, droth "DROTH": 0 7 1, stopt "STOPT": 0 6 1, start "START": 0 5 1, quhti "QUHTI": 0 4 1, timth "TIMTH": 0 3 1, volth "VOLTH": 0 2 1, perio "PERIO": 0 1 1, eveth "EVETH": 1 8 1, macar "MACAR": 1 7 1, envcl "ENVCL": 1 6 1, monit "MONIT": 1 5 1, termr "TERMR": 1 4 1, liusa "LIUSA": 1 3 1, timqu "TIMQU": 1 2 1, volqu "VOLQU": 1 1 1, upint "UPINT": 2 6 1, emrre "EMRRE": 2 5 1, quvti "QUVTI": 2 4 1, ipmjl "IPMJL": 2 3 1, tebur "TEBUR": 2 2 1, evequ "EVEQU": 2 1 1,
    }
}

pfcp_bits! {
    /// Usage Information (§8.2.59).
    pub struct UsageInformation "8.2.59" octets 1 min 1 {
        ube "UBE": 0 4 1, uae "UAE": 0 3 1, aft "AFT": 0 2 1, bef "BEF": 0 1 1,
    }
}

pfcp_bits! {
    /// Measurement Information (§8.2.68).
    pub struct MeasurementInformation "8.2.68" octets 1 min 1 {
        ciam "CIAM": 0 8 1, aspoc "ASPOC": 0 7 1, sspoc "SSPOC": 0 6 1, mnop "MNOP": 0 5 1, istm "ISTM": 0 4 1, radi "RADI": 0 3 1, inam "INAM": 0 2 1, mbqe "MBQE": 0 1 1,
    }
}

pfcp_bits! {
    /// Node Report Type (§8.2.69).
    pub struct NodeReportType "8.2.69" octets 1 min 1 {
        n6dr "N6DR": 0 7 1, vsr "VSR": 0 6 1, purr "PURR": 0 5 1, gpqr "GPQR": 0 4 1, ckdr "CKDR": 0 3 1, uprr "UPRR": 0 2 1, upfr "UPFR": 0 1 1,
    }
}

pfcp_bits! {
    /// OCI Flags (§8.2.76).
    pub struct OciFlags "8.2.76" octets 1 min 1 {
        aoci "AOCI": 0 1 1,
    }
}

pfcp_bits! {
    /// PFCP Association Release Request (§8.2.77).
    pub struct PfcpAssociationReleaseRequest "8.2.77" octets 1 min 1 {
        urss "URSS": 0 2 1, sarr "SARR": 0 1 1,
    }
}

pfcp_bits! {
    /// Graceful Release Period (§8.2.78).
    pub struct GracefulReleasePeriod "8.2.78" octets 1 min 1 {
        timer_unit "Timer unit": 0 6 3 as TimerUnit, timer_value "Timer value": 0 1 5,
    }
}

pfcp_bits! {
    /// PDN Type (§8.2.79).
    pub struct PdnType "8.2.79" octets 1 min 1 {
        pdn_type "PDN Type": 0 1 3 as PdnTypeValue,
    }
}

pfcp_bits! {
    /// Proxying (§8.2.97).
    pub struct Proxying "8.2.97" octets 1 min 1 {
        ins "INS": 0 2 1, arp "ARP": 0 1 1,
    }
}

pfcp_bits! {
    /// Ethernet Filter Properties (§8.2.99).
    pub struct EthernetFilterProperties "8.2.99" octets 1 min 1 {
        bide "BIDE": 0 1 1,
    }
}

pfcp_bits! {
    /// Ethernet PDU Session Information (§8.2.102).
    pub struct EthernetPduSessionInformation "8.2.102" octets 1 min 1 {
        ethi "ETHI": 0 1 1,
    }
}

pfcp_bits! {
    /// PFCPSRReq-Flags (§8.2.119).
    pub struct PFCPSRReqFlags "8.2.119" octets 1 min 1 {
        pppcp "PPPCP": 0 2 1, psdbu "PSDBU": 0 1 1,
    }
}

pfcp_bits! {
    /// PFCPAUReq-Flags (§8.2.120).
    pub struct PFCPAUReqFlags "8.2.120" octets 1 min 1 {
        parps "PARPS": 0 1 1,
    }
}

pfcp_bits! {
    /// Steering Functionality (§8.2.124).
    pub struct SteeringFunctionality "8.2.124" octets 1 min 1 {
        steering_functionality_value "Steering Functionality Value": 0 1 4 as SteeringFunctionalityValue,
    }
}

pfcp_bits! {
    /// Steering Mode (§8.2.125).
    pub struct SteeringMode "8.2.125" octets 1 min 1 {
        steering_mode_value "Steering Mode Value": 0 1 4 as SteeringModeValue,
    }
}

pfcp_bits! {
    /// Priority (§8.2.127).
    pub struct Priority "8.2.127" octets 1 min 1 {
        priority_value "Priority Value": 0 1 4 as PriorityValue,
    }
}

pfcp_bits! {
    /// Packet Replication and Detection Carry-On Information (§8.2.130).
    pub struct PacketReplicationAndDetectionCarryOnInformation "8.2.130" octets 1 min 1 {
        dcaroni "DCARONI": 0 4 1, prin6i "PRIN6I": 0 3 1, prin19i "PRIN19I": 0 2 1, priueai "PRIUEAI": 0 1 1,
    }
}

pfcp_bits! {
    /// PFCPASRsp-Flags (§8.2.134).
    pub struct PFCPASRspFlags "8.2.134" octets 1 min 1 {
        uupsi "UUPSI": 0 2 1, psrei "PSREI": 0 1 1,
    }
}

pfcp_bits! {
    /// PFCPSEReq-Flags (§8.2.136).
    pub struct PFCPSEReqFlags "8.2.136" octets 1 min 1 {
        epri "EPRI": 0 4 1, hrsbom "HRSBOM": 0 3 1, sumpc "SUMPC": 0 2 1, resti "RESTI": 0 1 1,
    }
}

pfcp_bits! {
    /// Create Bridge/Router Info (§8.2.140).
    pub struct CreateBridgeRouterInfo "8.2.140" octets 1 min 1 {
        rii "RII": 0 2 1, bii "BII": 0 1 1,
    }
}

pfcp_bits! {
    /// Requested Clock Drift Information (§8.2.145).
    pub struct RequestedClockDriftInformation "8.2.145" octets 1 min 1 {
        rrcr "RRCR": 0 2 1, rrto "RRTO": 0 1 1,
    }
}

pfcp_bits! {
    /// Requested Access Availability Information (§8.2.152).
    pub struct RequestedAccessAvailabilityInformation "8.2.152" octets 1 min 1 {
        rrca "RRCA": 0 1 1,
    }
}

pfcp_bits! {
    /// Access Availability Information (§8.2.153).
    pub struct AccessAvailabilityInformation "8.2.153" octets 1 min 1 {
        availability_status "Availability Status": 0 3 2 as AvailabilityStatus, access_type "Access Type": 0 1 2 as AccessType,
    }
}

pfcp_bits! {
    /// MPTCP Control Information (§8.2.154).
    pub struct MptcpControlInformation "8.2.154" octets 1 min 1 {
        tci "TCI": 0 1 1,
    }
}

pfcp_bits! {
    /// ATSSS-LL Control Information (§8.2.155).
    pub struct AtsssLlControlInformation "8.2.155" octets 1 min 1 {
        lli "LLI": 0 1 1,
    }
}

pfcp_bits! {
    /// ATSSS-LL Information (§8.2.160).
    pub struct AtsssLlInformation "8.2.160" octets 1 min 1 {
        lli "LLI": 0 1 1,
    }
}

pfcp_bits! {
    /// QoS Report Trigger (§8.2.165).
    pub struct QoSReportTrigger "8.2.165" octets 1 min 1 {
        ire "IRE": 0 3 1, thr "THR": 0 2 1, per "PER": 0 1 1,
    }
}

pfcp_bits! {
    /// GTP-U Path Interface Type (§8.2.166).
    pub struct GtpUPathInterfaceType "8.2.166" octets 1 min 1 {
        n3 "N3": 0 2 1, n9 "N9": 0 1 1,
    }
}

pfcp_bits! {
    /// Requested QoS Monitoring (§8.2.167).
    pub struct RequestedQoSMonitoring "8.2.167" octets 2 min 1 {
        uldr "ULDR": 0 8 1, dldr "DLDR": 0 7 1, ulci "ULCI": 0 6 1, dlci "DLCI": 0 5 1, gtpupm "GTPUPM": 0 4 1, rppd "RPPD": 0 3 1, ulpd "ULPD": 0 2 1, dlpd "DLPD": 0 1 1, ulab "ULAB": 1 2 1, dlab "DLAB": 1 1 1,
    }
}

pfcp_bits! {
    /// Reporting Frequency (§8.2.168).
    pub struct ReportingFrequency "8.2.168" octets 1 min 1 {
        reserved "Reserved": 0 3 1, perio "PERIO": 0 2 1, evett "EVETT": 0 1 1,
    }
}

pfcp_bits! {
    /// MT-EDT Control Information (§8.2.172).
    pub struct MtEdtControlInformation "8.2.172" octets 1 min 1 {
        rdsi "RDSI": 0 1 1,
    }
}

pfcp_bits! {
    /// QER Control Indications (§8.2.174).
    pub struct QerControlIndications "8.2.174" octets 1 min 1 {
        rcsr "RCSR": 0 1 1,
    }
}

pfcp_bits! {
    /// IP version (§8.2.177).
    pub struct IpVersion "8.2.177" octets 1 min 1 {
        v6 "V6": 0 2 1, v4 "V4": 0 1 1,
    }
}

pfcp_bits! {
    /// PFCPASReq-Flags (§8.2.178).
    pub struct PFCPASReqFlags "8.2.178" octets 1 min 1 {
        uupsi "UUPSI": 0 1 1,
    }
}

pfcp_bits! {
    /// Data Status (§8.2.179).
    pub struct DataStatus "8.2.179" octets 1 min 1 {
        buff "BUFF": 0 2 1, drop "DROP": 0 1 1,
    }
}

pfcp_bits! {
    /// RDS configuration information (§8.2.180).
    pub struct RdsConfigurationInformation "8.2.180" octets 1 min 1 {
        rds "RDS": 0 1 1,
    }
}

pfcp_bits! {
    /// Multipath Applicable Indication (§8.2.181).
    pub struct MultipathApplicableIndication "8.2.181" octets 1 min 1 {
        mqai "MQAI": 0 2 1, mtai "MTAI": 0 1 1,
    }
}

pfcp_bits! {
    /// L2TP Session Indications (§8.2.192).
    pub struct L2tpSessionIndications "8.2.192" octets 1 min 1 {
        rensa "RENSA": 0 3 1, redsa "REDSA": 0 2 1, reuia "REUIA": 0 1 1,
    }
}

pfcp_bits! {
    /// Steering Mode Indicator (§8.2.197).
    pub struct SteeringModeIndicator "8.2.197" octets 1 min 1 {
        ueai "UEAI": 0 2 1, albi "ALBI": 0 1 1,
    }
}

pfcp_bits! {
    /// Reporting Flags (§8.2.204).
    pub struct ReportingFlags "8.2.204" octets 1 min 1 {
        dupl "DUPL": 0 1 1,
    }
}

pfcp_bits! {
    /// MBSN4mbReq-Flags (§8.2.208).
    pub struct MBSN4mbReqFlags "8.2.208" octets 1 min 1 {
        mbs_resti "MBS RESTI": 0 3 1, jmbssm "JMBSSM": 0 2 1, pllssm "PLLSSM": 0 1 1,
    }
}

pfcp_bits! {
    /// MBSN4Resp-Flags (§8.2.211).
    pub struct MBSN4RespFlags "8.2.211" octets 1 min 1 {
        n19dtr "N19DTR": 0 3 1, jmti "JMTI": 0 2 1, nn19dt "NN19DT": 0 1 1,
    }
}

pfcp_bits! {
    /// PFCPSDRsp-Flags (§8.2.215).
    pub struct PFCPSDRspFlags "8.2.215" octets 1 min 1 {
        puru "PURU": 0 1 1,
    }
}

pfcp_bits! {
    /// QER Indications (§8.2.216).
    pub struct QerIndications "8.2.216" octets 1 min 1 {
        tnbmi "TNBMI": 0 6 1, dbsmi "DBSMI": 0 5 1, pdusm "PDUSM": 0 4 1, eml4s "EML4S": 0 3 1, edbmi "EDBMI": 0 2 1, iqfisn "IQFISN": 0 1 1,
    }
}

pfcp_bits! {
    /// Configured Time Domain (§8.2.218).
    pub struct ConfiguredTimeDomain "8.2.218" octets 1 min 1 {
        ctdi "CTDI": 0 1 1,
    }
}

pfcp_bits! {
    /// Traffic Parameter Measurement Indication (§8.2.223).
    pub struct TrafficParameterMeasurementIndication "8.2.223" octets 1 min 1 {
        n6jmi "N6JMI": 0 3 1, dlpmi "DLPMI": 0 2 1, ulpmi "ULPMI": 0 1 1,
    }
}

pfcp_bits! {
    /// MPQUIC Control Information (§8.2.225).
    pub struct MpquicControlInformation "8.2.225" octets 1 min 1 {
        ceth "CETH": 0 3 1, cip "CIP": 0 2 1, cudp "CUDP": 0 1 1,
    }
}

pfcp_bits! {
    /// Transport Mode (§8.2.227).
    pub struct TransportMode "8.2.227" octets 1 min 1 {
        transport_mode_value "Transport Mode Value": 0 1 4 as TransportModeValue,
    }
}

pfcp_bits! {
    /// Measurement Indication (§8.2.231).
    pub struct MeasurementIndication "8.2.231" octets 1 min 1 {
        dqfi "DQFI": 0 1 1,
    }
}

pfcp_bits! {
    /// Media Transport Protocol (§8.2.233).
    pub struct MediaTransportProtocol "8.2.233" octets 1 min 1 {
        media_transport_protocol "Media Transport Protocol": 0 1 4 as MediaTransportProtocolValue,
    }
}

pfcp_bits! {
    /// Extended DL Buffering Notification Policy (§8.2.238).
    pub struct ExtendedDlBufferingNotificationPolicy "8.2.238" octets 1 min 1 {
        edbn "EDBN": 0 1 1,
    }
}

pfcp_bits! {
    /// MT-SDT Control Information (§8.2.239).
    pub struct MtSdtControlInformation "8.2.239" octets 1 min 1 {
        rdsi "RDSI": 0 1 1,
    }
}

pfcp_bits! {
    /// RTP Header Extension Additional Information (§8.2.241).
    pub struct RtpHeaderExtensionAdditionalInformation "8.2.241" octets 2 min 2 {
        npdsi "NPDSI": 0 3 1, pssai "PSSAI": 0 2 1, fi "FI": 0 1 1, npds "NPDS": 1 4 1, pssa "PSSA": 1 3 1, format "Format": 1 1 2 as FormatField,
    }
}

pfcp_bits! {
    /// N6 Delay Measurement Protocols (§8.2.246).
    pub struct N6DelayMeasurementProtocols "8.2.246" octets 1 min 1 {
        other "OTHER": 0 4 1, stamp "STAMP": 0 3 1, owamp "OWAMP": 0 2 1, twamp "TWAMP": 0 1 1,
    }
}

pfcp_bits! {
    /// Packet Inspection functionality (§8.2.250).
    pub struct PacketInspectionFunctionality "8.2.250" octets 1 min 1 {
        dpid "DPID": 0 3 1, macd "MACD": 0 2 1, ipbd "IPBD": 0 1 1,
    }
}

pfcp_bits! {
    /// Header Handling Action (§8.2.255).
    pub struct HeaderHandlingAction "8.2.255" octets 1 min 1 {
        action_value "Action value": 0 1 4 as ActionValue,
    }
}

pfcp_bits! {
    /// Header Handling Condition (§8.2.258).
    pub struct HeaderHandlingCondition "8.2.258" octets 1 min 1 {
        condition_value "Condition value": 0 1 4 as ConditionValue,
    }
}

pfcp_bits! {
    /// Measurement Reporting Type (§8.2.262).
    pub struct MeasurementReportingType "8.2.262" octets 1 min 1 {
        ire "IRE": 0 3 1, evt "EVT": 0 2 1, per "PER": 0 1 1,
    }
}

pfcp_bits! {
    /// Header Handling Reporting Indication (§8.2.266).
    pub struct HeaderHandlingReportingIndication "8.2.266" octets 1 min 1 {
        otri "OTRI": 0 1 1,
    }
}

pfcp_bits! {
    /// SMF Change Reason (§8.2.267).
    pub struct SmfChangeReason "8.2.267" octets 1 min 1 {
        mpsai "MPSAI": 0 3 1, mpssf "MPSSF": 0 2 1, mpsnr "MPSNR": 0 1 1,
    }
}

pfcp_bits! {
    /// PDU Set Importance (§8.2.268).
    pub struct PduSetImportance "8.2.268" octets 2 min 2 {
        psi7 "PSI7": 0 8 1, psi6 "PSI6": 0 7 1, psi5 "PSI5": 0 6 1, psi4 "PSI4": 0 5 1, psi3 "PSI3": 0 4 1, psi2 "PSI2": 0 3 1, psi1 "PSI1": 0 2 1, psi0 "PSI0": 0 1 1, psi15 "PSI15": 1 8 1, psi14 "PSI14": 1 7 1, psi13 "PSI13": 1 6 1, psi12 "PSI12": 1 5 1, psi11 "PSI11": 1 4 1, psi10 "PSI10": 1 3 1, psi9 "PSI9": 1 2 1, psi8 "PSI8": 1 1 1,
    }
}

pfcp_bits! {
    /// MoQ Control Information (§8.2.269).
    pub struct MoQControlInformation "8.2.269" octets 1 min 1 {
        mqrai "MQRAI": 0 2 1, mqrei "MQREI": 0 1 1,
    }
}

pfcp_bits! {
    /// Media Related Information Transfer Info (§8.2.271).
    pub struct MediaRelatedInformationTransferInfo "8.2.271" octets 1 min 1 {
        transferring_method "Transferring method": 0 1 4 as TransferringMethod,
    }
}

pfcp_bits! {
    /// Reporting Control Information (§8.2.272).
    pub struct ReportingControlInformation "8.2.272" octets 1 min 1 {
        uelm "UELM": 0 1 1,
    }
}

pfcp_bits! {
    /// Security Mode (STAMP) (§8.2.273).
    pub struct SecurityMode "8.2.273" octets 1 min 1 {
        conp "CONP": 0 2 1, intp "INTP": 0 1 1,
    }
}

pfcp_bits! {
    /// Remaining Data Reporting Indication (§8.2.277).
    pub struct RemainingDataReportingIndication "8.2.277" octets 1 min 1 {
        remaining_data_reporting_indication_value "Remaining Data Reporting Indication value": 0 1 4 as RemainingDataReportingIndicationValue,
    }
}

pfcp_bits! {
    /// Expedited Transfer Indication (§8.2.278).
    pub struct ExpeditedTransferIndication "8.2.278" octets 1 min 1 {
        false_field "FALSE": 0 2 1, true_field "TRUE": 0 1 1,
    }
}

pfcp_bits! {
    /// Session Reflector Mode (STAMP) (§8.2.279).
    pub struct SessionReflectorMode "8.2.279" octets 1 min 1 {
        srm "SRM": 0 1 1,
    }
}

pfcp_bits! {
    /// Transport Level Marking Indications (§8.2.280).
    pub struct TransportLevelMarkingIndications "8.2.280" octets 1 min 1 {
        tlmip "TLMIP": 0 1 1,
    }
}

pfcp_bits! {
    /// PDU Set Importance for N6-unmarked PDUs (§8.2.282).
    pub struct PduSetImportanceForN6UnmarkedPDUs "8.2.282" octets 1 min 1 {
        psi_value "PSI value": 0 1 4,
    }
}

pfcp_octets! {
    /// Application ID (§8.2.6).
    ApplicationId "Application Identifier" "8.2.6";
    /// DL Buffering Suggested Packet Count (§8.2.30).
    DlBufferingSuggestedPacketCount "Packet Count Value" "8.2.30";
    /// Application Instance ID (§8.2.60).
    ApplicationInstanceId "Application Instance Identifier" "8.2.60";
    /// Activate Predefined Rules (§8.2.72).
    ActivatePredefinedRules "Predefined Rules Name" "8.2.72";
    /// Deactivate Predefined Rules (§8.2.73).
    DeactivatePredefinedRules "Predefined Rules Name" "8.2.73";
    /// Framed-Route (§8.2.109).
    FramedRoute "Framed-Route" "8.2.109";
    /// Framed-IPv6-Route (§8.2.111).
    FramedIPv6Route "Framed-IPv6-Route" "8.2.111";
    /// APN/DNN (§8.2.117).
    ApnDnn "APN/DNN" "8.2.117";
    /// Port Management Information Container (§8.2.144).
    PortManagementInformationContainer "Port Management Information" "8.2.144";
    /// Data Network Access Identifier (§8.2.161).
    DataNetworkAccessIdentifier "Data Network Access Identifier" "8.2.161";
    /// User Plane Node Management Information Container (§8.2.182).
    UserPlaneNodeManagementInformationContainer "User Plane Node Management Information" "8.2.182";
    /// Calling Number (§8.2.190).
    CallingNumber "Calling Number value" "8.2.190";
    /// Called Number (§8.2.191).
    CalledNumber "Called Number value" "8.2.191";
    /// Group ID (§8.2.198).
    GroupId "Group ID" "8.2.198";
    /// Event Notification URI (§8.2.202).
    EventNotificationUri "Event Notification URI" "8.2.202";
    /// Notification Correlation ID (§8.2.203).
    NotificationCorrelationId "Notification Correlation ID" "8.2.203";
    /// Predefined Rules Name (§8.2.205).
    PredefinedRulesName "Predefined Rules Name" "8.2.205";
    /// Metadata (§8.2.219).
    Metadata "Metadata" "8.2.219";
    /// TL-Container (§8.2.230).
    TlContainer "TL-Container Information" "8.2.230";
    /// URI (§8.2.244).
    Uri "URI" "8.2.244";
    /// Operator Configurable UPF Capability (§8.2.249).
    OperatorConfigurableUpfCapability "Operator Configurable UPF Capability" "8.2.249";
    /// Header Detection Reference (§8.2.251).
    HeaderDetectionReference "Header Detection Reference" "8.2.251";
    /// Header Detection Support Information (§8.2.252).
    HeaderDetectionSupportInformation "Header Detection Support Information" "8.2.252";
    /// Header Handling Control Reference (§8.2.254).
    HeaderHandlingControlReference "Header Handling Control Reference" "8.2.254";
    /// Header Information (§8.2.256).
    HeaderInformation "Header Information" "8.2.256";
    /// Header Value (§8.2.257).
    HeaderValue "Header Value" "8.2.257";
}

listed_value!(
    Cause,
    ReportType,
    OffendingIe,
    DownlinkDataNotificationDelay,
    DlBufferingDuration,
    PFCPSMReqFlags,
    PFCPSRRspFlags,
    SequenceNumber,
    Metric,
    Timer,
    UsageReportTrigger,
    DurationMeasurement,
    TimeOfFirstPacket,
    TimeOfLastPacket,
    StartTime,
    EndTime,
    UsageInformation,
    RecoveryTimeStamp,
    MeasurementInformation,
    NodeReportType,
    UrSeqn,
    OciFlags,
    PfcpAssociationReleaseRequest,
    GracefulReleasePeriod,
    PdnType,
    UserPlaneInactivityTimer,
    Multiplier,
    AggregatedUrrId,
    SubsequentTimeQuota,
    QueryUrrReference,
    TrafficEndpointId,
    Ethertype,
    Proxying,
    EthernetFilterId,
    EthernetFilterProperties,
    SuggestedBufferingPacketsCount,
    EthernetPduSessionInformation,
    EthernetInactivityTimer,
    EventQuota,
    EventThreshold,
    SubsequentEventQuota,
    SubsequentEventThreshold,
    FramedRouting,
    TimeStamp,
    PFCPSRReqFlags,
    PFCPAUReqFlags,
    ActivationTime,
    DeactivationTime,
    MarId,
    SteeringFunctionality,
    SteeringMode,
    Weight,
    Priority,
    PacketReplicationAndDetectionCarryOnInformation,
    QuotaValidityTime,
    NumberOfReports,
    PFCPASRspFlags,
    PFCPSEReqFlags,
    CreateBridgeRouterInfo,
    PortNumber,
    NwTtPortNumber,
    RequestedClockDriftInformation,
    TimeDomainNumber,
    TimeOffsetThreshold,
    CumulativeRateRatioThreshold,
    TimeOffsetMeasurement,
    CumulativeRateRatioMeasurement,
    SrrId,
    RequestedAccessAvailabilityInformation,
    AccessAvailabilityInformation,
    MptcpControlInformation,
    AtsssLlControlInformation,
    AtsssLlInformation,
    AveragePacketDelay,
    MinimumPacketDelay,
    MaximumPacketDelay,
    QoSReportTrigger,
    GtpUPathInterfaceType,
    RequestedQoSMonitoring,
    ReportingFrequency,
    MinimumWaitTime,
    MtEdtControlInformation,
    DlDataPacketsSize,
    QerControlIndications,
    NfInstanceId,
    SNssai,
    IpVersion,
    PFCPASReqFlags,
    DataStatus,
    RdsConfigurationInformation,
    MultipathApplicableIndication,
    ValidityTimer,
    TunnelPreference,
    L2tpSessionIndications,
    DnsServerAddress,
    NbnsServerAddress,
    MaximumReceiveUnit,
    SteeringModeIndicator,
    ReportingFlags,
    MBSN4mbReqFlags,
    MbsUnicastParametersId,
    MBSN4RespFlags,
    AreaSessionId,
    PFCPSDRspFlags,
    QerIndications,
    ConfiguredTimeDomain,
    DlPeriodicity,
    TrafficParameterMeasurementIndication,
    UlPeriodicity,
    MpquicControlInformation,
    TransportMode,
    MeasurementIndication,
    HplmnSNssai,
    MediaTransportProtocol,
    RtpHeaderExtensionType,
    RtpHeaderExtensionId,
    RtpPayloadType,
    RtpPayloadFormat,
    ExtendedDlBufferingNotificationPolicy,
    MtSdtControlInformation,
    RtpHeaderExtensionAdditionalInformation,
    N6DelayMeasurementProtocols,
    PacketInspectionFunctionality,
    ReportingEndpointId,
    HeaderHandlingAction,
    HeaderHandlingCondition,
    HeaderHandlingControlId,
    HeaderHandlingControlRuleId,
    MeasurementReportingType,
    N6DelayMeasurementFailureInformation,
    N6DelayMeasurementControlInformationId,
    MeasurementEndpointPortNumber,
    HeaderHandlingReportingIndication,
    SmfChangeReason,
    PduSetImportance,
    MoQControlInformation,
    MediaRelatedInformationTransferInfo,
    ReportingControlInformation,
    SecurityMode,
    SecurityModeValue,
    RemainingDataReportingIndication,
    ExpeditedTransferIndication,
    SessionReflectorMode,
    TransportLevelMarkingIndications,
    PduSetImportanceForN6UnmarkedPDUs,
);

pfcp_layout! {
    /// Volume Measurement (§8.2.44).
    pub struct VolumeMeasurement "8.2.44" {
        flags(u8) { dlnop "DLNOP": 6, ulnop "ULNOP": 5, tonop "TONOP": 4, dlvol "DLVOL": 3, ulvol "ULVOL": 2, tovol "TOVOL": 1 }
        total_volume "Total Volume": u64 if tovol,
        uplink_volume "Uplink Volume": u64 if ulvol,
        downlink_volume "Downlink Volume": u64 if dlvol,
        total_number_of_packets "Total Number of Packets": u64 if tonop,
        uplink_number_of_packets "Uplink Number of Packets": u64 if ulnop,
        downlink_number_of_packets "Downlink Number of Packets": u64 if dlnop,
    }
}

pfcp_layout! {
    /// Dropped DL Traffic Threshold (§8.2.49).
    pub struct DroppedDlTrafficThreshold "8.2.49" {
        flags(u8) { dlby "DLBY": 2, dlpa "DLPA": 1 }
        downlink_packets "Downlink Packets": u64 if dlpa,
        number_of_bytes_of_downlink_data "Number of Bytes of Downlink Data": u64 if dlby,
    }
}

pfcp_layout! {
    /// DL Flow Level Marking (§8.2.66).
    pub struct DlFlowLevelMarking "8.2.66" {
        flags(u8) { sci "SCI": 2, ttc "TTC": 1 }
        tos_traffic_class "ToS/Traffic Class": u16 if ttc,
        service_class_indicator "Service Class Indicator": u16 if sci,
    }
}

pfcp_layout! {
    /// Remote GTP-U Peer (§8.2.70).
    pub struct RemoteGtpUPeer "8.2.70" {
        flags(u8) { rts "RTS": 5, ni "NI": 4, di "DI": 3, v4 "V4": 2, v6 "V6": 1 }
        ipv4_address "IPv4 address": Ipv4Addr if v4,
        ipv6_address "IPv6 address": Ipv6Addr if v6,
        destination_interface_field "Destination Interface field": Lv16 if di,
        network_instance_field "Network Instance field": Lv16 if ni,
        recovery_timestamp "Recovery Timestamp": u32 if rts,
    }
}

pfcp_layout! {
    /// Subsequent Volume Quota (§8.2.86).
    pub struct SubsequentVolumeQuota "8.2.86" {
        flags(u8) { dlvol "DLVOL": 3, ulvol "ULVOL": 2, tovol "TOVOL": 1 }
        total_volume "Total Volume": u64 if tovol,
        uplink_volume "Uplink Volume": u64 if ulvol,
        downlink_volume "Downlink Volume": u64 if dlvol,
    }
}

pfcp_layout! {
    /// User ID (§8.2.101): the IMSI, the IMEI and the MSISDN as their digits, the others as
    /// text.
    pub struct UserId "8.2.101" {
        flags(u8) { peif "PEIF": 7, gpsif "GPSIF": 6, supif "SUPIF": 5, naif "NAIF": 4, msisdnf "MSISDNF": 3, imeif "IMEIF": 2, imsif "IMSIF": 1 }
        imsi "IMSI": DigitsLv8 if imsif,
        imei "IMEI": DigitsLv8 if imeif,
        msisdn "MSISDN": DigitsLv8 if msisdnf,
        nai "NAI": TextLv8 if naif,
        supi "SUPI": TextLv8 if supif,
        gpsi "GPSI": TextLv8 if gpsif,
        pei "PEI": TextLv8 if peif,
    }
}

pfcp_layout! {
    /// Alternative SMF IP Address (§8.2.129).
    pub struct AlternativeSmfIpAddress "8.2.129" {
        flags(u8) { ppe "PPE": 3, v4 "V4": 2, v6 "V6": 1 }
        ipv4_address "IPv4 Address": Ipv4Addr if v4,
        ipv6_address "IPv6 Address": Ipv6Addr if v6,
    }
}

pfcp_layout! {
    /// IP Multicast Address (§8.2.137).
    pub struct IpMulticastAddress "8.2.137" {
        flags(u8) { a "A": 4, r "R": 3, v4 "V4": 2, v6 "V6": 1 }
        ipv4_address "(start) IPv4 address": Ipv4Addr if v4,
        ipv6_address "(start) IPv6 address": Ipv6Addr if v6,
        ipv4_address_2 "(end) IPv4 address": Ipv4Addr if v4,
        ipv6_address_2 "(end) IPv6 address": Ipv6Addr if v6,
    }
}

pfcp_layout! {
    /// 5GS User Plane Node ID (§8.2.143).
    pub struct FiveGsUserPlaneNodeId "8.2.143" {
        flags(u8) { bid "BID": 1 }
        user_plane_node_id_value "User Plane Node ID value": u64 if bid,
    }
}

pfcp_layout! {
    /// Packet Delay Thresholds (§8.2.169).
    pub struct PacketDelayThresholds "8.2.169" {
        flags(u8) { rp "RP": 3, ul "UL": 2, dl "DL": 1 }
        downlink_packet_delay_threshold "Downlink packet delay threshold": u32 if dl,
        uplink_packet_delay_threshold "Uplink packet delay threshold": u32 if ul,
        round_trip_packet_delay_threshold "Round trip packet delay threshold": u32 if rp,
    }
}

pfcp_layout! {
    /// QoS Monitoring Measurement (§8.2.171).
    pub struct QoSMonitoringMeasurement "8.2.171" {
        flags(u8) { uldr "ULDR": 8, dldr "DLDR": 7, ulci "ULCI": 6, dlci "DLCI": 5, plmf "PLMF": 4, rppd "RPPD": 3, ulpd "ULPD": 2, dlpd "DLPD": 1 }
        downlink_packet_delay "Downlink packet delay": u32 if dlpd,
        uplink_packet_delay "Uplink packet delay": u32 if ulpd,
        round_trip_packet_delay "Round trip packet delay": u32 if rppd,
        downlink_congestion_information "Downlink Congestion information": u16 if dlci,
        uplink_congestion_information "Uplink Congestion information": u16 if ulci,
        average_downlink_data_rate "Average downlink data rate": U40 if dldr,
        average_uplink_data_rate "Average uplink data rate": U40 if uldr,
    }
}

pfcp_layout! {
    /// Number of UE IP Addresses (§8.2.183).
    pub struct NumberOfUeIpAddresses "8.2.183" {
        flags(u8) { ipv6 "IPv6": 2, ipv4 "IPv4": 1 }
        number_of_ue_ipv4_addresses "Number of UE IPv4 Addresses": u32 if ipv4,
        number_of_ue_ipv6_addresses "Number of UE IPv6 Addresses": u32 if ipv6,
    }
}

pfcp_layout! {
    /// Thresholds (§8.2.196).
    pub struct Thresholds "8.2.196" {
        flags(u8) { plr "PLR": 2, rtt "RTT": 1 }
        rtt_value "RTT value": u16 if rtt,
        packet_loss_rate_value "Packet Loss Rate value": Percent if plr,
    }
}

pfcp_layout! {
    /// CP IP Address (§8.2.199).
    pub struct CpIpAddress "8.2.199" {
        flags(u8) { v4 "V4": 2, v6 "V6": 1 }
        ipv4_address "IPv4 Address": Ipv4Addr if v4,
        ipv6_address "IPv6 Address": Ipv6Addr if v6,
    }
}

pfcp_layout! {
    /// Mapped N6 IP Address (§8.2.242).
    pub struct MappedN6IpAddress "8.2.242" {
        flags(u8) { v4 "V4": 2, chv4 "CHV4": 1 }
        ipv4_address "IPv4 address": Ipv4Addr if v4 && !chv4,
    }
    check(address, path, found) {
        if address.v4 && address.chv4 {
            found.push(crate::check::Deviation::new(path, "8.2.242", crate::check::DeviationKind::Rule("V4 and CHV4 are both set")));
        }
    }
}

pfcp_layout! {
    /// N6 Routing Information (§8.2.243).
    pub struct N6RoutingInformation "8.2.243" {
        flags(u8) { dpo "DPO": 6, dipv6 "DIPV6": 5, dipv4 "DIPV4": 4, spo "SPO": 3, sipv6 "SIPV6": 2, sipv4 "SIPV4": 1 }
        source_ipv4_address "Source IPv4 address": Ipv4Addr if sipv4,
        source_ipv6_address "Source IPv6 address": Ipv6Addr if sipv6,
        source_port_number "Source Port Number": u16 if spo,
        destination_ipv4_address "Destination IPv4 address": Ipv4Addr if dipv4,
        destination_ipv6_address "Destination IPv6 address": Ipv6Addr if dipv6,
        destination_port_number "Destination Port Number": u16 if dpo,
    }
}

pfcp_layout! {
    /// N6 Delay Measurement Information (§8.2.247).
    pub struct N6DelayMeasurementInformation "8.2.247" {
        flags(u8) { maxd "MAXD": 2, mind "MIND": 1 }
        average_packet_delay "Average Packet Delay": u32 if true,
        minimum_packet_delay "Minimum Packet Delay": u32 if mind,
        maximum_packet_delay "Maximum Packet Delay": u32 if maxd,
    }
}

pfcp_layout! {
    /// Measurement Endpoint Address (§8.2.248).
    pub struct MeasurementEndpointAddress "8.2.248" {
        flags(u8) { v6 "V6": 2, v4 "V4": 1 }
        ipv4_address "IPv4 Address": Ipv4Addr if v4,
        ipv6_address "IPv6 Address": Ipv6Addr if v6,
    }
}

pfcp_layout! {
    /// MoQ Relay IP Address (§8.2.270).
    pub struct MoQRelayIpAddress "8.2.270" {
        flags(u8) { v4 "V4": 2, v6 "V6": 1 }
        ipv4_address "IPv4 Address": Ipv4Addr if v4,
        ipv6_address "IPv6 Address": Ipv6Addr if v6,
    }
}

listed_value!(
    VolumeMeasurement,
    DroppedDlTrafficThreshold,
    DlFlowLevelMarking,
    RemoteGtpUPeer,
    SubsequentVolumeQuota,
    UserId,
    AlternativeSmfIpAddress,
    IpMulticastAddress,
    FiveGsUserPlaneNodeId,
    PacketDelayThresholds,
    QoSMonitoringMeasurement,
    NumberOfUeIpAddresses,
    Thresholds,
    CpIpAddress,
    MappedN6IpAddress,
    N6RoutingInformation,
    N6DelayMeasurementInformation,
    MeasurementEndpointAddress,
    MoQRelayIpAddress,
);
