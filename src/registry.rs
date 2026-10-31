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


use crate::macros::{pfcp_ies, pfcp_table};
use crate::values::*;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    3 "Create FAR" grouped "7.5.2.3-1";
    4 "Forwarding Parameters" grouped "7.5.2.3-2";
    5 "Duplicating Parameters" grouped "7.5.2.3-3";
    6 "Create URR" grouped "7.5.2.4-1";
    7 "Create QER" grouped "7.5.2.5-1";
    8 "Created PDR" grouped "7.5.3.2-1";
    9 "Update PDR" grouped "7.5.4.2-1";
    10 "Update FAR" grouped "7.5.4.3-1";
    11 "Update Forwarding Parameters" grouped "7.5.4.3-2";
    12 "Update BAR (PFCP Session Report Response)" grouped "7.5.9.2-1";
    13 "Update URR" grouped "7.5.4.4-1";
    14 "Update QER" grouped "7.5.4.5-1";
    15 "Remove PDR" grouped "7.5.4.6-1";
    16 "Remove FAR" grouped "7.5.4.7-1";
    17 "Remove URR" grouped "7.5.4.8-1";
    18 "Remove QER" grouped "7.5.4.9-1";
    19 "Cause" fixed(1) "8.2.1";
    20 "Source Interface" extendable(1) "8.2.2" => SourceInterface;
    21 "F-TEID" extendable(1) "8.2.3" => FTeid;
    22 "Network Instance" variable "8.2.4";
    23 "SDF Filter" extendable(2) "8.2.5";
    24 "Application ID" variable "8.2.6";
    25 "Gate Status" extendable(1) "8.2.7";
    26 "MBR" extendable(10) "8.2.8";
    27 "GBR" extendable(10) "8.2.9";
    28 "QER Correlation ID" extendable(4) "8.2.10";
    29 "Precedence" extendable(4) "8.2.11" => Precedence;
    30 "Transport Level Marking" extendable(2) "8.2.12";
    31 "Volume Threshold" extendable(1) "8.2.13";
    32 "Time Threshold" extendable(4) "8.2.14";
    33 "Monitoring Time" extendable(4) "8.2.15";
    34 "Subsequent Volume Threshold" extendable(1) "8.2.16";
    35 "Subsequent Time Threshold" extendable(4) "8.2.17";
    36 "Inactivity Detection Time" extendable(4) "8.2.18";
    37 "Reporting Triggers" extendable(2) "8.2.19";
    38 "Redirect Information" extendable(3) "8.2.20";
    39 "Report Type" extendable(1) "8.2.21";
    40 "Offending IE" fixed(2) "8.2.22";
    41 "Forwarding Policy" extendable(1) "8.2.23";
    42 "Destination Interface" extendable(1) "8.2.24";
    43 "UP Function Features" extendable(1) "8.2.25";
    44 "Apply Action" extendable(1) "8.2.26";
    45 "Downlink Data Service Information" extendable(1) "8.2.27";
    46 "Downlink Data Notification Delay" extendable(1) "8.2.28";
    47 "DL Buffering Duration" extendable(1) "8.2.29";
    48 "DL Buffering Suggested Packet Count" variable "8.2.30";
    49 "PFCPSMReq-Flags" extendable(1) "8.2.31";
    50 "PFCPSRRsp-Flags" extendable(1) "8.2.32";
    51 "Load Control Information" grouped "7.5.3.3-1";
    52 "Sequence Number" fixed(4) "8.2.33";
    53 "Metric" fixed(1) "8.2.34";
    54 "Overload Control Information" grouped "7.5.3.4-1";
    55 "Timer" extendable(1) "8.2.35";
    56 "PDR ID" extendable(2) "8.2.36" => PdrId;
    57 "F-SEID" extendable(9) "8.2.37" => FSeid;
    58 "Application ID's PFDs" grouped "7.4.3.1-2";
    59 "PFD context" grouped "7.4.3.1-3";
    60 "Node ID" extendable(1) "8.2.38" => NodeId;
    61 "PFD contents" extendable(2) "8.2.39";
    62 "Measurement Method" extendable(1) "8.2.40";
    63 "Usage Report Trigger" extendable(2) "8.2.41";
    64 "Measurement Period" extendable(4) "8.2.42";
    65 "FQ-CSID" extendable(1) "8.2.43";
    66 "Volume Measurement" extendable(1) "8.2.44";
    67 "Duration Measurement" extendable(4) "8.2.45";
    68 "Application Detection Information" grouped "7.5.8.3-2";
    69 "Time of First Packet" extendable(4) "8.2.46";
    70 "Time of Last Packet" extendable(4) "8.2.47";
    71 "Quota Holding Time" extendable(4) "8.2.48";
    72 "Dropped DL Traffic Threshold" extendable(1) "8.2.49";
    73 "Volume Quota" extendable(1) "8.2.50";
    74 "Time Quota" extendable(4) "8.2.51";
    75 "Start Time" extendable(4) "8.2.52";
    76 "End Time" extendable(4) "8.2.53";
    77 "Query URR" grouped "7.5.4.10-1";
    78 "Usage Report (Session Modification Response)" grouped "7.5.5.2-1";
    79 "Usage Report (Session Deletion Response)" grouped "7.5.7.2-1";
    80 "Usage Report (Session Report Request)" grouped "7.5.8.3-1";
    81 "URR ID" extendable(4) "8.2.54" => UrrId;
    82 "Linked URR ID" extendable(4) "8.2.55";
    83 "Downlink Data Report" grouped "7.5.8.2-1";
    84 "Outer Header Creation" extendable(2) "8.2.56";
    85 "Create BAR" grouped "7.5.2.6-1";
    86 "Update BAR (Session Modification Request)" grouped "7.5.4.11-1";
    87 "Remove BAR" grouped "7.5.4.12-1";
    88 "BAR ID" extendable(1) "8.2.57";
    89 "CP Function Features" extendable(1) "8.2.58";
    90 "Usage Information" extendable(1) "8.2.59";
    91 "Application Instance ID" variable "8.2.60";
    92 "Flow Information" extendable(3) "8.2.61";
    93 "UE IP Address" extendable(1) "8.2.62" => UeIpAddress;
    94 "Packet Rate" extendable(1) "8.2.63";
    95 "Outer Header Removal" extendable(1) "8.2.64";
    96 "Recovery Time Stamp" extendable(4) "8.2.65";
    97 "DL Flow Level Marking" extendable(1) "8.2.66";
    98 "Header Enrichment" extendable(1) "8.2.67";
    99 "Error Indication Report" grouped "7.5.8.4-1";
    100 "Measurement Information" extendable(1) "8.2.68";
    101 "Node Report Type" extendable(1) "8.2.69";
    102 "User Plane Path Failure Report" grouped "7.4.5.1.2-1";
    103 "Remote GTP-U Peer" extendable(1) "8.2.70";
    104 "UR-SEQN" fixed(4) "8.2.71";
    105 "Update Duplicating Parameters" grouped "7.5.4.3-3";
    106 "Activate Predefined Rules" variable "8.2.72";
    107 "Deactivate Predefined Rules" variable "8.2.73";
    108 "FAR ID" extendable(4) "8.2.74" => FarId;
    109 "QER ID" extendable(4) "8.2.75" => QerId;
    110 "OCI Flags" extendable(1) "8.2.76";
    111 "PFCP Association Release Request" extendable(1) "8.2.77";
    112 "Graceful Release Period" extendable(1) "8.2.78";
    113 "PDN Type" extendable(1) "8.2.79";
    114 "Failed Rule ID" extendable(1) "8.2.80";
    115 "Time Quota Mechanism" extendable(1) "8.2.81";
    117 "User Plane Inactivity Timer" extendable(4) "8.2.83";
    118 "Aggregated URRs" grouped "7.5.2.4-2";
    119 "Multiplier" fixed(12) "8.2.84";
    120 "Aggregated URR ID" fixed(4) "8.2.85";
    121 "Subsequent Volume Quota" extendable(1) "8.2.86";
    122 "Subsequent Time Quota" extendable(4) "8.2.87";
    123 "RQI" extendable(1) "8.2.88";
    124 "QFI" extendable(1) "8.2.89";
    125 "Query URR Reference" extendable(4) "8.2.90";
    126 "Additional Usage Reports Information" extendable(2) "8.2.91";
    127 "Create Traffic Endpoint" grouped "7.5.2.7-1";
    128 "Created Traffic Endpoint" grouped "7.5.3.5-1";
    129 "Update Traffic Endpoint" grouped "7.5.4.13-1";
    130 "Remove Traffic Endpoint" grouped "7.5.4.14-1";
    131 "Traffic Endpoint ID" extendable(1) "8.2.92";
    132 "Ethernet Packet Filter" grouped "7.5.2.2-3";
    133 "MAC address" extendable(1) "8.2.93";
    134 "C-TAG" extendable(3) "8.2.94";
    135 "S-TAG" extendable(3) "8.2.95";
    136 "Ethertype" extendable(2) "8.2.96";
    137 "Proxying" extendable(1) "8.2.97";
    138 "Ethernet Filter ID" extendable(4) "8.2.98";
    139 "Ethernet Filter Properties" extendable(1) "8.2.99";
    140 "Suggested Buffering Packets Count" extendable(1) "8.2.100";
    141 "User ID" extendable(1) "8.2.101";
    142 "Ethernet PDU Session Information" extendable(1) "8.2.102";
    143 "Ethernet Traffic Information" grouped "7.5.8.3-3";
    144 "MAC Addresses Detected" extendable(7) "8.2.103";
    145 "MAC Addresses Removed" extendable(7) "8.2.104";
    146 "Ethernet Inactivity Timer" extendable(4) "8.2.105";
    147 "Additional Monitoring Time" grouped "7.5.2.4-3";
    148 "Event Quota" extendable(4) "8.2.112";
    149 "Event Threshold" extendable(4) "8.2.113";
    150 "Subsequent Event Quota" extendable(4) "8.2.106";
    151 "Subsequent Event Threshold" extendable(4) "8.2.107";
    152 "Trace Information" extendable(7) "8.2.108";
    153 "Framed-Route" variable "8.2.109";
    154 "Framed-Routing" fixed(4) "8.2.110";
    155 "Framed-IPv6-Route" variable "8.2.111";
    156 "Time Stamp" extendable(4) "8.2.114";
    157 "Averaging Window" extendable(4) "8.2.115";
    158 "Paging Policy Indicator" extendable(1) "8.2.116";
    159 "APN/DNN" variable "8.2.117";
    160 "3GPP Interface Type" extendable(1) "8.2.118";
    161 "PFCPSRReq-Flags" extendable(1) "8.2.119";
    162 "PFCPAUReq-Flags" extendable(1) "8.2.120";
    163 "Activation Time" extendable(4) "8.2.121";
    164 "Deactivation Time" extendable(4) "8.2.122";
    165 "Create MAR" grouped "7.5.2.8-1";
    166 "3GPP Access Forwarding Action Information" grouped "7.5.2.8-2";
    167 "Non-3GPP Access Forwarding Action Information" grouped "7.5.2.8-3";
    168 "Remove MAR" grouped "7.5.4.15-1";
    169 "Update MAR" grouped "7.5.4.16-1";
    170 "MAR ID" extendable(2) "8.2.123";
    171 "Steering Functionality" extendable(1) "8.2.124";
    172 "Steering Mode" extendable(1) "8.2.125";
    173 "Weight" fixed(1) "8.2.126";
    174 "Priority" extendable(1) "8.2.127";
    175 "Update 3GPP Access Forwarding Action Information" grouped "7.5.4.16-2";
    176 "Update Non 3GPP Access Forwarding Action Information" grouped "7.5.4.16-3";
    177 "UE IP address Pool Identity" extendable(2) "8.2.128";
    178 "Alternative SMF IP Address" extendable(1) "8.2.129";
    179 "Packet Replication and Detection Carry-On Information" extendable(1) "8.2.130";
    180 "SMF Set ID" extendable(1) "8.2.131";
    181 "Quota Validity Time" extendable(4) "8.2.132";
    182 "Number of Reports" fixed(2) "8.2.133";
    183 "PFCP Session Retention Information (within PFCP Association Setup Request)" grouped "7.4.4.1-2";
    184 "PFCPASRsp-Flags" extendable(1) "8.2.134";
    185 "CP PFCP Entity IP Address" extendable(1) "8.2.135";
    186 "PFCPSEReq-Flags" extendable(1) "8.2.136";
    187 "User Plane Path Recovery Report" grouped "7.4.5.1.3-1";
    188 "IP Multicast Addressing Info within PFCP Session Establishment Request" grouped "7.5.2.2-4";
    189 "Join IP Multicast Information IE within Usage Report" grouped "7.5.8.3-4";
    190 "Leave IP Multicast Information IE within Usage Report" grouped "7.5.8.3-5";
    191 "IP Multicast Address" extendable(1) "8.2.137";
    192 "Source IP Address" extendable(1) "8.2.138";
    193 "Packet Rate Status" extendable(1) "8.2.139";
    194 "Create Bridge/Router Info" extendable(1) "8.2.140";
    195 "Created Bridge/Router Info" grouped "7.5.3.6-1";
    196 "Port Number" fixed(4) "8.2.141";
    197 "NW-TT Port Number" fixed(4) "8.2.142";
    198 "5GS User Plane Node ID" extendable "8.2.143";
    199 "TSC Management Information IE within PFCP Session Modification Request" grouped "7.5.4.18-1";
    200 "TSC Management Information IE within PFCP Session Modification Response" grouped "7.5.5.3-1";
    201 "TSC Management Information IE within PFCP Session Report Request" grouped "7.5.8.5-1";
    202 "Port Management Information Container" variable "8.2.144";
    203 "Clock Drift Control Information" grouped "7.4.4.1.2-1";
    204 "Requested Clock Drift Information" extendable(1) "8.2.145";
    205 "Clock Drift Report" grouped "7.4.5.1.4-1";
    206 "Time Domain Number" extendable(1) "8.2.146";
    207 "Time Offset Threshold" extendable(8) "8.2.147";
    208 "Cumulative rateRatio Threshold" extendable(4) "8.2.148";
    209 "Time Offset Measurement" extendable(8) "8.2.149";
    210 "Cumulative rateRatio Measurement" extendable(4) "8.2.150";
    211 "Remove SRR" grouped "7.5.4.19-1";
    212 "Create SRR" grouped "7.5.2.9-1";
    213 "Update SRR" grouped "7.5.4.20-1";
    214 "Session Report" grouped "7.5.7.3-1";
    215 "SRR ID" extendable(1) "8.2.151";
    216 "Access Availability Control Information" grouped "7.5.2.9-2";
    217 "Requested Access Availability Information" extendable(1) "8.2.152";
    218 "Access Availability Report" grouped "7.5.8.6-2";
    219 "Access Availability Information" extendable(1) "8.2.153";
    220 "Provide ATSSS Control Information" grouped "7.5.2.10-1";
    221 "ATSSS Control Parameters" grouped "7.5.3.7-1";
    222 "MPTCP Control Information" extendable(1) "8.2.154";
    223 "ATSSS-LL Control Information" extendable(1) "8.2.155";
    224 "PMF Control Information" extendable(1) "8.2.156";
    225 "MPTCP Parameters" grouped "7.5.3.7-2";
    226 "ATSSS-LL Parameters" grouped "7.5.3.7-3";
    227 "PMF Parameters" grouped "7.5.3.7-4";
    228 "MPTCP Address Information" extendable(4) "8.2.157";
    229 "Link-Specific Multipath IP Address" extendable(1) "8.2.158";
    230 "PMF Address Information" extendable(1) "8.2.159";
    231 "ATSSS-LL Information" extendable(1) "8.2.160";
    232 "Data Network Access Identifier" variable "8.2.161";
    233 "UE IP address Pool Information" grouped "7.4.4.1-3";
    234 "Average Packet Delay" extendable(4) "8.2.162";
    235 "Minimum Packet Delay" extendable(4) "8.2.163";
    236 "Maximum Packet Delay" extendable(4) "8.2.164";
    237 "QoS Report Trigger" extendable(1) "8.2.165";
    238 "GTP-U Path QoS Control Information" grouped "7.4.4.1.3-1";
    239 "GTP-U Path QoS Report (PFCP Node Report Request)" grouped "7.4.5.1.5-1";
    240 "QoS Information in GTP-U Path QoS Report" grouped "7.4.5.1.6-1";
    241 "GTP-U Path Interface Type" extendable(1) "8.2.166";
    242 "QoS Monitoring per QoS flow Control Information" grouped "7.5.2.9-3";
    243 "Requested QoS Monitoring" extendable(1) "8.2.167";
    244 "Reporting Frequency" extendable(1) "8.2.168";
    245 "Packet Delay Thresholds" extendable(1) "8.2.169";
    246 "Minimum Wait Time" extendable(4) "8.2.170";
    247 "QoS Monitoring Report" grouped "7.5.8.6-3";
    248 "QoS Monitoring Measurement" extendable(1) "8.2.171";
    249 "MT-EDT Control Information" extendable(1) "8.2.172";
    250 "DL Data Packets Size" extendable(2) "8.2.173";
    251 "QER Control Indications" extendable(1) "8.2.174";
    252 "Packet Rate Status Report" grouped "7.5.7.1-2";
    253 "NF Instance ID" fixed(16) "8.2.175";
    254 "Ethernet Context Information" grouped "7.5.4.21-1";
    255 "Redundant Transmission Parameters" grouped "7.5.2.2-5";
    256 "Updated PDR" grouped "7.5.5.5-1";
    257 "S-NSSAI" fixed(4) "8.2.176";
    258 "IP version" extendable(1) "8.2.177";
    259 "PFCPASReq-Flags" extendable(1) "8.2.178";
    260 "Data Status" extendable(1) "8.2.179";
    261 "Provide RDS configuration information" grouped "7.5.2.11-1";
    262 "RDS configuration information" extendable(1) "8.2.180";
    263 "Query Packet Rate Status IE within PFCP Session Modification Request" grouped "7.5.4.22-1";
    264 "Packet Rate Status Report IE within PFCP Session Modification Response" grouped "7.5.5.4-1";
    265 "Multipath Applicable Indication" extendable(1) "8.2.181";
    266 "User Plane Node Management Information Container" variable "8.2.182";
    267 "UE IP Address Usage Information" grouped "7.4.4.3.1-1";
    268 "Number of UE IP Addresses" extendable(1) "8.2.183";
    269 "Validity Timer" extendable(2) "8.2.184";
    270 "Redundant Transmission Forwarding Parameters" grouped "7.5.2.3-4";
    271 "Transport Delay Reporting" grouped "7.5.2.2-6";
    272 "Partial Failure Information" grouped "7.5.3.1-2";
    274 "Offending IE Information" variable "8.2.185";
    275 "RAT Type" extendable(1) "8.2.186";
    276 "L2TP Tunnel Information" grouped "7.5.2.1-2";
    277 "L2TP Session Information" grouped "7.5.2.1-3";
    278 "L2TP User Authentication" extendable(1) "8.2.187";
    279 "Created L2TP Session" grouped "7.5.3.1-3";
    280 "LNS Address" extendable(4) "8.2.188";
    281 "Tunnel Preference" fixed(3) "8.2.189";
    282 "Calling Number" variable "8.2.190";
    283 "Called Number" variable "8.2.191";
    284 "L2TP Session Indications" extendable(1) "8.2.192";
    285 "DNS Server Address" extendable(4) "8.2.193";
    286 "NBNS Server Address" extendable(4) "8.2.194";
    287 "Maximum Receive Unit" fixed(2) "8.2.195";
    288 "Thresholds" extendable(1) "8.2.196";
    289 "Steering Mode Indicator" extendable(1) "8.2.197";
    290 "PFCP Session Change Info" grouped "7.4.7.1-2";
    291 "Group ID" variable "8.2.198";
    292 "CP IP Address" variable "8.2.199";
    293 "IP Address and Port number Replacement" extendable(2) "8.2.200";
    294 "DNS Query/Response Filter" extendable(2) "8.2.201";
    295 "Direct Reporting Information" grouped "7.5.2.9-4";
    296 "Event Notification URI" variable "8.2.202";
    297 "Notification Correlation ID" variable "8.2.203";
    298 "Reporting Flags" extendable(1) "8.2.204";
    299 "Predefined Rules Name" variable "8.2.205";
    300 "MBS Session N4mb Control Information" grouped "7.5.2.1-4";
    301 "MBS Multicast Parameters" grouped "7.5.2.3-5";
    302 "Add MBS Unicast Parameters" grouped "7.5.2.3-6";
    303 "MBS Session N4mb Information" grouped "7.5.3.1-4";
    304 "Remove MBS Unicast Parameters" grouped "7.5.4.3-4";
    305 "MBS Session Identifier" extendable(1) "8.2.206";
    306 "Multicast Transport Information" extendable(5) "8.2.207";
    307 "MBSN4mbReq-Flags" extendable(1) "8.2.208";
    308 "Local Ingress Tunnel" extendable(1) "8.2.209";
    309 "MBS Unicast Parameters ID" extendable(2) "8.2.210";
    310 "MBS Session N4 Control Information" grouped "7.5.2.1-5";
    311 "MBS Session N4 Information" grouped "7.5.3.1-5";
    312 "MBSN4Resp-Flags" extendable(1) "8.2.211";
    313 "Tunnel Password" variable "8.2.212";
    314 "Area Session ID" fixed(2) "8.2.213";
    315 "Peer UP Restart Report" grouped "7.4.5.1.7-1";
    316 "DSCP to PPI Control Information" grouped "7.5.2.1-6";
    317 "DSCP to PPI Mapping Information" extendable(2) "8.2.214";
    318 "PFCPSDRsp-Flags" extendable(1) "8.2.215";
    319 "QER Indications" extendable(1) "8.2.216";
    320 "Vendor-Specific Node Report Type" extendable(3) "8.2.217";
    321 "Configured Time Domain" extendable(1) "8.2.218";
    322 "Metadata" variable "8.2.219";
    323 "Traffic Parameter Measurement Control Information" grouped "7.5.2.9-5";
    324 "Traffic Parameter Measurement Report" grouped "7.5.8.6-4";
    325 "Traffic Parameter Threshold" extendable(1) "8.2.219";
    326 "DL Periodicity" extendable(5) "8.2.219";
    327 "N6 Jitter Measurement" extendable(1) "8.2.219";
    328 "Traffic Parameter Measurement Indication" extendable(1) "8.2.223";
    329 "UL Periodicity" extendable(5) "8.2.223";
    330 "MPQUIC Control Information" extendable(1) "8.2.225";
    331 "MPQUIC Parameters" grouped "7.5.3.7-5";
    332 "MPQUIC Address Information" extendable(4) "8.2.226";
    333 "Transport Mode" extendable(1) "8.2.227";
    334 "Protocol Description" grouped "7.5.2.2-7";
    335 "Reporting Suggestion Info" extendable(1) "8.2.229";
    336 "TL-Container" variable "8.2.230";
    337 "Measurement Indication" extendable(1) "8.2.231";
    338 "HPLMN S-NSSAI" fixed(4) "8.2.232";
    339 "Media Transport Protocol" extendable(1) "8.2.233";
    340 "RTP Header Extension Information" grouped "7.5.2.2-8";
    341 "RTP Payload Information" grouped "7.5.2.2-9";
    342 "RTP Header Extension Type" fixed(1) "8.2.234";
    343 "RTP Header Extension ID" fixed(1) "8.2.235";
    344 "RTP Payload Type" fixed(1) "8.2.236";
    345 "RTP Payload Format" fixed(1) "8.2.237";
    346 "Extended DL Buffering Notification Policy" extendable(1) "8.2.238";
    347 "MT-SDT Control Information" extendable(1) "8.2.239";
    348 "Reporting Thresholds" extendable(1) "8.2.240";
    349 "RTP Header Extension Additional Information" extendable(2) "8.2.241";
    350 "Mapped N6 IP Address" extendable(1) "8.2.242";
    351 "N6 Routing Information" extendable(1) "8.2.243";
    352 "URI" variable "8.2.244";
    353 "UE Level Measurements Configuration" extendable(2) "8.2.245";
    354 "N6 Delay Measurement Protocols" extendable(1) "8.2.246";
    355 "N6 Delay Measurement Control Information" grouped "7.4.4.1.4-1";
    356 "N6 Delay Measurement Report (PFCP Node Report Request)" grouped "7.4.5.1.8-1";
    357 "N6 Delay Measurement Information" extendable(1) "8.2.247";
    358 "Measurement Endpoint Address" extendable(1) "8.2.248";
    359 "Operator Configurable UPF Capability" variable "8.2.249";
    360 "Packet Inspection functionality" extendable(1) "8.2.250";
    361 "Header Handling Control Rule" grouped "7.5.2.3-7";
    362 "Header Handling Reporting Control Info" grouped "7.5.2.3-8";
    363 "Header Handling Control information" grouped "7.5.2.3-9";
    364 "Header Detection Reference" variable "8.2.251";
    365 "Header Detection Support Information" variable "8.2.252";
    366 "Reporting Endpoint ID" fixed(1) "8.2.253";
    367 "Header Handling Control Reference" variable "8.2.254";
    368 "Header Handling Action" fixed(1) "8.2.255";
    369 "Header Information" variable "8.2.256";
    370 "Header Value" variable "8.2.257";
    371 "Header Handling Condition" fixed(1) "8.2.258";
    372 "Header Handling Control ID" fixed(1) "8.2.259";
    373 "Header Handling Control Rule ID" fixed(1) "8.2.260";
    374 "On-path N6 Connection Information" extendable(1) "8.2.261";
    375 "Measurement Reporting Type" extendable(1) "8.2.262";
    376 "N6 Delay Measurement Failure Information" extendable(1) "8.2.263";
    377 "N6 Delay Measurement Control Information ID" fixed(2) "8.2.264";
    378 "Protocol Specific Configuration Parameters" grouped "7.4.4.1.4-2";
    379 "Measurement Endpoint Port Number" fixed(2) "8.2.265";
    380 "Header Handling Reporting Indication" extendable(1) "8.2.266";
    382 "SMF Change Reason" extendable(1) "8.2.267";
    383 "Extended Transport Level Marking" grouped "7.5.2.3-10";
    384 "PDU Set Importance" fixed(2) "8.2.268";
    385 "MoQ Control Information" extendable(1) "8.2.269";
    386 "MoQ Information" grouped "7.5.3.1-6";
    387 "MoQ Relay IP Address" extendable(1) "8.2.270";
    388 "Media Related Information Transfer Info" extendable(1) "8.2.271";
    389 "Reporting Control Information" extendable(1) "8.2.272";
    390 "Security Mode (STAMP)" fixed(1) "8.2.273";
    391 "HMAC Key (STAMP)" variable "8.2.274";
    392 "Security Mode (OWAMP or TWAMP)" fixed(4) "8.2.275";
    393 "Key ID and Shared Secret (OWAMP or TWAMP)" extendable(1) "8.2.276";
    394 "Remaining Data Reporting Indication" extendable(1) "8.2.277";
    395 "Expedited Transfer Indication" fixed(1) "8.2.278";
    396 "Session Reflector Mode (STAMP)" fixed(1) "8.2.279";
    397 "PFD Partial Failure Information" grouped "7.4.3.2-2";
    398 "Transport Level Marking Indications" fixed(1) "8.2.280";
    399 "Redundant N3/N9 Transmission Information" grouped "7.5.8.6-5";
    400 "Local N3/N9 Tunnel Information" grouped "7.5.8.6-6";
    401 "Remote N3/N9 Tunnel Information" grouped "7.5.8.6-7";
    402 "Binding Indication" variable "8.2.281";
    403 "PDU Set Importance for N6-unmarked PDUs" fixed(1) "8.2.282";
}

pfcp_table! {
    /// Heartbeat Request (§7.4.2.1).
    message HeartbeatRequest = 1, "PFCP Heartbeat Request", "7.4.2.1-1" {
        recovery_time_stamp: "Recovery Time Stamp" M raw 96 [SXA SXB SXC N4 N4MB],
        source_ip_address: "Source IP Address" O raw 192 [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// Heartbeat Response (§7.4.2.2).
    message HeartbeatResponse = 2, "PFCP Heartbeat Response", "7.4.2.2-1" {
        recovery_time_stamp: "Recovery Time Stamp" M raw 96 [SXA SXB SXC N4 N4MB],
    }
}

pfcp_table! {
    /// PFCP Session Establishment Request (§7.5.2.1).
    message SessionEstablishmentRequest = 50, "PFCP Session Establishment Request", "7.5.2.1-1" {
        node_id: "Node ID" M NodeId [SXA SXB SXC N4 N4MB],
        cp_f_seid: "CP F-SEID" M FSeid [SXA SXB SXC N4 N4MB],
        create_pdr: "Create PDR" M* CreatePdr [SXA SXB SXC N4 N4MB],
        create_far: "Create FAR" M* raw 3 [SXA SXB SXC N4 N4MB],
        create_urr: "Create URR" C* raw 6 [SXA SXB SXC N4 N4MB],
        create_qer: "Create QER" C* raw 7 [SXB SXC N4 N4MB],
        create_bar: "Create BAR" O raw 85 [SXA N4],
        create_traffic_endpoint: "Create Traffic Endpoint" C* raw 127 [SXA SXB SXC N4 N4MB],
        pdn_type: "PDN Type" C raw 113 [SXA SXB N4],
        fq_csid: "FQ-CSID" C*5 raw 65 [SXA SXB N4]
            roles ["SGW-C FQ-CSID" C [SXA SXB], "MME FQ-CSID" C [SXA SXB], "PGW-C/SMF FQ-CSID" C [SXA SXB N4],
                "ePDG FQ-CSID" C [SXB], "TWAN FQ-CSID" C [SXB]],
        user_plane_inactivity_timer: "User Plane Inactivity Timer" O raw 117 [SXB SXC N4 N4MB],
        user_id: "User ID" O raw 141 [SXA SXB SXC N4],
        trace_information: "Trace Information" O raw 152 [SXA SXB SXC N4],
        apn_dnn: "APN/DNN" O raw 159 [SXA SXB N4 N4MB],
        create_mar: "Create MAR" C* raw 165 [N4],
        pfcpsereq_flags: "PFCPSEReq-Flags" C raw 186 [SXA SXB N4],
        create_bridge_router_info: "Create Bridge/Router Info" C raw 194 [N4],
        create_srr: "Create SRR" O* raw 212 [N4],
        provide_atsss_control_information: "Provide ATSSS Control Information" C raw 220 [N4],
        recovery_time_stamp: "Recovery Time Stamp" O raw 96 [SXA SXB SXC N4],
        s_nssai: "S-NSSAI" O raw 257 [N4 N4MB],
        hplmn_s_nssai: "HPLMN S-NSSAI" C raw 338 [N4],
        provide_rds_configuration_information: "Provide RDS configuration information" O raw 261 [SXB N4],
        rat_type: "RAT Type" O raw 275 [SXA SXB N4],
        l2tp_tunnel_information: "L2TP Tunnel Information" C raw 276 [SXB N4],
        l2tp_session_information: "L2TP Session Information" C raw 277 [SXB N4],
        group_id: "Group Id" O raw 291 [SXB N4],
        mbs_session_n4mb_control_information: "MBS Session N4mb Control Information" M raw 300 [N4MB],
        mbs_session_n4_control_information: "MBS Session N4 Control Information" C* raw 310 [N4],
        dscp_to_ppi_control_information: "DSCP to PPI Control Information" O* raw 316 [N4],
        tl_container: "TL-Container" C raw 336 [N4],
        trace_collection_entity_uri: "Trace Collection Entity URI" O raw 352 [SXA SXB SXC N4],
        ue_level_measurements_configuration: "UE Level Measurements Configuration" O raw 353 [N4],
        alternative_smf_ip_address: "Alternative SMF IP Address" O raw 178 [N4],
        moq_control_information: "MoQ Control Information" C raw 385 [N4],
    }
}

pfcp_table! {
    /// Create PDR within PFCP Session Establishment Request (Table 7.5.2.2-1).
    group CreatePdr = 1, "Create PDR", "7.5.2.2-1" {
        pdr_id: "PDR ID" M PdrId [SXA SXB SXC N4 N4MB],
        precedence: "Precedence" M Precedence [SXB SXC N4 N4MB],
        pdi: "PDI" M Pdi [SXA SXB SXC N4 N4MB],
        outer_header_removal: "Outer Header Removal" C raw 95 [SXA SXB N4 N4MB],
        far_id: "FAR ID" C FarId [SXA SXB SXC N4 N4MB],
        urr_id: "URR ID" C* UrrId [SXA SXB SXC N4],
        qer_id: "QER ID" C* QerId [SXB SXC N4 N4MB],
        activate_predefined_rules: "Activate Predefined Rules" C* raw 106 [SXB SXC N4],
        activation_time: "Activation Time" O raw 163 [SXB SXC N4],
        deactivation_time: "Deactivation Time" O raw 164 [SXB SXC N4],
        mar_id: "MAR ID" C raw 170 [N4],
        packet_replication_and_detection_carry_on_information:
            "Packet Replication and Detection Carry-On Information" C raw 179 [N4],
        ip_multicast_addressing_info: "IP Multicast Addressing Info" O* raw 188 [N4],
        ue_ip_address_pool_identity: "UE IP address Pool Identity" O*2 raw 177 [SXB N4],
        multipath_applicable_indication: "Multipath Applicable Indication" C raw 265 [N4],
        transport_delay_reporting: "Transport Delay Reporting" C raw 271 [N4],
        rat_type: "RAT Type" O raw 275 [N4],
    }
}

pfcp_table! {
    /// PDI within PFCP Session Establishment Request (Table 7.5.2.2-2).
    group Pdi = 2, "PDI", "7.5.2.2-2" {
        source_interface: "Source Interface" M SourceInterface [SXA SXB SXC N4 N4MB],
        local_f_teid: "Local F-TEID" O FTeid [SXA SXB N4],
        local_ingress_tunnel: "Local Ingress Tunnel" C raw 308 [N4MB],
        network_instance: "Network Instance" O raw 22 [SXA SXB SXC N4 N4MB],
        redundant_transmission_detection_parameters:
            "Redundant Transmission Detection Parameters" O raw 255 [N4],
        ue_ip_address: "UE IP address" O* UeIpAddress [SXB SXC N4],
        mapped_n6_ip_address: "Mapped N6 IP Address" O raw 350 [N4],
        n6_routing_information: "N6 Routing Information" O raw 351 [N4],
        traffic_endpoint_id: "Traffic Endpoint ID" C* raw 131 [SXA SXB SXC N4 N4MB],
        sdf_filter: "SDF Filter" O* raw 23 [SXB SXC N4 N4MB],
        application_id: "Application ID" O raw 24 [SXB SXC N4 N4MB],
        ethernet_pdu_session_information: "Ethernet PDU Session Information" O raw 142 [N4],
        ethernet_packet_filter: "Ethernet Packet Filter" O* raw 132 [N4],
        qfi: "QFI" O* raw 124 [N4],
        framed_route: "Framed-Route" O* raw 153 [SXB N4],
        framed_routing: "Framed-Routing" O raw 154 [SXB N4],
        framed_ipv6_route: "Framed-IPv6-Route" O* raw 155 [SXB N4],
        source_interface_type: "Source Interface Type" C raw 160 [SXA SXB N4 N4MB],
        ip_multicast_addressing_info: "IP Multicast Addressing Info" O* raw 188 [N4 N4MB],
        dns_query_response_filter: "DNS Query/Response Filter" O* raw 294 [N4]
            roles ["DNS Query Filter" O [N4], "DNS Response Filter" O [N4]],
        mbs_session_identifier: "MBS Session Identifier" C raw 305 [N4],
        area_session_id: "Area Session ID" C raw 314 [N4],
        protocol_description: "Protocol Description" O raw 334 [N4],
        expedited_transfer_indication: "Expedited Transfer Indication" O raw 395 [N4],
    }
}

