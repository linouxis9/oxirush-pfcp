//! The messages of the measurements: Session Establishment Requests the size of those of
//! a lab, and the workloads.

use std::net::Ipv4Addr;

use oxirush_pfcp::*;

/// A Network Instance, as an APN: `internet`.
fn network_instance() -> NetworkInstance {
    NetworkInstance(b"\x08internet".to_vec().into())
}

fn network_instance_fp() -> NetworkInstance {
    NetworkInstance(b"\x08internet".to_vec().into())
}

fn far(id: u32, core: bool) -> CreateFar {
    // FAR ID, Apply Action (FORW), Forwarding Parameters: Destination Interface, Network
    // Instance and, toward the access, Outer Header Creation (GTP-U/UDP/IPv4)
    let mut forwarding = ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::from_value(u8::from(core))))
        .with_network_instance(network_instance_fp());
    if !core {
        let creation = OuterHeaderCreation { gtpu_udp_ipv4: true, teid: Some(1), ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)), ..Default::default() };
        forwarding = forwarding.with_outer_header_creation(creation);
    }
    CreateFar::new(FarId::new(id), ApplyAction { forw: true, ..Default::default() }).with_forwarding_parameters(forwarding)
}

fn urr(id: u32) -> CreateUrr {
    // URR ID, Measurement Method (VOLUM DURAT), Reporting Triggers (VOLTH TIMTH),
    // Volume Threshold (TOVOL), Time Threshold
    CreateUrr::new(
        UrrId::new(id),
        MeasurementMethod { volum: true, durat: true, ..Default::default() },
        ReportingTriggers { volth: true, timth: true, ..Default::default() },
    )
    .with_volume_threshold(VolumeThreshold { tovol: true, total_volume: Some(0x4000_0000), ..Default::default() })
    .with_time_threshold(TimeThreshold::new(3600))
}

fn qer(id: u32) -> CreateQer {
    // QER ID, Gate Status, MBR, QFI
    CreateQer::new(QerId::new(id), GateStatus::default())
        .with_maximum_bitrate(Mbr { ul_mbr: U40(1_000_000), dl_mbr: U40(1_000_000), ..Default::default() })
        .with_qos_flow_identifier(Qfi { qfi_value: 9, ..Default::default() })
}

/// The value of the octets of an IE.
fn value<T: Codec>(octets: &[u8]) -> T {
    T::decode(octets).unwrap()
}

fn sdf_filter(text: &str) -> SdfFilter {
    // FD, then the length of the Flow Description and the description
    let mut octets = vec![0x01, 0x00];
    octets.extend_from_slice(&(text.len() as u16).to_be_bytes());
    octets.extend_from_slice(text.as_bytes());
    value::<SdfFilter>(&octets)
}

fn pdr(id: u16, uplink: bool) -> CreatePdr {
    let pdi = if uplink {
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access))
            .with_local_f_teid(FTeid::choose_ipv4())
            .with_network_instance(network_instance())
            .with_qfi(Qfi { qfi_value: 9, ..Default::default() })
    } else {
        let ue = UeIpAddress { v4: true, sd: true, ipv4: Some(Ipv4Addr::new(10, 45, 0, 2)), ..Default::default() };
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Core))
            .with_network_instance(network_instance())
            .with_ue_ip_address(ue)
            .with_sdf_filter(sdf_filter("permit out ip from any to assigned"))
    };
    let mut created = CreatePdr::new_n4(PdrId::new(id), Precedence::new(255 - u32::from(id)), pdi)
        .with_far_id(FarId::new(u32::from(id)))
        .with_urr_id(UrrId::new(u32::from(id).div_ceil(2)))
        .with_qer_id(QerId::new(1));
    if uplink {
        created = created.with_outer_header_removal(OuterHeaderRemoval::default());
    }
    created
}

/// A Session Establishment Request of `pdrs` PDRs, as many FARs, half as many URRs and
/// one QER, with the SMF's Node ID as an FQDN.
pub fn establishment(pdrs: u16) -> Vec<u8> {
    let smf = Ipv4Addr::new(10, 0, 0, 1);
    let seid = FSeid { v4: true, seid: Some(0x1001), ipv4: Some(smf), ..Default::default() };
    let mut labels = Vec::new();
    for label in "smf.5gc.mnc093.mcc208.3gppnetwork.org".split('.') {
        labels.push(label.len() as u8);
        labels.extend_from_slice(label.as_bytes());
    }
    let mut request = SessionEstablishmentRequest::new_n4(NodeId::Fqdn(labels.into()), seid, pdr(1, true), far(1, true));
    for id in 2..=pdrs {
        request = request.with_create_pdr(pdr(id, id % 2 == 1));
    }
    for id in 2..=u32::from(pdrs) {
        request = request.with_create_far(far(id, id % 2 == 1));
    }
    for id in 1..=u32::from(pdrs).div_ceil(2) {
        request = request.with_create_urr(urr(id));
    }
    request = request
        .with_create_qer(qer(1))
        .with_pdn_type(value::<PdnType>(&[0x01]))
        .with_apn_dnn(value::<ApnDnn>(b"\x08internet"))
        .with_s_nssai(value::<SNssai>(&[0x01, 0x00, 0x00, 0x01]))
        .with_user_id(value::<UserId>(&[0x01, 0x08, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0xf1]));
    let message = Message { header: Header::session(0, 7), body: request.into() };
    message.encode().unwrap()
}

/// The messages of the measurements, by name.
pub fn messages() -> Vec<(&'static str, Vec<u8>)> {
    let mut messages = vec![
        ("heartbeat", hex::decode("200100251122330000600004dfd52c0000c00015037f00000120010000000000000000000000000001").unwrap()),
        ("ser-4", establishment(4)),
        ("ser-16", establishment(16)),
    ];
    // The messages of the lab runs, by their run and number: `captures` measures them all.
    if let Ok(file) = std::env::var("PFCP_CAPTURES") {
        for line in std::fs::read_to_string(file).unwrap().lines().filter(|line| !line.starts_with('#')) {
            let fields: Vec<&str> = line.split('\t').collect();
            let name: &'static str = format!("capture:{}:{}", fields[0], fields[1]).leak();
            messages.push((name, hex::decode(fields[5]).unwrap()));
        }
    }
    if let Ok(file) = std::env::var("PFCP_VECTORS") {
        for line in std::fs::read_to_string(file).unwrap().lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields[0] == "session-establishment-request_test.go" && fields[1] == "Multiple IEs" {
                messages.push(("go-pfcp-ser", hex::decode(fields[2]).unwrap()));
            }
        }
    }
    messages
}

/// Every value of a decoded message, read: what a program that takes all of it does.
pub fn read(message: &Message) -> u64 {
    let mut sum = u64::from(message.header.sequence);
    let octets = |octets: &[u8]| octets.len() as u64 + u64::from(octets.first().copied().unwrap_or(0));
    let raw = |raw: &[RawIe]| raw.iter().map(|ie| u64::from(ie.ie_type) + octets(&ie.octets)).sum::<u64>();
    let f_teid = |f: &FTeid| u64::from(f.teid.unwrap_or(0)) + u64::from(f.ch) + f.ipv4.map_or(0, |a| u64::from(a.to_bits()));
    if let Body::SessionEstablishmentRequest(request) = &message.body {
        sum += match &request.node_id {
            Some(NodeId::Fqdn(labels)) => octets(labels),
            Some(NodeId::Ipv4(address)) => u64::from(address.to_bits()),
            _ => 0,
        };
        if let Some(seid) = &request.cp_f_seid {
            sum += seid.seid.unwrap_or(0) + seid.ipv4.map_or(0, |a| u64::from(a.to_bits()));
        }
        for pdr in &request.create_pdr {
            sum += pdr.pdr_id.as_ref().map_or(0, |id| u64::from(id.value));
            sum += pdr.precedence.as_ref().map_or(0, |p| u64::from(p.value));
            sum += pdr.far_id.as_ref().map_or(0, |id| u64::from(id.value));
            sum += pdr.urr_id.iter().map(|id| u64::from(id.value)).sum::<u64>();
            sum += pdr.qer_id.iter().map(|id| u64::from(id.value)).sum::<u64>();
            sum += pdr.outer_header_removal.as_ref().map_or(0, |r| u64::from(r.outer_header_removal_description.value()));
            if let Some(pdi) = &pdr.pdi {
                sum += pdi.source_interface.as_ref().map_or(0, |s| u64::from(s.interface_value.value()));
                sum += pdi.local_f_teid.as_ref().map_or(0, f_teid);
                sum += pdi.network_instance.as_ref().map_or(0, |n| octets(&n.0));
                sum += pdi.ue_ip_address.iter().map(|u| u.ipv4.map_or(0, |a| u64::from(a.to_bits()))).sum::<u64>();
                sum += pdi.sdf_filter.iter().map(|f| f.flow_description.as_ref().map_or(0, |d| octets(&d.0))).sum::<u64>();
                sum += pdi.qfi.iter().map(|q| u64::from(q.qfi_value)).sum::<u64>();
                sum += raw(&pdi.raw);
            }
            sum += raw(&pdr.raw);
        }
        for far in &request.create_far {
            sum += far.far_id.as_ref().map_or(0, |id| u64::from(id.value));
            sum += far.apply_action.as_ref().map_or(0, |a| u64::from(a.forw) + u64::from(a.buff));
            if let Some(forwarding) = &far.forwarding_parameters {
                sum += forwarding.destination_interface.as_ref().map_or(0, |d| u64::from(d.interface_value.value()));
                sum += forwarding.network_instance.as_ref().map_or(0, |n| octets(&n.0));
                sum += forwarding.outer_header_creation.as_ref().map_or(0, |o| u64::from(o.teid.unwrap_or(0)) + o.ipv4.map_or(0, |a| u64::from(a.to_bits())));
                sum += raw(&forwarding.raw);
            }
            sum += raw(&far.raw);
        }
        for urr in &request.create_urr {
            sum += urr.urr_id.as_ref().map_or(0, |id| u64::from(id.value));
            sum += urr.measurement_method.as_ref().map_or(0, |m| u64::from(m.volum));
            sum += urr.reporting_triggers.as_ref().map_or(0, |r| u64::from(r.volth));
            sum += urr.volume_threshold.as_ref().map_or(0, |v| v.total_volume.unwrap_or(0));
            sum += urr.time_threshold.as_ref().map_or(0, |t| u64::from(t.value));
            sum += raw(&urr.raw);
        }
        for qer in &request.create_qer {
            sum += qer.qer_id.as_ref().map_or(0, |id| u64::from(id.value));
            sum += qer.gate_status.as_ref().map_or(0, |g| u64::from(g.ul_gate.value()));
            sum += qer.maximum_bitrate.as_ref().map_or(0, |m| m.ul_mbr.0 + m.dl_mbr.0);
            sum += qer.qos_flow_identifier.as_ref().map_or(0, |q| u64::from(q.qfi_value));
            sum += raw(&qer.raw);
        }
        sum += request.pdn_type.as_ref().map_or(0, |p| u64::from(p.pdn_type.value()));
        sum += request.apn_dnn.as_ref().map_or(0, |a| octets(&a.0));
        sum += request.s_nssai.as_ref().map_or(0, |s| u64::from(s.sst) + u64::from(s.sd.0));
        sum += request.user_id.as_ref().map_or(0, |u| u.imsi.as_ref().map_or(0, |i| octets(&i.0)));
        sum += raw(&request.raw);
    }
    sum
}

/// The IEs of a message, depth first, framed and not decoded: the length of each.
pub fn frame(octets: &[u8]) -> u64 {
    fn walk(ies: framing::Ies) -> u64 {
        let mut sum = 0;
        for ie in ies.flatten() {
            sum += u64::from(ie.length);
            if ie_type_info(ie.ie_type).is_some_and(|info| info.form == Form::Grouped) {
                sum += walk(ie.ies());
            }
        }
        sum
    }
    let (_, _, ies) = framing::message_ies(octets).unwrap();
    walk(ies)
}
