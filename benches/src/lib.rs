//! The messages of the measurements: Session Establishment Requests the size of those of
//! a lab, and the workloads.

use std::net::Ipv4Addr;

use oxirush_pfcp::*;

/// A Network Instance, as an APN: `internet`.
fn network_instance() -> Raw<'static, 22> {
    Raw(b"\x08internet".to_vec().into())
}

fn far(id: u32, core: bool) -> Raw<'static, 3> {
    // FAR ID, Apply Action (FORW), Forwarding Parameters: Destination Interface, Network
    // Instance and, toward the access, Outer Header Creation (GTP-U/UDP/IPv4)
    let mut ies = vec![0x00, 0x6c, 0x00, 0x04];
    ies.extend_from_slice(&id.to_be_bytes());
    ies.extend_from_slice(&[0x00, 0x2c, 0x00, 0x02, 0x02, 0x00]);
    let mut forwarding = vec![0x00, 0x2a, 0x00, 0x01, if core { 1 } else { 0 }];
    forwarding.extend_from_slice(&[0x00, 0x16, 0x00, 0x09]);
    forwarding.extend_from_slice(b"\x08internet");
    if !core {
        forwarding.extend_from_slice(&[0x00, 0x54, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 10, 0, 0, 2]);
    }
    ies.extend_from_slice(&[0x00, 0x04]);
    ies.extend_from_slice(&(forwarding.len() as u16).to_be_bytes());
    ies.extend_from_slice(&forwarding);
    Raw(ies.into())
}

fn urr(id: u32) -> Raw<'static, 6> {
    // URR ID, Measurement Method (VOLUM DURAT), Reporting Triggers (VOLTH TIMTH),
    // Volume Threshold (TOVOL), Time Threshold
    let mut ies = vec![0x00, 0x51, 0x00, 0x04];
    ies.extend_from_slice(&id.to_be_bytes());
    ies.extend_from_slice(&[0x00, 0x3e, 0x00, 0x01, 0x03]);
    ies.extend_from_slice(&[0x00, 0x25, 0x00, 0x03, 0x06, 0x00, 0x00]);
    ies.extend_from_slice(&[0x00, 0x1f, 0x00, 0x09, 0x01, 0, 0, 0, 0, 0x40, 0, 0, 0]);
    ies.extend_from_slice(&[0x00, 0x20, 0x00, 0x04, 0, 0, 0x0e, 0x10]);
    Raw(ies.into())
}

fn qer(id: u32) -> Raw<'static, 7> {
    // QER ID, Gate Status, MBR, QFI
    let mut ies = vec![0x00, 0x6d, 0x00, 0x04];
    ies.extend_from_slice(&id.to_be_bytes());
    ies.extend_from_slice(&[0x00, 0x19, 0x00, 0x01, 0x00]);
    ies.extend_from_slice(&[0x00, 0x1a, 0x00, 0x0a, 0, 0, 0x0f, 0x42, 0x40, 0, 0, 0x0f, 0x42, 0x40]);
    ies.extend_from_slice(&[0x00, 0x7c, 0x00, 0x01, 0x09]);
    Raw(ies.into())
}

fn sdf_filter(text: &str) -> Raw<'static, 23> {
    // FD, then the length of the Flow Description and the description
    let mut octets = vec![0x01, 0x00];
    octets.extend_from_slice(&(text.len() as u16).to_be_bytes());
    octets.extend_from_slice(text.as_bytes());
    Raw(octets.into())
}

fn pdr(id: u16, uplink: bool) -> CreatePdr<'static> {
    let pdi = if uplink {
        Pdi::new(SourceInterface::new(InterfaceValue::Access))
            .with_local_f_teid(FTeid::choose_ipv4())
            .with_network_instance(network_instance())
            .with_qfi(Raw(vec![0x09].into()))
    } else {
        let ue = UeIpAddress { v4: true, sd: true, ipv4: Some(Ipv4Addr::new(10, 45, 0, 2)), ..Default::default() };
        Pdi::new(SourceInterface::new(InterfaceValue::Core))
            .with_network_instance(network_instance())
            .with_ue_ip_address(ue)
            .with_sdf_filter(sdf_filter("permit out ip from any to assigned"))
    };
    let mut created = CreatePdr::new(PdrId::new(id), Precedence::new(255 - u32::from(id)), pdi)
        .with_far_id(FarId::new(u32::from(id)))
        .with_urr_id(UrrId::new(u32::from(id).div_ceil(2)))
        .with_qer_id(QerId::new(1));
    if uplink {
        created = created.with_outer_header_removal(Raw(vec![0x00].into()));
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
    let mut request = SessionEstablishmentRequest::new(NodeId::Fqdn(labels.into()), seid, pdr(1, true), far(1, true));
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
        .with_pdn_type(Raw(vec![0x01].into()))
        .with_apn_dnn(Raw(b"\x08internet".to_vec().into()))
        .with_s_nssai(Raw(vec![0x01, 0x00, 0x00, 0x01].into()))
        .with_user_id(Raw(vec![0x01, 0x08, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0xf1].into()));
    let message = Message { header: Header::session(0, 7), body: Body::SessionEstablishmentRequest(request) };
    message.encode().unwrap()
}

/// The messages of the measurements, by name.
pub fn messages() -> Vec<(&'static str, Vec<u8>)> {
    let mut messages = vec![
        ("heartbeat", hex::decode("200100251122330000600004dfd52c0000c00015037f00000120010000000000000000000000000001").unwrap()),
        ("ser-4", establishment(4)),
        ("ser-16", establishment(16)),
    ];
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
pub fn read(message: &Message<'_>) -> u64 {
    let mut sum = u64::from(message.header.sequence);
    let octets = |octets: &[u8]| octets.len() as u64 + u64::from(octets.first().copied().unwrap_or(0));
    let raw = |raw: &[RawIe<'_>]| raw.iter().map(|ie| u64::from(ie.ie_type) + octets(&ie.octets)).sum::<u64>();
    let f_teid = |f: &FTeid<'_>| u64::from(f.teid.unwrap_or(0)) + u64::from(f.ch) + f.ipv4.map_or(0, |a| u64::from(a.to_bits()));
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
            sum += pdr.outer_header_removal.as_ref().map_or(0, |r| octets(&r.0));
            if let Some(pdi) = &pdr.pdi {
                sum += pdi.source_interface.as_ref().map_or(0, |s| u64::from(s.spare));
                sum += pdi.local_f_teid.as_ref().map_or(0, f_teid);
                sum += pdi.network_instance.as_ref().map_or(0, |n| octets(&n.0));
                sum += pdi.ue_ip_address.iter().map(|u| u.ipv4.map_or(0, |a| u64::from(a.to_bits()))).sum::<u64>();
                sum += pdi.sdf_filter.iter().map(|f| octets(&f.0)).sum::<u64>();
                sum += pdi.qfi.iter().map(|q| octets(&q.0)).sum::<u64>();
                sum += raw(&pdi.raw);
            }
            sum += raw(&pdr.raw);
        }
        sum += request.create_far.iter().map(|f| octets(&f.0)).sum::<u64>();
        sum += request.create_urr.iter().map(|u| octets(&u.0)).sum::<u64>();
        sum += request.create_qer.iter().map(|q| octets(&q.0)).sum::<u64>();
        for field in [&request.pdn_type.as_ref().map(|r| &r.0[..]), &request.apn_dnn.as_ref().map(|r| &r.0[..])] {
            sum += field.map_or(0, octets);
        }
        sum += request.s_nssai.as_ref().map_or(0, |r| octets(&r.0));
        sum += request.user_id.as_ref().map_or(0, |r| octets(&r.0));
        sum += raw(&request.raw);
    }
    sum
}

/// The IEs of a message, depth first, framed and not decoded: the length of each.
pub fn frame(octets: &[u8]) -> u64 {
    fn walk(ies: framing::Ies<'_>) -> u64 {
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
