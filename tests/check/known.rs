//! What `check_with()` finds with what a message does not hold: the features that the two
//! functions announced.

use oxirush_pfcp::*;

/// The message `name` of `ies`.
fn message(name: &str, ies: tree::Value) -> Message {
    let header = match name.contains("Session") {
        true => tree!({"SEID": 1, "Sequence Number": 1}),
        false => tree!({"Sequence Number": 1}),
    };
    let written = tree!({"message": name, "header": header, "ies": ies});
    Message::from_tree(&written).unwrap_or_else(|error| panic!("{error}"))
}

/// What `check_with()` finds in `message` on N4 with `known`: the path, the clause and the
/// kind of each deviation.
fn told(message: &Message, known: &Known<'_>) -> Vec<(String, &'static str, DeviationKind)> {
    let found = message.check_with(Interfaces::N4, known).into_iter();
    found
        .map(|found| (found.path, found.clause, found.kind))
        .collect()
}

/// "This IE may be present if the UP function supports the NORP feature" (Table
/// 7.5.2.4-1): a Number of Reports is told where the UP function is known not to have
/// announced NORP, and not where it announced it, or where what it announced is not known.
#[test]
fn an_ie_of_a_feature_that_was_not_announced() {
    let urr = tree!({
        "URR ID": 1, "Measurement Method": {"EVENT": true}, "Reporting Triggers": {"PERIO": true},
        "Measurement Period": 60, "Number of Reports": 2,
    });
    let request = message(
        "PFCP Session Modification Request",
        tree!({"Create URR": [urr]}),
    );
    assert_eq!(request.check(Interfaces::N4), []);
    let none = UpFunctionFeatures::default();
    let norp = UpFunctionFeatures {
        norp: true,
        ..Default::default()
    };
    let excluded = DeviationKind::Excluded { ie_type: 182 };
    assert_eq!(
        told(&request, &Known::default().with_up_features(&none)),
        [(
            "/pfcp/Create URR/0/Number of Reports".to_string(),
            "7.5.2.4-1",
            excluded
        )]
    );
    assert_eq!(
        told(&request, &Known::default().with_up_features(&norp)),
        []
    );
    // The features of the CP function say nothing of those of the UP function
    let cp = CpFunctionFeatures::default();
    assert_eq!(told(&request, &Known::default().with_cp_features(&cp)), []);
}

/// "In the 5GC, several IEs with the same IE type may be present to represent multiple UE
/// IP addresses, if the UPF indicated support of the IP6PL feature" (Table 7.5.2.2-2): a
/// second UE IP address of a PDI is told without IP6PL, and one is not.
#[test]
fn several_ies_of_a_feature_that_was_not_announced() {
    let address = |last: u8| tree!({"V4": true, "IPv4 address": format!("10.0.0.{last}")});
    let pdr = |addresses: tree::Value| {
        tree!({"Create PDR": [{
            "PDR ID": 1, "Precedence": 1, "FAR ID": 1,
            "PDI": {"Source Interface": "Core", "UE IP address": addresses},
        }]})
    };
    let modification = "PFCP Session Modification Request";
    let two = message(modification, pdr(tree!([address(1), address(2)])));
    let one = message(modification, pdr(tree!([address(1)])));
    let none = UpFunctionFeatures::default();
    let ip6pl = UpFunctionFeatures {
        ip6pl: true,
        ..Default::default()
    };
    assert_eq!(two.check(Interfaces::N4), []);
    let repeated = DeviationKind::Repeated { ie_type: 93 };
    assert_eq!(
        told(&two, &Known::default().with_up_features(&none)),
        [(
            "/pfcp/Create PDR/0/PDI/UE IP address".to_string(),
            "7.5.2.2-2",
            repeated
        )]
    );
    assert_eq!(told(&two, &Known::default().with_up_features(&ip6pl)), []);
    assert_eq!(told(&one, &Known::default().with_up_features(&none)), []);
}

/// "This IE may be present if the (MB-)SMF advertises the support of the SSET and/or MPAS
/// feature in the CP Function Features IE" (Tables 7.4.4.1-1 to 7.4.4.3-1): the features
/// of an association setup are those of the message, which check() reads, and either of
/// the two has the IE there. An association update has its own where it changes them, and
/// those that are known otherwise.
#[test]
fn the_cp_features_of_an_association_message() {
    let setup = |features: Option<tree::Value>| {
        let mut ies = tree!({
            "Node ID": "10.0.0.1", "Recovery Time Stamp": 1,
            "Alternative SMF IP Address": [{"V4": true, "IPv4 Address": "10.0.0.2"}],
        });
        if let Some(features) = features {
            ies["CP Function Features"] = features;
        }
        let request = message("PFCP Association Setup Request", ies);
        told(&request, &Known::default())
    };
    let excluded = |table| {
        let kind = DeviationKind::Excluded { ie_type: 178 };
        [("/pfcp/Alternative SMF IP Address".to_string(), table, kind)]
    };
    assert_eq!(setup(None), excluded("7.4.4.1-1"));
    assert_eq!(setup(Some(tree!({"LOAD": true}))), excluded("7.4.4.1-1"));
    assert_eq!(setup(Some(tree!({"SSET": true}))), []);
    assert_eq!(setup(Some(tree!({"LOAD": true, "SSET": true}))), []);

    let update = |features: Option<tree::Value>, known: &Known<'_>| {
        let mut ies = tree!({
            "Node ID": "10.0.0.1",
            "Alternative SMF IP Address": [{"V4": true, "IPv4 Address": "10.0.0.2"}],
        });
        if let Some(features) = features {
            ies["CP Function Features"] = features;
        }
        told(&message("PFCP Association Update Request", ies), known)
    };
    let none = CpFunctionFeatures::default();
    let mpas = CpFunctionFeatures {
        mpas: true,
        ..Default::default()
    };
    assert_eq!(update(None, &Known::default()), []);
    assert_eq!(
        update(None, &Known::default().with_cp_features(&none)),
        excluded("7.4.4.3-1")
    );
    assert_eq!(update(None, &Known::default().with_cp_features(&mpas)), []);
    let load = Some(tree!({"LOAD": true}));
    assert_eq!(
        update(load, &Known::default().with_cp_features(&mpas)),
        excluded("7.4.4.3-1")
    );
}

/// What `check_with()` reports with `known` that `check()` does not.
fn more(message: &Message, known: &Known<'_>) -> Vec<(String, &'static str, DeviationKind)> {
    let alone = message.check(Interfaces::N4);
    let found = message.check_with(Interfaces::N4, known).into_iter();
    let found = found.filter(|found| !alone.contains(found));
    found
        .map(|found| (found.path, found.clause, found.kind))
        .collect()
}

/// The message `name` with `header` and `ies`.
fn message_of(name: &str, header: tree::Value, ies: tree::Value) -> Message {
    let written = tree!({"message": name, "header": header, "ies": ies});
    Message::from_tree(&written).unwrap_or_else(|error| panic!("{error}"))
}

const ESTABLISHMENT: &str = "PFCP Session Establishment Request";
const ESTABLISHED: &str = "PFCP Session Establishment Response";
const MODIFICATION: &str = "PFCP Session Modification Request";
const MODIFIED: &str = "PFCP Session Modification Response";

/// A Session Establishment Request with CP F-SEID 0x1001 and sequence number 7, and `more`
/// IEs.
fn establishment_with(more: tree::Value) -> Message {
    let mut ies = tree!({
        "Node ID": "10.0.0.1",
        "CP F-SEID": {"V4": true, "SEID": 0x1001, "IPv4 address": "10.0.0.1"},
    });
    for (name, value) in more.as_object().unwrap() {
        ies[name.as_str()] = value.clone();
    }
    message_of(ESTABLISHMENT, tree!({"SEID": 0, "Sequence Number": 7}), ies)
}

/// A response `name` with `cause`, SEID 0x1001, sequence number 7, and `more` IEs.
fn response_with(name: &str, cause: &str, more: tree::Value) -> Message {
    let mut ies = tree!({"Cause": cause});
    for (name, value) in more.as_object().unwrap() {
        ies[name.as_str()] = value.clone();
    }
    message_of(name, tree!({"SEID": 0x1001, "Sequence Number": 7}), ies)
}

const ACCEPTED: &str = "Request accepted (success)";
const REJECTED: &str = "No resources available";

/// A response has the message type that follows the type of its request (Table 7.3-1) and
/// "A Request and its Response message shall have the same Sequence Number value" (§6.4).
/// A Version Not Supported Response answers any request.
#[test]
fn the_type_and_the_sequence_number_of_a_response() {
    let request = establishment_with(tree!({}));
    let known = Known::default().with_request(&request);
    let rule =
        |path: &str, clause, rule| vec![(path.to_string(), clause, DeviationKind::Rule(rule))];

    let response = response_with(ESTABLISHED, REJECTED, tree!({}));
    assert_eq!(more(&response, &known), []);
    let modified = response_with(MODIFIED, REJECTED, tree!({}));
    let not_the_response = "the message is not the response to this request";
    assert_eq!(
        more(&modified, &known),
        rule("/message", "7.3", not_the_response)
    );
    // A request is not the response to a request
    assert_eq!(
        more(&request, &known),
        rule("/message", "7.3", not_the_response)
    );

    let header = tree!({"SEID": 0x1001, "Sequence Number": 8});
    let late = message_of(ESTABLISHED, header, tree!({"Cause": REJECTED}));
    let sequence = "the Sequence Number is not the one of the request";
    assert_eq!(
        more(&late, &known),
        rule("/header/Sequence Number", "6.4", sequence)
    );

    let version = message_of(
        "PFCP Version Not Supported Response",
        tree!({"Sequence Number": 7}),
        tree!({}),
    );
    assert_eq!(more(&version, &known), []);
}

/// "The Session Endpoint Identifier is set by the sending entity ... to the SEID value
/// provided by the corresponding receiving entity" (§7.2.2.4.1): a Session Establishment
/// Response has the SEID of the CP F-SEID of its request. A response that rejects the
/// request may have a SEID of 0 instead (§7.2.2.4.2).
#[test]
fn the_seid_of_an_establishment_response() {
    let request = establishment_with(tree!({}));
    let known = Known::default().with_request(&request);
    let response = |seid: u64, cause: &str| {
        let header = tree!({"SEID": seid, "Sequence Number": 7});
        more(
            &message_of(ESTABLISHED, header, tree!({"Cause": cause})),
            &known,
        )
    };
    let rule = DeviationKind::Rule("the SEID is not the one of the CP F-SEID of the request");
    let told = [("/header/SEID".to_string(), "7.2.2.4.1", rule)];
    assert_eq!(response(0x1001, ACCEPTED), []);
    assert_eq!(response(0x2002, ACCEPTED), told);
    assert_eq!(response(0, ACCEPTED), told);
    assert_eq!(response(0, REJECTED), []);
    assert_eq!(response(0x1001, REJECTED), []);
    assert_eq!(response(0x2002, REJECTED), told);
}

/// A Created PDR "shall be present if the cause is set to "success" and the UP function
/// was requested to allocate a local F-TEID or a UE IP address/prefix" (Table 7.5.3.1-1),
/// and holds what was allocated (Table 7.5.3.2-1): one for each PDR that asks.
#[test]
fn a_created_pdr_for_each_pdr_that_asks_for_an_allocation() {
    let pdr = |id: u16, pdi: tree::Value| {
        let mut pdr = tree!({"PDR ID": id, "Precedence": 1, "FAR ID": 1, "PDI": {"Source Interface": "Access"}});
        for (name, value) in pdi.as_object().unwrap() {
            pdr["PDI"][name.as_str()] = value.clone();
        }
        pdr
    };
    let choose = tree!({"Local F-TEID": {"CH": true, "V4": true}});
    let address = tree!({"UE IP address": [{"CHV4": true, "V4": true}]});
    let fixed = tree!({"Local F-TEID": {"V4": true, "TEID": 9, "IPv4 address": "10.0.0.2"}});
    let request =
        establishment_with(tree!({"Create PDR": [pdr(1, choose), pdr(2, fixed), pdr(3, address)]}));
    let known = Known::default().with_request(&request);
    let missing = |path: &str, clause, ie_type| {
        (
            path.to_string(),
            clause,
            DeviationKind::ConditionalMissing { ie_type },
        )
    };
    let teid = tree!({"V4": true, "TEID": 5, "IPv4 address": "10.0.0.2"});
    let created =
        |pdrs: tree::Value| response_with(ESTABLISHED, ACCEPTED, tree!({"Created PDR": pdrs}));

    // No Created PDR for PDR 1 nor for PDR 3; PDR 2 asked for nothing
    let none = response_with(ESTABLISHED, ACCEPTED, tree!({}));
    let absent = missing("/pfcp/Created PDR", "7.5.3.1-1", 8);
    assert_eq!(more(&none, &known), [absent.clone(), absent.clone()]);
    assert_eq!(more(&none, &Known::default()), []);
    // A response that rejects the request creates nothing
    assert_eq!(
        more(&response_with(ESTABLISHED, REJECTED, tree!({})), &known),
        []
    );
    // One for each, with what was asked
    let both = created(tree!([
        {"PDR ID": 3, "UE IP Address": [{"V4": true, "IPv4 address": "10.1.0.1"}]},
        {"PDR ID": 1, "F-TEID": [teid.clone()]},
    ]));
    assert_eq!(more(&both, &known), []);
    // One that lacks the F-TEID of PDR 1, and none for PDR 3
    let empty = created(tree!([{"PDR ID": 2, "F-TEID": [teid]}, {"PDR ID": 1}]));
    assert_eq!(
        more(&empty, &known),
        [
            missing("/pfcp/Created PDR/1/F-TEID", "7.5.3.2-1", 21),
            absent
        ]
    );
}

/// The same in a modification (Table 7.5.5.1-1): a Created PDR for a Create PDR, a
/// Created/Updated Traffic Endpoint for a Create or an Update Traffic Endpoint, and an
/// Updated PDR for an Update PDR, when each asks for an allocation.
#[test]
fn what_a_modification_response_returns_for_an_allocation() {
    let choose = tree!({"CH": true, "V4": true});
    let request = message_of(
        MODIFICATION,
        tree!({"SEID": 0x2001, "Sequence Number": 7}),
        tree!({
            "Create Traffic Endpoint": [{"Traffic Endpoint ID": 1, "Local F-TEID": choose.clone()}],
            "Update Traffic Endpoint": [{"Traffic Endpoint ID": 2, "UE IP address": [{"CHV6": true, "V6": true}]}],
            "Update PDR": [{"PDR ID": 4, "PDI": {"Source Interface": "Core", "UE IP address": [{"CHV6": true, "V6": true}]}}],
        }),
    );
    let known = Known::default().with_request(&request);
    let missing = |path: &str, clause, ie_type| {
        (
            path.to_string(),
            clause,
            DeviationKind::ConditionalMissing { ie_type },
        )
    };
    let none = response_with(MODIFIED, ACCEPTED, tree!({}));
    let endpoint = missing("/pfcp/Created~1Updated Traffic Endpoint", "7.5.5.1-1", 128);
    assert_eq!(
        more(&none, &known),
        [
            endpoint.clone(),
            endpoint,
            missing("/pfcp/Updated PDR", "7.5.5.1-1", 256)
        ]
    );
    let prefix = tree!({"V6": true, "IPv6 address": "2001:db8::"});
    let all = response_with(
        MODIFIED,
        ACCEPTED,
        tree!({
            "Created/Updated Traffic Endpoint": [
                {"Traffic Endpoint ID": 1, "F-TEID": [{"V4": true, "TEID": 5, "IPv4 address": "10.0.0.2"}]},
                {"Traffic Endpoint ID": 2},
            ],
            "Updated PDR": [{"PDR ID": 4, "UE IP Address": [prefix]}],
        }),
    );
    assert_eq!(
        more(&all, &known),
        [missing(
            "/pfcp/Created~1Updated Traffic Endpoint/1/UE IP Address",
            "7.5.3.5-1",
            93
        )]
    );
}

/// A Created Bridge/Router Info "shall be present if the UPF was requested to provide
/// Bridge/Router information" (Table 7.5.3.1-1), with its Port Number and its 5GS User
/// Plane Node ID "If the BII bit or the RII bit was set to "1" in the Create Bridge/Router
/// Info IE" (Table 7.5.3.6-1). With BII, the Port Number is an Unsigned16 and "Octets 5 and
/// 6 shall be set to all zeros" (§8.2.141).
#[test]
fn the_bridge_information_that_a_request_asks_for() {
    let request =
        |flag: &str| establishment_with(tree!({"Create Bridge/Router Info": {flag: true}}));
    let bridge = request("BII");
    let known = Known::default().with_request(&bridge);
    let missing = |path: &str, clause, ie_type| {
        (
            path.to_string(),
            clause,
            DeviationKind::ConditionalMissing { ie_type },
        )
    };
    let info = "/pfcp/Created Bridge~1Router Info";
    let none = response_with(ESTABLISHED, ACCEPTED, tree!({}));
    assert_eq!(more(&none, &known), [missing(info, "7.5.3.1-1", 195)]);
    let created = |info: tree::Value| {
        response_with(
            ESTABLISHED,
            ACCEPTED,
            tree!({"Created Bridge/Router Info": info}),
        )
    };
    let node = tree!({"octets": "000102"});
    // An IE of no length reads as an IE that is absent (§8.1.2)
    assert_eq!(
        more(&created(tree!({})), &known),
        [missing(info, "7.5.3.1-1", 195)]
    );
    assert_eq!(
        more(&created(tree!({"Port Number": 7})), &known),
        [missing(
            &format!("{info}/5GS User Plane Node ID"),
            "7.5.3.6-1",
            198
        )]
    );
    assert_eq!(
        more(
            &created(tree!({"5GS User Plane Node ID": node.clone()})),
            &known
        ),
        [missing(&format!("{info}/Port Number"), "7.5.3.6-1", 196)]
    );
    let whole = created(tree!({"Port Number": 7, "5GS User Plane Node ID": node.clone()}));
    assert_eq!(more(&whole, &known), []);
    let wide = created(tree!({"Port Number": 0x1_0000, "5GS User Plane Node ID": node}));
    let rule = DeviationKind::Rule("the Port Number of a bridge is more than 16 bits");
    assert_eq!(
        more(&wide, &known),
        [(format!("{info}/Port Number"), "8.2.141", rule)]
    );
    // A router has a Port Number of 32 bits
    let router = request("RII");
    assert_eq!(more(&wide, &Known::default().with_request(&router)), []);
}
