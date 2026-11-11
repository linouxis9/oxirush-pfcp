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
