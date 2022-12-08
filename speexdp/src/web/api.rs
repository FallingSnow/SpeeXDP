use std::{net::{Ipv4Addr, Ipv6Addr}, fmt::Display};

use poem_openapi::{payload::Json, ApiRequest, Enum, Object, Union, Tags};

#[derive(Tags)]
pub enum ApiTags {
    Rule,
    Program,
    Interface
}

#[derive(Debug, Object, Eq, PartialEq)]
#[oai(rename_all = "camelCase")]
pub struct Rule {
    pub ip: IpAddress,
    /// Allows you to apply this rule to a range of IP addresses.
    pub subnet_mask: Option<u32>,
    pub start_port: Option<u16>,
    pub end_port: Option<u16>,
    pub action: RuleAction,
}

#[derive(Debug, Object, Eq, PartialEq)]
pub struct ResponseObject {
    pub msg: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Rules {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Object, Eq, PartialEq)]
pub struct ProgramList {
    pub programs: Vec<Program>,
}

#[derive(Debug, Object, Eq, PartialEq)]
pub struct InterfaceList {
    pub interfaces: Vec<String>,
}

#[derive(Debug, ApiRequest, Eq, PartialEq)]
pub enum RuleRequest {
    Json(Json<Rule>),
}

#[derive(Debug, Enum, Eq, PartialEq, Copy, Clone)]
#[oai(rename_all = "camelCase")]
pub enum RuleAction {
    Allow,
    Deny,
    Redirect,
}

impl From<speexdp_common::RuleAction> for RuleAction {
    fn from(value: speexdp_common::RuleAction) -> Self {
        match value {
            speexdp_common::RuleAction::Allow => RuleAction::Allow,
            speexdp_common::RuleAction::Deny => RuleAction::Deny,
            speexdp_common::RuleAction::Redirect => RuleAction::Redirect,
        }
    }
}

impl Into<speexdp_common::RuleAction> for RuleAction {
    fn into(self) -> speexdp_common::RuleAction {
        match self {
            RuleAction::Allow => speexdp_common::RuleAction::Allow,
            RuleAction::Deny => speexdp_common::RuleAction::Deny,
            RuleAction::Redirect => speexdp_common::RuleAction::Redirect,
        }
    }
}

#[derive(Debug, Union, Eq, PartialEq)]
#[oai(rename_all = "camelCase", one_of = true)]
/// IPv4 is a single u32. IPv6 should be an array containing exactly 4 u32's.
pub enum IpAddress {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
}

impl IpAddress {
    pub fn len(&self) -> u32 {
        match self {
            IpAddress::IPv4(_) => 32,
            IpAddress::IPv6(_) => 128,
        }
    }
}

#[derive(Debug, Enum, Eq, PartialEq)]
#[oai(rename_all = "lowercase")]
/// IPv4 is a single u32. IPv6 should be an array containing exactly 4 u32's.
pub enum Program {
    Firewall,
    Loadbalancer
}

impl Display for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Program::Firewall => f.write_str("firewall"),
            Program::Loadbalancer => f.write_str("loadbalancer")
        }
    }
}

impl TryFrom<&str> for Program {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "firewall" => Program::Firewall,
            "loadbalancer" => Program::Loadbalancer,
            _ => return Err(())
        })
    }
}