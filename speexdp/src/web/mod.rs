use std::{
    fmt::Display,
    net::Ipv4Addr,
    sync::{Arc, RwLock},
};

use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        HashMap,
    },
    programs::{Program, Xdp, XdpFlags},
    Bpf,
};
use futures::TryStreamExt;
use log::{debug, trace};
use poem::{
    error::InternalServerError, listener::TcpListener, middleware::AddData, web::Data, EndpointExt,
    Result, Route,
};
use poem_openapi::{param::Path, payload::Json, OpenApi, OpenApiService};
use rtnetlink::{packet::rtnl::link::nlas::Nla, Handle};
use speexdp_common::RuleDefinition;

use self::api::{
    ApiTags, InterfaceList, IpAddress, Program as ApiProgram, ProgramList, ResponseObject, Rule,
    RuleRequest,
};

mod api;

#[derive(Debug)]
struct GenericError(&'static str);

impl std::error::Error for GenericError {}

impl Display for GenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

struct Api;

#[OpenApi]
impl Api {
    /// Create a new rule
    #[oai(path = "/rule", method = "put", tag = "ApiTags::Rule")]
    async fn rule(
        &self,
        bpf: Data<&Arc<RwLock<Bpf>>>,
        body: RuleRequest,
    ) -> Result<Json<ResponseObject>> {
        let payload = match body {
            RuleRequest::Json(payload) => payload,
        };
        let payload = &*payload;

        let (start_port, end_port) = (
            payload.start_port.unwrap_or(0),
            payload.end_port.unwrap_or(u16::MAX),
        );
        let prefix = payload.subnet_mask.unwrap_or_else(|| payload.ip.len());

        match payload.ip {
            IpAddress::IPv4(ip) => {
                let mut bpf = bpf.write().unwrap();
                let mut ipv4_rules: LpmTrie<_, u32, RuleDefinition> =
                    LpmTrie::try_from(bpf.map_mut("IPV4_RULES").ok_or(InternalServerError(
                        GenericError("failed to get ipv4_rules map"),
                    ))?)
                    .map_err(InternalServerError)?;

                let enabled = true;
                let ip_be = <Ipv4Addr as Into<u32>>::into(ip).to_be();
                let protocol = None;
                let action = payload.action.into();

                let rule = RuleDefinition {
                    enabled,
                    start_port,
                    end_port,
                    protocol,
                    action,
                };

                // Networking is done in big endian
                let key = Key::new(prefix, ip_be);
                ipv4_rules
                    .insert(&key, rule, 0)
                    .map_err(InternalServerError)?;

                debug!(
                    "Added rule to {:?} inbound from {}/{prefix} to destination ports {start_port}-{end_port}",
                    payload.action,
                    Ipv4Addr::from(ip),
                );
            }
            IpAddress::IPv6(_ip) => {
                todo!();
            }
        };

        Ok(Json(ResponseObject { msg: None }))
    }

    /// Remove an existing rule
    #[oai(path = "/rule", method = "delete", tag = "ApiTags::Rule")]
    async fn remove_rule(
        &self,
        bpf: Data<&Arc<RwLock<Bpf>>>,
        body: RuleRequest,
    ) -> Result<Json<ResponseObject>> {
        todo!();
    }

    /// Get a list of rules
    #[oai(path = "/rules", method = "get", tag = "ApiTags::Rule")]
    async fn rules(&self, bpf: Data<&Arc<RwLock<Bpf>>>) -> Result<Json<Vec<Rule>>> {
        trace!("getting list of rules");
        let bpf = bpf.read().unwrap();
        let ipv4_rules: LpmTrie<_, u32, RuleDefinition> = LpmTrie::try_from(
            bpf.map("IPV4_RULES")
                .ok_or(InternalServerError(GenericError(
                    "failed to get ipv4_rules map",
                )))?,
        )
        .map_err(InternalServerError)?;

        let key = Key::new(32, u32::from(Ipv4Addr::new(192,168,1,1)).to_be());
        if let Ok(_) = ipv4_rules.get(&key, 0) {
            debug!("Rule exists!");
        }

        ipv4_rules.keys().for_each(|k| {
            dbg!(Ipv4Addr::from(k.unwrap().data));
        });

        ipv4_rules.iter().for_each(|r| {
            let r = r.unwrap();
            dbg!(r.1);
        });

        // let block_rules: Vec<Rule> = ipv4_rules
        //     .iter()
        //     .map(|res| {
        //         debug!("Found a rule");
        //         let (ip, description) = res.expect("failed to iterate over map");

        //         Rule {
        //             ip: IpAddress::IPv4(Ipv4Addr::from(ip.to_le())),
        //             subnet_mask: None,
        //             start_port: Some(description.start_port),
        //             end_port: Some(description.end_port),
        //             action: api::RuleAction::Deny,
        //         }
        //     })
        //     .collect();

        trace!("got list of rules");

        Ok(Json(vec![]))
    }

    /// List all interfaces
    #[oai(path = "/interfaces", method = "get", tag = "ApiTags::Interface")]
    async fn interface_list(
        &self,
        netlink: Data<&Arc<RwLock<Handle>>>,
    ) -> Result<Json<InterfaceList>> {
        trace!("getting list of interfaces");
        let mut interfaces = vec![];

        let mut links = netlink.read().unwrap().link().get().execute();

        while let Some(msg) = links.try_next().await.map_err(InternalServerError)? {
            for nla in msg.nlas.into_iter() {
                if let Nla::IfName(name) = nla {
                    interfaces.push(name);
                }
            }
        }

        Ok(Json(InterfaceList { interfaces }))
    }

    /// List programs that are available
    #[oai(path = "/programs", method = "get", tag = "ApiTags::Program")]
    async fn program_list(&self, bpf: Data<&Arc<RwLock<Bpf>>>) -> Result<Json<ProgramList>> {
        let programs: Vec<ApiProgram> = bpf
            .read()
            .unwrap()
            .programs()
            .map(|(name, _)| name.try_into().unwrap())
            .collect();

        Ok(Json(ProgramList { programs }))
    }

    /// Unload a program
    #[oai(path = "/program/:name", method = "delete", tag = "ApiTags::Program")]
    async fn delete_program(
        &self,
        bpf: Data<&Arc<RwLock<Bpf>>>,
        name: Path<String>,
    ) -> Result<Json<ResponseObject>> {
        trace!("attempting to unload program {}", *name);

        let mut bpf = bpf.write().unwrap();

        let program = bpf.program_mut(&name).expect("unable to find program");

        match program {
            Program::Xdp(p) => p.unload().map_err(InternalServerError)?,
            _ => unimplemented!(),
        };

        debug!("Program {} unloaded", *name);
        Ok(Json(ResponseObject { msg: None }))
    }

    /// Load a program into the kernel
    #[oai(path = "/program/:name", method = "put", tag = "ApiTags::Program")]
    async fn load_program(
        &self,
        bpf: Data<&Arc<RwLock<Bpf>>>,
        name: Path<String>,
    ) -> Result<Json<ResponseObject>> {
        trace!("attempting to load program {}", *name);

        let mut bpf = bpf.write().unwrap();

        let program: &mut Xdp = bpf
            .program_mut(&name)
            .expect(&format!("unable to find program named \"{}\"", *name))
            .try_into()
            .map_err(InternalServerError)?;

        program.load().map_err(InternalServerError)?;
        debug!("Program {} loaded", *name);

        Ok(Json(ResponseObject { msg: None }))
    }

    /// Attach a program to a specific interface
    #[oai(
        path = "/program/:name/attach/:interface",
        method = "put",
        tag = "ApiTags::Program"
    )]
    async fn attach_to_interface(
        &self,
        bpf: Data<&Arc<RwLock<Bpf>>>,
        name: Path<String>,
        interface: Path<String>,
    ) -> Result<Json<ResponseObject>> {
        trace!(
            "attempting to attach program {} to interface {}",
            *name,
            *interface
        );

        let mut bpf = bpf.write().unwrap();

        let program: &mut Xdp = bpf
            .program_mut(&name)
            .expect(&format!("unable to find program named \"{}\"", *name))
            .try_into()
            .map_err(InternalServerError)?;

        // "failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE"
        program
            .attach(&interface, XdpFlags::default())
            .map_err(InternalServerError)?;

        debug!("Program {} attached to interface {}", *name, *interface);

        Ok(Json(ResponseObject { msg: None }))
    }

    /// Detach a program from a specific interface
    #[oai(
        path = "/program/:name/attach/:interface",
        method = "delete",
        tag = "ApiTags::Program"
    )]
    async fn detach_from_interface(
        &self,
        bpf: Data<&Arc<RwLock<Bpf>>>,
        name: Path<String>,
        interface: Path<String>,
    ) -> Json<ResponseObject> {
        trace!(
            "attempting to detach program {} to interface {}",
            *name,
            *interface
        );
        todo!();
        // let mut bpf = bpf.write().unwrap();

        // let program: &mut Xdp = bpf
        //     .program_mut(&name)
        //     .expect(&format!("unable to find program named \"{}\"", *name))
        //     .try_into()
        //     .expect("could not create program");

        // program.detach(&interface, XdpFlags::default())
        // .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE").unwrap();

        // Json(ResponseObject { msg: None })
    }
}

pub async fn run(bpf: Bpf, netlink: Handle) -> Result<(), std::io::Error> {
    let bpf = Arc::new(RwLock::new(bpf));
    let bpf_data = AddData::new(bpf);

    let netlink = Arc::new(RwLock::new(netlink));
    let netlink_data = AddData::new(netlink);

    let api_service =
        OpenApiService::new(Api, "SpeeXDP Rest API", "1").server("http://localhost:3000/api/v1");
    let ui = api_service.openapi_explorer();

    let app = Route::new()
        .nest("/api/v1", api_service)
        .nest("/api", ui)
        .with(bpf_data)
        .with(netlink_data);

    poem::Server::new(TcpListener::bind("127.0.0.1:3000"))
        .run(app)
        .await
}
