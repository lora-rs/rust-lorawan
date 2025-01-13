use lorawan::keys::{CryptoFactory, McKEKey};
pub use lorawan::parser::MulticastAddr;
pub use lorawan::{
    keys::{McAppSKey, McKey, McNetSKey, McRootKey},
    multicast::Session,
};

pub(crate) type Result<T = ()> = core::result::Result<T, Error>;

const DEFAULT_MC_PORT: u8 = 200;

#[derive(Debug)]
pub enum Error {
    NoAvailableSlotForSession,
}

pub(crate) struct Multicast {
    pub(crate) mc_root_key: McRootKey,
    pub(crate) mc_k_e_key: McKEKey,
    port: u8,
    pub sessions: [Option<Session>; 4],
}

impl Multicast {
    pub fn new<F: CryptoFactory>(crypto: &F, mc_root_key: McRootKey) -> Self {
        let mc_k_e_key = McKEKey::derive_from(crypto, &mc_root_key);
        Self { mc_root_key, mc_k_e_key, port: DEFAULT_MC_PORT, sessions: [None, None, None, None] }
    }

    pub(crate) fn set_port(&mut self, port: u8) {
        self.port = port;
    }

    pub(crate) fn port(&self) -> u8 {
        self.port
    }

    pub(crate) fn matching_session(
        &mut self,
        multicast_addr: MulticastAddr<&[u8]>,
    ) -> Option<&mut Session> {
        self.sessions.iter_mut().find_map(|s| {
            if let Some(s) = s {
                println!(
                    "s.multicast_addr(): = {:?} =? multicast_addr: {:?}",
                    s.multicast_addr(),
                    multicast_addr
                );
                if s.multicast_addr() == multicast_addr {
                    return Some(s);
                }
            }
            None
        })
    }

    pub(crate) fn add_session(
        &mut self,
        multicast_addr: MulticastAddr<[u8; 4]>,
        mc_net_skey: McNetSKey,
        mc_app_skey: McAppSKey,
    ) -> Result {
        for i in 0..self.sessions.len() {
            if self.sessions[i].is_none() {
                self.sessions[i] =
                    Some(Session::new(multicast_addr, mc_net_skey, mc_app_skey, 0, 0));
                return Ok(());
            }
        }
        Err(Error::NoAvailableSlotForSession)
    }
}
