use crate::keys::{CryptoFactory, McAppSKey, McKEKey, McKey, McNetSKey};
use crate::{
    keys::{AppSKey, Encrypter, NwkSKey},
    multicast::{McGroupSetupAnsPayload, McGroupSetupReqPayload},
    parser::MulticastAddr,
};

#[derive(Debug)]
pub struct Session {
    multicast_addr: MulticastAddr<[u8; 4]>,
    mc_net_s_key: McNetSKey,
    mc_app_s_key: McAppSKey,
    pub fcnt_down: u32,
    max_fcnt_down: u32,
}

impl Session {
    pub fn new(
        multicast_addr: MulticastAddr<[u8; 4]>,
        mc_net_s_key: McNetSKey,
        mc_app_s_key: McAppSKey,
        fcnt_down: u32,
        max_fcnt_down: u32,
    ) -> Self {
        Self { multicast_addr, mc_net_s_key, mc_app_s_key, fcnt_down, max_fcnt_down }
    }
    pub fn multicast_addr(&self) -> MulticastAddr<[u8; 4]> {
        self.multicast_addr
    }
    pub fn mc_net_s_key(&self) -> McNetSKey {
        self.mc_net_s_key
    }
    pub fn mc_app_s_key(&self) -> McAppSKey {
        self.mc_app_s_key
    }

    pub fn fcnt_down(&self) -> u32 {
        self.fcnt_down
    }
}

impl McGroupSetupReqPayload<'_> {
    /*
     | McGroupIDHeader |  McAddr |   McKey_encrypted | minMcFCount | maxMcFCount |
     |       1         |    4    |         16        |   4         |     4       |
    */
    pub fn mc_group_id_header(&self) -> u8 {
        self.0[0]
    }

    pub fn mc_addr(&self) -> MulticastAddr<&[u8]> {
        const OFFSET: usize = 1;
        const END: usize = OFFSET + MulticastAddr::<&[u8]>::byte_len();
        MulticastAddr::new_from_raw(&self.0[OFFSET..END])
    }

    pub(crate) fn mc_key_encrypted(&self) -> &[u8] {
        const OFFSET: usize = 1 + MulticastAddr::<&[u8]>::byte_len();
        const END: usize = OFFSET + McKey::byte_len();
        &self.0[OFFSET..END]
    }

    fn mc_key_decrypted<F: CryptoFactory>(&self, crypto: &F, key: &McKEKey) -> McKey {
        let aes_enc = crypto.new_enc(&key.0);
        let mut bytes: [u8; 16] = self.mc_key_encrypted().try_into().unwrap();
        aes_enc.encrypt_block(&mut bytes);
        McKey::from(bytes)
    }

    pub fn derive_session_keys<F: CryptoFactory>(
        &self,
        crypto: &F,
        key: &McKEKey,
    ) -> (McAppSKey, McNetSKey) {
        let mc_key = self.mc_key_decrypted(crypto, key);
        let mc_addr = self.mc_addr();
        (mc_key.derive_mcappskey(crypto, &mc_addr), mc_key.derive_mcnetskey(crypto, &mc_addr))
    }

    pub fn derive_session<F: CryptoFactory>(&self, crypto: &F, key: &McKEKey) -> Session {
        let (mc_app_s_key, mc_net_s_key) = self.derive_session_keys(crypto, key);
        Session {
            multicast_addr: self.mc_addr().to_owned(),
            mc_net_s_key,
            mc_app_s_key,
            fcnt_down: self.min_mc_fcount(),
            max_fcnt_down: self.max_mc_fcount(),
        }
    }

    /// `minMcFCount` is the next frame counter value of the multicast downlink to be sent by the
    /// server for this group
    pub fn min_mc_fcount(&self) -> u32 {
        const OFFSET: usize = 1 + MulticastAddr::<&[u8]>::byte_len() + McKey::byte_len();
        u32::from_le_bytes([
            self.0[OFFSET],
            self.0[OFFSET + 1],
            self.0[OFFSET + 2],
            self.0[OFFSET + 3],
        ])
    }

    /// `maxMcFCount` specifies the life time of this multicast group expressed as a maximum number
    /// of frames. The end-device will only accept a multicast downlink frame if the 32-bits frame
    /// counter value minMcFCount ≤ McFCount < maxMcFCount.
    pub fn max_mc_fcount(&self) -> u32 {
        const OFFSET: usize =
            1 + MulticastAddr::<&[u8]>::byte_len() + McKey::byte_len() + size_of::<u32>();
        println!("{}", OFFSET + 3);
        u32::from_le_bytes([
            self.0[OFFSET],
            self.0[OFFSET + 1],
            self.0[OFFSET + 2],
            self.0[OFFSET + 3],
        ])
    }
}
