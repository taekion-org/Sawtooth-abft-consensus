extern crate hbbft;
extern crate rand;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate crypto;
extern crate hex;

use std::env;
use std::collections::BTreeMap;
use hbbft::crypto::{SecretKey, PublicKey, PublicKeySet, SecretKeyShare};
use hbbft::crypto::serde_impl::SerdeSecret;
use hbbft::{to_pub_keys, NetworkInfo, PubKeyMap};
use rand::{rngs::OsRng, Rng};

type PeerId = Vec<u8>;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let node_ids: Vec<PeerId> = args.iter().map(|e| hex::decode(e).expect("hex decode")).collect();

    let mut rng = OsRng::new().expect("Could not initialize OS random number generator.");

    // Generate keys for signing and encrypting messages, and for threshold cryptography.
    let sec_keys: BTreeMap<_, SecretKey> = node_ids.iter().map(|id| (id, rng.gen())).collect();
    let mut pub_keys: BTreeMap<PeerId, PublicKey> = BTreeMap::new();
    for (key, value) in sec_keys {
        pub_keys.insert(key.clone(), value.public_key());
    }
    //let pub_keys: PubKeyMap<PeerId> = to_pub_keys(&sec_keys);
    let netinfos = NetworkInfo::generate_map(pub_keys.keys().cloned(), &mut rng)
        .expect("Failed to create `NetworkInfo` map");

    for (node, info) in netinfos.iter() {
        let sec_share = serde_json::to_string(&SerdeSecret(info.secret_key_share().expect("key share"))).expect("json key share");
        let pkey = serde_json::to_string(info.public_key_set()).expect("pkset json");

        println!("\"{}\":{{\"sec_key_share\":{},\"pkset\":{}}}", hex::encode(&node), sec_share, pkey);
    }
}