use std::fmt::{self};
use std::sync::Arc;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time;
use std::collections::{HashMap};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hex;
use std::fs::File;
use std::io::prelude::*;

use bincode;

use sawtooth_sdk::consensus::{engine::*, service::Service};

use hbbft::broadcast::Broadcast;
use hbbft::subset::{Subset};
use hbbft::{NetworkInfo};
use hbbft::threshold_sign::ThresholdSign;
use hbbft::crypto::{SecretKeyShare, PublicKeySet};

use crate::timing::Timeout;

#[derive(Debug, Deserialize)]
pub struct KeyInfo {
    sec_key_share: SecretKeyShare,
    pkset: PublicKeySet,
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct OfferPacket {
    offer_id: Vec<u8>,
    summary: Vec<u8>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
struct ABFTPacket {
    seq_num: u64,
    msg_type: String,
    bytes: Vec<u8>,
}

#[derive(Default, Clone)]
struct LoggedPacket {
    peer: PeerId,
    packet: ABFTPacket
}

impl fmt::Display for ABFTPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ABFTPackett(SeqNum[{}] Bytes[{}])", self.seq_num, hex::encode(&self.bytes))
    }
}

#[derive(PartialEq, Debug)]
enum ServiceState {
    Startup,
    Initializing,
    SelectingBlock,
    VoteReady,
    SeekingAgreement,
    Signing,
    AwaitingCommit,
    Finishing,
}

pub struct ABFTService {
    service: Box<dyn Service>,
    local_peer_id: PeerId,
    state: ServiceState,
    block_cycle_timeout: Timeout, // Time from a finalized commit -> finalized commit, max
    vote_broadcast: Option<Broadcast<PeerId>>,
    validators: Vec<PeerId>,
    pending_msgs: Vec<LoggedPacket>,
    offer_summary: Vec<u8>,
    our_offer: Vec<u8>,
    selected_offer: Vec<u8>,
    current_seq_num: u64,
    key_info: KeyInfo,
    netinfo: Option<NetworkInfo<PeerId>>,
    tsign: Option<ThresholdSign<PeerId>>,
    subset: Option<Subset<PeerId, u64>>,
    offers: Vec<(PeerId, Vec<u8>)>,
}

impl ABFTService {
    pub fn new(service: Box<dyn Service>, local_peer_id: PeerId, key_info: KeyInfo) -> Self {
        ABFTService {
            service,
            local_peer_id,
            state: ServiceState::Startup,
            block_cycle_timeout: Timeout::new(time::Duration::from_secs(10)),
            vote_broadcast: None,
            validators: vec![],
            pending_msgs: vec![],
            offer_summary: vec![],
            our_offer: vec![],
            selected_offer: vec![],
            current_seq_num: 0,
            key_info,
            netinfo:None,
            tsign:None,
            subset:None,
            offers:vec![],
        }
    }

    fn add_pending_msg(&mut self, peer:PeerId, packet: ABFTPacket) {
        let find_res = self.pending_msgs.iter().position(|lp| lp.packet.seq_num == packet.seq_num && lp.packet.msg_type == packet.msg_type && lp.peer == peer);
        if  find_res.is_some() {
            self.pending_msgs.remove(find_res.unwrap());
        }
        self.pending_msgs.push(LoggedPacket{peer, packet});
    }

    fn load_settings(&mut self, block_id:BlockId) {
        let results = self.service.get_settings(block_id, vec![String::from("sawtooth.consensus.abft.members")]);
        if results.is_err() {
            panic!("Could not retrieve the settings");
        }

        let settings = results.unwrap();
        self.validators = get_members_from_settings(&settings);
        self.netinfo = Some(NetworkInfo::new(self.local_peer_id.clone(), self.key_info.sec_key_share.clone(), self.key_info.pkset.clone(), &self.validators));
    }

    #[allow(clippy::ptr_arg)]
    fn get_block(&mut self, block_id: &BlockId) -> Block {
        debug!("Getting block {}", hex::encode(&block_id));
        self.service
            .get_blocks(vec![block_id.clone()])
            .expect("Failed to get block")
            .remove(block_id)
            .unwrap()
    }

    // Wraps in a consistent information packet
    fn send_to(&mut self, peer: &PeerId, msg_type: &str, bytes: Vec<u8>) -> Result<(), Error> {
        let packet = ABFTPacket{
            seq_num:self.current_seq_num+1,
            msg_type:String::from(msg_type),
            bytes
        };

        let payload = bincode::serialize(&packet).map_err(|_e| Error::EncodingError(String::from("send_to payload")))?;
        self.add_pending_msg(self.local_peer_id.clone(), packet);
        return self.service.send_to(peer, msg_type, payload);
    }

    fn initialize_block(&mut self) {
        debug!("Initializing block");
        self.state = ServiceState::Initializing;
        match self.service.cancel_block() {
            Ok(_) => {},
            Err(e) => error!("Error canceling block {}", e),
        }
        match self.service.initialize_block(None) {
            Ok(_) => {
                // TODO:  Check our assumption that everyone will start around the same time
                self.block_cycle_timeout.start();
                self.state = ServiceState::SelectingBlock
            },
            Err(e) => error!("Error from intialize {}", e),
        }
    }

    fn get_potential_block(&mut self) -> Result<(), Error> {
        trace!("Getting our potential block");
        let summary = self.service.summarize_block()?;

        debug!("Block summary: {}", hex::encode(&summary));

        // TODO:  For now we mix in our peer id to force some randomness into the block ordering
        let mut sha = Sha256::new();
        sha.input(&summary);
        sha.input(&self.local_peer_id);
        let hash: &mut [u8] = &mut [0; 32];
        sha.result(hash);

        debug!("Offered hash {}", hex::encode(&hash));

        let vec_res = Vec::from(hash);
        self.offer_summary = summary.clone();
        
        let offer_packet = OfferPacket{
            offer_id: vec_res,
            summary: summary,
        };

        self.our_offer = bincode::serialize(&offer_packet).map_err(|e| Error::EncodingError(e.to_string()))?;
        let mut ss = Subset::new(Arc::new(self.netinfo.clone().unwrap()), 0).map_err(|_e| Error::InvalidState(String::from("Couldn't start a subset")))?;
        let steps = ss.propose(self.our_offer.clone()).map_err(|e| Error::SendError(e.to_string()))?;
        self.send_subset_messages(&steps)?;
        self.subset = Some(ss);

        self.state = ServiceState::SeekingAgreement;

        let early_msgs = self.pending_msgs.iter()
            .filter(|lp| lp.peer != self.local_peer_id && lp.packet.seq_num == (self.current_seq_num + 1) && lp.packet.msg_type == "subset").cloned().collect::<Vec<_>>();
        debug!("Handling {} early messages for subset", early_msgs.len());
        for em in early_msgs {
            self.handle_subset_message(&em.peer, &em.packet)?;
            if self.state == ServiceState::Signing {
                break;
            }
        }

        Ok(())
    }

    fn check_block(&mut self, block_id: BlockId) {
        debug!("Checking block {}", hex::encode(&block_id));
        self.service
            .check_blocks(vec![block_id])
            .expect("Failed to check block");
    }

    fn commit_block(&mut self, block_id: BlockId) {
        debug!("Committing block {}", hex::encode(&block_id));
        self.service
            .commit_block(block_id)
            .expect("Failed to commit block");
    }

    fn cancel_block(&mut self) {
        debug!("Canceling block");
        match self.service.cancel_block() {
            Ok(_) => {}
            Err(Error::InvalidState(_)) => {}
            Err(err) => {
                panic!("Failed to cancel block: {:?}", err);
            }
        };
    }

    fn sign_and_send(&mut self, data:&Vec<u8>) -> Result<(), Error> {

        let ni_arc = Arc::new(self.netinfo.clone().unwrap());
        let mut tsign = ThresholdSign::new_with_document(ni_arc, data).expect("Could not build a thresold signature object");
        
        let tsign_steps = tsign.sign().expect("signature busted");
        self.send_tsign_messages(&tsign_steps)?;
        self.tsign = Some(tsign);

        let early_msgs = self.pending_msgs.iter()
            .filter(|lp| lp.peer != self.local_peer_id && lp.packet.seq_num == (self.current_seq_num + 1) && lp.packet.msg_type == "tsign").cloned().collect::<Vec<_>>();
        debug!("Handling {} early messages for tsign", early_msgs.len());
        for em in early_msgs {
            self.handle_tsign_message(&em.peer, &em.packet)?;
        }

        self.state = ServiceState::Signing;

        Ok(())
    }

    fn handle_tsign_message(&mut self, from_id: &PeerId, packet:&ABFTPacket) -> Result<(), Error> {
        if self.tsign.is_none() {
            error!("Received a sign but we aren't ready");
            return Err(Error::InvalidState(String::from("We didn't start our signing process yet")));
        }

        let hbmsg: hbbft::threshold_sign::Message = bincode::deserialize(&packet.bytes).expect("deser error");
        let steps = self.tsign.as_mut().expect("handle_message").handle_message(from_id, hbmsg).expect("handle steps");
        self.send_tsign_messages(&steps)?;

        if steps.output.is_empty() {
            return Ok(());
        }

        info!("threshold sign is done {}", hex::encode(bincode::serialize(steps.output.first().unwrap()).expect("")));

        if self.selected_offer == self.our_offer {
            info!("We're the lead, committing!");
            let signature = steps.output.first().ok_or(Error::EncodingError(String::from("Coudl not build signature")))?;
            self.service.finalize_block(bincode::serialize(&signature).map_err(|_e|
                Error::EncodingError(String::from("Could not serialzie signature")))?)?;
        }

        self.state = ServiceState::AwaitingCommit;

        Ok(())
    }

    fn handle_subset_message(&mut self, from_id: &PeerId, packet:&ABFTPacket) -> Result<(), Error> {
        if self.subset.is_none() {
            error!("Received a subset but we aren't ready");
            return Err(Error::InvalidState(String::from("We didn't start our subset process yet")));
        }

        // Get our data out, and process via the subset methods.  Convert all errors to our type.
        let hbmsg: hbbft::subset::Message<PeerId> = bincode::deserialize(&packet.bytes).map_err(|e| Error::EncodingError(e.to_string()))?;
        let steps = self.subset.as_mut().expect("subset handler").handle_message(from_id, hbmsg).map_err(|e| Error::EncodingError(e.to_string()))?;
        self.send_subset_messages(&steps)?;

        if steps.output.is_empty() {
            return Ok(());
        }

        debug!("Output is done: {:?}", steps.output);
        
        use hbbft::subset::SubsetOutput::*;

        for entry in steps.output {
            match entry {
                Contribution(peer, offer) => {
                    self.offers.push((peer, offer));
                },
                Done => {
                    // This is our "vote" logic.  This could be expanded in many different directions
                    // to support specific use cases, and more clear fairness metrics.
                    debug!("Done with all data: {:?}", self.offers);
                    self.offers.sort_by_key(|o| hex::encode(&o.1));
                    debug!("Offers:");
                    for offer in &self.offers {
                        debug!("\t{:}: {:}", hex::encode(&offer.0), hex::encode(&offer.1));
                    }
                    self.state = ServiceState::VoteReady;

                    let selected_offer = self.offers.first().ok_or(Error::InvalidState(String::from("No valid offer found")))?;
                    self.selected_offer = selected_offer.1.clone();
                }
            }
        }

        if !self.selected_offer.is_empty() {
            let op: OfferPacket = bincode::deserialize(&self.selected_offer).map_err(|e| Error::EncodingError(e.to_string()))?;
            self.sign_and_send(&op.summary)?;
        }

        Ok(())
    }

    fn send_subset_messages(&mut self, step: &hbbft::subset::Step<PeerId>) -> Result<(), Error> {
        for msg in step.messages.iter() {
            debug!("Doing subset message: {:?}", msg);

            let bytes = bincode::serialize(&msg.message).map_err(|e| {
                error!("Error serializing step: {}", e);
                return;
            }).unwrap();

            // TODO:  This clone is nonsense and needs a rework of the way we store validators to it's own struct
            for peerid in &self.validators.clone() {
                if msg.target.contains(peerid) {
                    let res = self.send_to(peerid, "subset", bytes.clone());
                    if let Err(e) = res {
                        error!("Failed to send subset step to {:?}: {}", hex::encode(&peerid), e);
                    }
                }
            }
        }
        Ok(())
    }

    fn send_tsign_messages(&mut self, step: &hbbft::threshold_sign::Step<PeerId>) -> Result<(), Error> {
        for msg in step.messages.iter() {
            debug!("Doing message: {:?}", msg);

            let bytes = bincode::serialize(&msg.message).map_err(|e| {
                error!("Error serializing step: {}", e);
                return;
            }).unwrap();

            // TODO:  This cloen is nonsense and needs a rework of the way we store validators to it's own struct
            for peerid in &self.validators.clone() {
                if msg.target.contains(peerid) {
                    let res = self.send_to(peerid, "tsign", bytes.clone());
                    if let Err(e) = res {
                        error!("Failed to send broadcast step to {:?}: {}", hex::encode(&peerid), e);
                    }
                }
            }
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.state = ServiceState::Initializing;
        self.our_offer.clear();
        self.offer_summary.clear();
        self.selected_offer.clear();
        self.our_offer.clear();
        self.block_cycle_timeout.stop();
        self.vote_broadcast = None;
        self.tsign = None;
        self.subset = None;
        let cur_seq = self.current_seq_num;
        self.pending_msgs.retain(|lp| lp.packet.seq_num >= cur_seq);
        self.offers.clear();
    }

    fn check_timers(&mut self) {
        if self.block_cycle_timeout.check_expired() {
            warn!("Timer cycled in state {:?}", self.state);
            let save_seq = self.current_seq_num + 1;
            self.pending_msgs.retain(|lp| lp.packet.seq_num > save_seq);
            self.reset();
            return;
        }
    }

    fn handle_commit(&mut self, new_chain_head: BlockId) {              
        info!(
            "Chain head updated to {}, abandoning block in progress",
            hex::encode(&new_chain_head)
        );
        let block = self.get_block(&new_chain_head);
        
        self.current_seq_num = block.block_num;
        self.state = ServiceState::Finishing;

        self.cancel_block();

        self.reset();

        self.state = ServiceState::Initializing;
    }

    fn handle_block_new(&mut self, block: Block) {
        if self.state != ServiceState::AwaitingCommit {
            error!("Got a new block when we weren't expecting it! BlockId: {}", hex::encode(&block.block_id));
        }

        info!("BlockNew, checking consensus data: {}", DisplayBlock(&block));
        let res = bincode::deserialize::<hbbft::crypto::Signature>(&block.payload);
        match res {
            Err(e) => {
                error!("We got an error decoding the payload! {}", e);
            }
            Ok(sig) => {
                if self.key_info.pkset.public_key().verify(&sig, block.summary) {
                    debug!("The signature is valid!");
                } else {
                    panic!("The signature does not validate?!");
                }
            }
        }

        if block.block_num == 0 {
            warn!("Received genesis block; ignoring");
            return;
        }

        if self.selected_offer.len() == 0 {
            warn!("We are attempted to work on a block with no voted selection. Accepting it because the signature is valid.");
        }
        
        self.check_block(block.block_id);
    }

    fn handle_peer_message(&mut self, message: PeerMessage, peer_id: PeerId) -> Result<(), Error> {
        let packet: ABFTPacket = bincode::deserialize(&message.content).map_err(|_e| Error::EncodingError(String::from("deserialize packet")))?;
        info!("Got a peer message for seq {} type {}", packet.seq_num, message.header.message_type);
        self.add_pending_msg(peer_id, packet.clone());

        match ABFTMessage::from_str(message.header.message_type.as_ref())
            .unwrap()
        {
            ABFTMessage::TSign => {
                self.handle_tsign_message(&message.header.signer_id, &packet)?;
            }

            ABFTMessage::Subset => {
                self.handle_subset_message(&message.header.signer_id, &packet)?;
            }
        }

        Ok(())
    }

    fn handle_block_valid(&mut self, block_id: BlockId) {
        let block = self.get_block(&block_id);
        info!("BlockValid {}", DisplayBlock(&block));

        self.commit_block(block_id);
    }

    fn handle_peer_connected(&mut self, peerinfo: PeerInfo) {
        if self.state == ServiceState::Startup {
            self.state = ServiceState::Initializing;
        }
        info!("Peer connected: {}", hex::encode(&peerinfo.peer_id));
    }
}

pub struct ABFTEngine {
    config_path: String,
}

impl ABFTEngine {
    pub fn new(config_path:&str) -> Self {
        ABFTEngine {
            config_path: String::from(config_path)
        }
    }
}

impl Engine for ABFTEngine {
    #[allow(clippy::cognitive_complexity)]
    fn start(
        &mut self,
        updates: Receiver<Update>,
        service: Box<dyn Service>,
        startup_state: StartupState,
    ) -> Result<(), Error> {
        let mut file = File::open(&self.config_path).map_err(|_e| Error::EncodingError(String::from("key config file")))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|_e| Error::EncodingError(String::from("key config file data")))?;

        // Knowingly blow up on bad key info
        let key_info: KeyInfo = serde_json::from_str(&contents).unwrap();
        debug!("We got the keys: {:?}", key_info);

        let mut service = ABFTService::new(service, startup_state.local_peer_info.peer_id.clone(), key_info);

        info!("Starting, local peer id: {}", hex::encode(&service.local_peer_id));
        service.load_settings(startup_state.chain_head.block_id);
        if startup_state.peers.len() > 0 {
            service.state = ServiceState::Initializing;
        }
        service.current_seq_num = startup_state.chain_head.block_num;

        loop {
            let incoming_message = updates.recv_timeout(time::Duration::from_millis(10));

            match incoming_message {
                Ok(update) => {
                    debug!("Received message: {}", message_type(&update));

                    match update {
                        Update::Shutdown => {
                            break;
                        }
                        Update::PeerConnected(peerinfo) => service.handle_peer_connected(peerinfo),
                        Update::BlockNew(block) => service.handle_block_new(block),
                        Update::BlockValid(block_id) => service.handle_block_valid(block_id),
                        Update::BlockCommit(new_chain_head) => service.handle_commit(new_chain_head),
                        Update::PeerMessage(message, sender_id) => {
                            let res = service.handle_peer_message(message, sender_id);
                            if res.is_err() {
                                warn!("Issue handling a peer message: {}", res.err().unwrap());
                            }
                        }
                        _ => {}
                    }
                }

                Err(RecvTimeoutError::Disconnected) => {
                    error!("Disconnected from validator");
                    break;
                }

                Err(RecvTimeoutError::Timeout) => {}
            }

            service.check_timers();
            
            match service.state {
                ServiceState::Initializing => service.initialize_block(),
                ServiceState::SelectingBlock => {
                    match service.get_potential_block() {
                        Err(Error::BlockNotReady) => {
                            /* Do nothing, try again */
                        },
                        Err(e) => {
                            error!("Got an error retrieving the next block {:}", e);
                        },
                        Ok(_) => {
                            info!("We offered our block");
                        }
                    }
                }
                //ServiceState::VoteReady => service.start_vote(),
                _ => { }
            }
        }

        Ok(())
    }

    fn version(&self) -> String {
        "1.0".into()
    }

    fn name(&self) -> String {
        "abft".into()
    }

    fn additional_protocols(&self) -> Vec<(String, String)> {
        vec![]
    }
}

struct DisplayBlock<'b>(&'b Block);

impl<'b> fmt::Display for DisplayBlock<'b> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Block(")?;
        f.write_str(&self.0.block_num.to_string())?;
        write!(f, ", id: {}", hex::encode(&self.0.block_id))?;
        write!(f, ", prev: {})", hex::encode(&self.0.previous_id))
    }
}

fn message_type(update: &Update) -> &str {
    match *update {
        Update::PeerConnected(_) => "PeerConnected",
        Update::PeerDisconnected(_) => "PeerDisconnected",
        Update::PeerMessage(..) => "PeerMessage",
        Update::BlockNew(_) => "BlockNew",
        Update::BlockValid(_) => "BlockValid",
        Update::BlockInvalid(_) => "BlockInvalid",
        Update::BlockCommit(_) => "BlockCommit",
        Update::Shutdown => "Shutdown",
    }
}

pub enum ABFTMessage {
    TSign,
    Subset,
}

impl FromStr for ABFTMessage {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tsign" => Ok(ABFTMessage::TSign),
            "subset" => Ok(ABFTMessage::Subset),
            _ => Err("Invalid message type"),
        }
    }
}

fn get_members_from_settings<S: std::hash::BuildHasher>(
    settings: &HashMap<String, String, S>,
) -> Vec<PeerId> {
    let members_setting_value = settings
        .get("sawtooth.consensus.abft.members")
        .expect("'sawtooth.consensus.abft.members' is empty; this setting must exist to use ABFT");

    debug!("Settings value {}", members_setting_value);

    let members: Vec<String> = serde_json::from_str(members_setting_value).unwrap_or_else(|err| {
        panic!(
            "Unable to parse value at 'sawtooth.consensus.abft.members' due to error: {:?}",
            err
        )
    });

    for member in &members {
        debug!("Member: {}", member);
    }

    members
        .into_iter()
        .map(|s| {
            hex::decode(s).unwrap_or_else(|err| {
                panic!("Unable to parse PeerId from string due to error: {:?}", err)
            })
        })
        .collect()
}