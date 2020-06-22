use std::fmt::{self, Write};
use std::sync::Arc;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time;
use std::collections::{BTreeMap, HashMap, HashSet};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hex;

use bincode::{deserialize, serialize};

use sawtooth_sdk::consensus::{engine::*, service::Service};

use hbbft::broadcast::Broadcast;
use hbbft::{ValidatorSet};

use crate::timing::Timeout;

#[derive(Default, Debug, Serialize, Deserialize)]
struct OfferPacket {
    offer_id: Vec<u8>,
    summary: Vec<u8>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct OfferedBlock {
    peer: PeerId,
    offer_id: Vec<u8>,
    summary: Vec<u8>,
}

impl fmt::Display for OfferedBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Offered(Peer[{}] OfferId[{}])", hex::encode(&self.peer), hex::encode(&self.offer_id))
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
struct ABFTPacket {
    seq_num: u64,
    msg_type: String,
    bytes: Vec<u8>,
}

struct LoggedPacket {
    peer: PeerId,
    packet: ABFTPacket
}

impl fmt::Display for ABFTPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ABFTPackett(SeqNum[{}] Bytes[{}])", self.seq_num, hex::encode(&self.bytes))
    }
}

#[derive(PartialEq)]
enum ServiceState {
    Startup,
    Initializing,
    SelectingBlock,
    FoundBlock,
    OfferedBlock,
    VoteReady,
    CheckingBlock,
    Voted,
    SeekingAgreement,
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
    selected_offer: Vec<u8>,
    current_seq_num: u64,
}

impl ABFTService {
    pub fn new(service: Box<dyn Service>, local_peer_id: PeerId) -> Self {
        ABFTService {
            service,
            local_peer_id,
            state: ServiceState::Startup,
            block_cycle_timeout: Timeout::new(time::Duration::from_secs(10)),
            vote_broadcast: None,
            validators: vec![],
            pending_msgs: vec![],
            selected_offer: vec![],
            current_seq_num: 0,
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
    }

    fn get_chain_head(&mut self) -> Block {
        debug!("Getting chain head");
        self.service
            .get_chain_head()
            .expect("Failed to get chain head")
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
    fn broadcast(&mut self, msg_type: &str, bytes: Vec<u8>) -> Result<(), Error> {
        let packet = ABFTPacket{
            seq_num:self.current_seq_num+1,
            msg_type:String::from(msg_type),
            bytes
        };

        let payload = bincode::serialize(&packet).map_err(|_e| Error::EncodingError(String::from("broadcast payload")))?;
        self.add_pending_msg(self.local_peer_id.clone(), packet);
        return self.service.broadcast(msg_type, payload);
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
        self.block_cycle_timeout.start();
        self.state = ServiceState::Initializing;
        match self.service.cancel_block() {
            Ok(_) => {},
            Err(e) => error!("Error canceling block {}", e),
        }
        match self.service.initialize_block(None) {
            Ok(_) => self.state = ServiceState::SelectingBlock,
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
        
        let offer_packet = OfferPacket{
            offer_id: Vec::from(hash),
            summary: summary,
        };

        match serialize(&offer_packet) {
            Ok(b) => {
                debug!("Sending our offer {}", hex::encode(&b));
                self.broadcast("offer", b)?;
            }
            Err(e) => {
                error!("Could not serialize the offer: {}", e);
                self.service.cancel_block()?;
                return Err(Error::EncodingError(String::from("serialize offer")));
            }
        };
        
        self.state = ServiceState::OfferedBlock;

        self.handle_offer_packet();

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

    fn handle_offer_packet(&mut self) -> Result<(), Error> {
        // Check to see if we have all the offers
        let offers = self.pending_msgs.iter().filter(|m| m.packet.msg_type == "offer" && m.packet.seq_num == (self.current_seq_num + 1)).collect::<Vec<_>>();
        if offers.len() < self.validators.len() {
            return Ok(());
        }

        let mut sorted_offers = offers.iter().filter_map(|p| {
            bincode::deserialize::<OfferPacket>(&p.packet.bytes).ok()
        }).collect::<Vec<_>>();
        sorted_offers.sort_by_key(|o| hex::encode(&o.offer_id));

        info!("Offers:");
        for offer in &sorted_offers {
            info!("\t{:?}", offer);
        }
        self.state = ServiceState::VoteReady;

        let selected_offer = sorted_offers.first().ok_or(Error::InvalidState(String::from("No ovalid offer found")))?;
        self.broadcast("vote", selected_offer.offer_id.clone());
        self.selected_offer = selected_offer.offer_id.clone();

        self.state = ServiceState::Voted;

        Ok(())

        

        /*
        // TODO:  Check that the block info matches what we stored
        self.offered_blocks.insert(offer_packet.offer_id.clone(),
            OfferedBlock{
                peer:peer.clone(),
                offer_id:offer_packet.offer_id,
                summary:offer_packet.summary,
            }
        );
        info!("Offers:");
        for (offer_id, offer) in &self.offered_blocks {
            info!("\t{}: {}", hex::encode(&offer_id), offer);
        }
        
        if self.offered_blocks.len() == self.validators.len() {
           self.state = ServiceState::VoteReady;
           info!("May now proceed to vote");
        }
        */
    }

    /*
    fn start_vote(&mut self) {
        let selected_offer_id = self.offered_blocks.keys().next();
        if selected_offer_id.is_none() {
            return;
        }

        let offer_id = selected_offer_id.unwrap();
        if self.broadcast("vote", offer_id.clone()).is_err() {
            error!("Error broadcasting vote");
        }
        debug!("Self voting for {}", hex::encode(offer_id));
        self.add_vote(offer_id.clone());
        self.state = ServiceState::Voted;
    }

    fn cleanup_offered_blocks(&mut self, selected_block_id: Option<BlockId>) {
        let blocks: Vec<BlockId> = self.offered_blocks.keys().cloned().collect();
        for block_id in blocks {
            debug!("attempting cleanup of {}", hex::encode(&block_id));
            if selected_block_id.is_none() || &block_id != selected_block_id.as_ref().unwrap() {
                trace!("Ignoring block {}", hex::encode(&block_id));
                /*
                match self.service.fail_block(block_id) {
                    Err(e) => debug!("Error ignoring {}", e),
                    Ok(_) => {},
                }
                */
            }
        }
        self.offered_blocks.clear();
    }
    */

    fn handle_vote_packet(&mut self) -> Result<(), Error> {
        let vote_packets = self.pending_msgs.iter().filter(|m| m.packet.msg_type == "vote" && m.packet.seq_num == (self.current_seq_num + 1)).collect::<Vec<_>>();

        if vote_packets.len() != self.validators.len() {
            return Ok(());
        }

        let mut votes = HashMap::new();

        for vp in &vote_packets {
            let vote = votes.entry(vp.packet.bytes.clone()).or_insert(0);
            *vote += 1;
        }

        info!("Votes:");
        for (offer_id, count) in &votes {
            info!("\t{}: {}", hex::encode(&offer_id), count);
        }

        let voted_entry = votes.iter().max_by(|a, b| a.1.cmp(&b.1));
        if voted_entry.is_none() {
            error!("We got a bad vote entry?");
            return Err(Error::InvalidState(String::from("empty vote entry")));
        }
        let offer_hash = voted_entry.unwrap().0;

        let offer_res = self.pending_msgs.iter().find(|lp| {
            if lp.packet.msg_type == "offer" && lp.packet.seq_num == (self.current_seq_num + 1) {
                let offer:OfferPacket = bincode::deserialize(&lp.packet.bytes).expect("deserialize");
                return offer.offer_id == *offer_hash;
            }
            return false;
        });
        if offer_res.is_none() {
            error!("We didn't have an offer entry for the voted block!");
            return Err(Error::InvalidState(String::from("no offer information for the given vote")));
        }

        if let Some(offer) = offer_res {
            let validators = Arc::new(ValidatorSet::from(self.validators.iter()));
            for (i, idx) in validators.all_indices() {
                debug!("Validator {}:{}", idx, hex::encode(i));
            }
            debug!("Creating Broadcast from {} for leader {}", hex::encode(&self.local_peer_id), hex::encode(&offer.peer));
            let broadcast = Broadcast::new(self.local_peer_id.clone(), validators.clone(), offer.peer.clone());
            if let Err(e) = broadcast {
                error!("Could not create a broadcast: {}", e);
                return Err(Error::InvalidState(String::from("Broadcast create failure")));
            }
            self.vote_broadcast = Some(broadcast.unwrap());
            if offer.peer == self.local_peer_id {
                let broadcaster = self.vote_broadcast.as_mut().expect("initial broadcast");
                let offer_packet: OfferPacket = bincode::deserialize(&offer.packet.bytes).expect("Deserialize for broadcast");
                debug!("Broadcasting start for offer: {}", hex::encode(&offer_packet.offer_id));
                match broadcaster.broadcast(offer_packet.offer_id) {
                    Ok(initial_step) => {
                        self.send_step_messages(&initial_step);
                    }
                    Err(e) => {
                        error!("Error creating initial step {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_broadcast_messsage(&mut self, msg: &PeerMessage, packet:&ABFTPacket) {
        if self.vote_broadcast.is_none() {
            error!("Received a broadcast but we aren't ready");
        }

        let hbmsg: hbbft::broadcast::Message = bincode::deserialize(&packet.bytes).expect("deser error");
        let steps = self.vote_broadcast.as_mut().expect("handle_message").handle_message(&msg.header.signer_id, hbmsg).expect("handle steps");
        let res = self.send_step_messages(&steps);
        if let Err(e) = res {
            error!("Error: {}", e);
            return;
        }
        if steps.output.is_empty() {
            return;
        }
        
        debug!("We have output from the broadcast! {:?} {}", steps.output, hex::encode(&self.selected_offer));
        if !steps.output.first().expect("offer id to submit").eq(&self.selected_offer) {
            return;
        }

        info!("We're the lead, committing!");
        self.service.finalize_block(create_consensus(&self.local_peer_id)).map_err(|e| error!("Could not finalize: {}", e));
        self.state = ServiceState::AwaitingCommit;
    }

    fn send_step_messages(&mut self, step: &hbbft::broadcast::Step<PeerId>) -> Result<(), Error> {
        for msg in step.messages.iter() {
            debug!("Doing message: {:?}", msg);

            let bytes = bincode::serialize(&msg.message).map_err(|e| {
                error!("Error serializing step: {}", e);
                return;
            }).unwrap();

            // TODO:  This cloen is nonsense and needs a rework of the way we store validators to it's own struct
            for peerid in &self.validators.clone() {
                if msg.target.contains(peerid) {
                    let res = self.send_to(peerid, "broadcast", bytes.clone());
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
        self.selected_offer.clear();
        //self.cleanup_offered_blocks(None);
        self.block_cycle_timeout.stop();
        self.vote_broadcast = None;
        let cur_seq = self.current_seq_num;
        self.pending_msgs.retain(|lp| lp.packet.seq_num >= cur_seq);
    }

    fn check_timers(&mut self) {
        if self.block_cycle_timeout.check_expired() {
            self.reset();
            return;
        }

        /*
        if service.block_vote_timeout.check_expired() {
            service.state = ServiceState::VoteReady;
        }
        */
    }

    fn handle_commit(&mut self, new_chain_head: BlockId) {              
        info!(
            "Chain head updated to {}, abandoning block in progress",
            hex::encode(&new_chain_head)
        );
        
        self.current_seq_num += 1;
        self.state = ServiceState::Finishing;

        self.cancel_block();

        self.reset();

        self.state = ServiceState::Initializing;
    }

    fn handle_block_new(&mut self, block: Block) {
        if self.state != ServiceState::AwaitingCommit {
            error!("Got a new block when we weren't expecting it! BlockId: {}", hex::encode(&block.block_id));
        }

        // TODO:  Actually check the consensus data
        info!("BlockNew, checking consensus data: {}", DisplayBlock(&block));

        if block.block_num == 0 {
            warn!("Received genesis block; ignoring");
            return;
        }

        // TODO: Dump the bad block with ignore or fail?
        if self.selected_offer.len() == 0 {
            error!("We are attempted to work on a block with no voted selection.");
            return;
        }
        
        /* TODO:  Fix this validation
        let selected_offer = &self.offered_blocks[&self.selected_offer];
        if block.summary != selected_offer.summary {
            error!("The offer doesn't match the expected summary");
            return;
        }

        if block.signer_id != selected_offer.peer {
            error!("The block was not initiated by the selected peer");
            return;
        }
        */
        
        self.check_block(block.block_id);
    }

    fn handle_peer_message(&mut self, message: PeerMessage, peer_id: PeerId) -> Result<(), Error> {
        info!("Got a peer message for type {}", message.header.message_type);
        let packet: ABFTPacket = bincode::deserialize(&message.content).map_err(|_e| Error::EncodingError(String::from("deserialize packet")))?;
        self.add_pending_msg(peer_id, packet.clone());

        match ABFTMessage::from_str(message.header.message_type.as_ref())
            .unwrap()
        {
            ABFTMessage::Offer => {
                self.handle_offer_packet();
            }

            ABFTMessage::Vote => {
                self.handle_vote_packet();
            }

            ABFTMessage::Broadcast => {
                self.handle_broadcast_messsage(&message, &packet);
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

pub struct ABFTEngine {}

impl ABFTEngine {
    pub fn new() -> Self {
        ABFTEngine {}
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
        let mut service = ABFTService::new(service, startup_state.local_peer_info.peer_id.clone());

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
                            service.handle_peer_message(message, sender_id);
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

fn check_consensus(block: &Block) -> bool {
    block.payload == create_consensus(&block.summary)
}

fn create_consensus(summary: &[u8]) -> Vec<u8> {
    let mut consensus: Vec<u8> = Vec::from(&b"ABFT"[..]);
    consensus.extend_from_slice(summary);
    consensus
}

pub enum ABFTMessage {
    Offer,
    Vote,
    Broadcast,
}

impl FromStr for ABFTMessage {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "offer" => Ok(ABFTMessage::Offer),
            "vote" => Ok(ABFTMessage::Vote),
            "broadcast" => Ok(ABFTMessage::Broadcast),
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