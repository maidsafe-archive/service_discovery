// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! # Service Discovery
//!
//! Discover other instances of your application on the local network.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/config_file_handler/")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
      non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
      private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
      unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
      unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

#[macro_use]
extern crate log;
extern crate mio;
// extern crate bytes;
extern crate rustc_serialize;
#[macro_use]
extern crate maidsafe_utilities;

use std::sync::mpsc;
use std::str::FromStr;
use std::net::SocketAddr;
use std::collections::VecDeque;
use std::io;
use std::io::{ErrorKind, Error};

use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::{serialise, deserialise};

use mio::udp::UdpSocket;
use mio::{EventLoop, EventSet, Token, Handler, PollOpt};

// use bytes::RingBuf;
// use bytes::buf::{Buf, MutBuf};

use rustc_serialize::{Encodable, Decodable};

const DISCOVERY: Token = Token(0);
const SEEK_PEERS: Token = Token(1);

/// TODO
pub struct ServiceDiscovery<Reply: 'static + Encodable + Decodable + Send + Clone> {
    sender: mio::Sender<MioMessage<Reply>>,
    _raii_joiner: RaiiThreadJoiner,
}

impl<Reply: 'static + Encodable + Decodable + Send + Clone> ServiceDiscovery<Reply> {
    /// TODO
    pub fn new(port: u16, reply: Reply) -> io::Result<Self> {
        let (mio_msg_sender, raii_joiner) = try!(ServiceDiscoveryImpl::<Reply>::start(port, reply));

        Ok(ServiceDiscovery {
            sender: mio_msg_sender,
            _raii_joiner: raii_joiner,
        })
    }

    /// TODO
    pub fn register_seek_peer_observer(&self, observer: mpsc::Sender<Reply>) -> bool {
        self.sender.send(MioMessage::RegisterObserver(observer)).is_ok()
    }

    /// TODO
    pub fn listen_to_broadcasts(&self, listen: bool) -> bool {
        self.sender.send(MioMessage::SetBroadcastListen(listen)).is_ok()
    }

    /// TODO
    pub fn seek_peers(&self) -> bool {
        self.sender.send(MioMessage::SeekPeers).is_ok()
    }
}

impl<Reply: 'static + Encodable + Decodable + Send + Clone> Drop for ServiceDiscovery<Reply> {
    fn drop(&mut self) {
        let _ = self.sender.send(MioMessage::Shutdown);
    }
}

trait TypeTrait {
    type DiscoveryMsg;
}

#[derive(RustcEncodable, RustcDecodable)]
enum DiscoveryMsg<Reply: Encodable + Decodable> {
    Request,
    Response {
        guid: u64,
        content: Reply,
    },
}

enum MioMessage<Reply> {
    RegisterObserver(mpsc::Sender<Reply>),
    SetBroadcastListen(bool),
    SeekPeers,
    Shutdown,
}

struct ServiceDiscoveryImpl<Reply> {
    guid: u64,
    seek_peers_on: SocketAddr,
    broadcast_listen: bool,
    socket: UdpSocket,
    // read_buf: RingBuf,
    read_buf: [u8; 1024],
    serialised_reply: Vec<u8>,
    serialised_seek_peers_request: Vec<u8>,
    reply_to: VecDeque<SocketAddr>,
    observers: Vec<mpsc::Sender<Reply>>,
}

impl<Reply: 'static + Encodable + Decodable + Send + Clone> TypeTrait for ServiceDiscoveryImpl<Reply> {
    type DiscoveryMsg = DiscoveryMsg<Reply>;
}

impl<Reply: 'static + Encodable + Decodable + Send + Clone> Handler for ServiceDiscoveryImpl<Reply> {
    type Timeout = ();
    type Message = MioMessage<Reply>;

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
        if events.is_readable() && token == DISCOVERY {
            if let Err(err) = self.readable(event_loop) {
                error!("Error in readable - {:?}", err);
                event_loop.shutdown();
            }
        }

        if events.is_writable() {
            if let Err(err) = self.writable(event_loop, token) {
                error!("Error in writable - {:?}", err);
                event_loop.shutdown();
            }
        }
    }

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, msg: Self::Message) {
        match msg {
            MioMessage::RegisterObserver(observer) => self.observers.push(observer),
            MioMessage::SetBroadcastListen(status) => {
                self.broadcast_listen = status;
            }
            MioMessage::SeekPeers => {
                match self.socket
                          .send_to(&self.serialised_seek_peers_request, &self.seek_peers_on) {
                    Ok(Some(_)) => {
                        if let Err(err) = event_loop.reregister(&self.socket,
                                                                DISCOVERY,
                                                                EventSet::readable(),
                                                                PollOpt::edge() |
                                                                PollOpt::oneshot()) {
                            error!("{:?}", err);
                            event_loop.shutdown();
                        }
                    }
                    Ok(None) => {
                        if let Err(err) = event_loop.reregister(&self.socket,
                                                                SEEK_PEERS,
                                                                EventSet::writable(),
                                                                PollOpt::edge() |
                                                                PollOpt::oneshot()) {
                            error!("{:?}", err);
                            event_loop.shutdown();
                        }
                    }
                    Err(err) => {
                        error!("{:?}", err);
                        event_loop.shutdown();
                    }
                }
            }
            MioMessage::Shutdown => event_loop.shutdown(),
        }
    }
}

impl<Reply: 'static + Encodable + Decodable + Send + Clone> ServiceDiscoveryImpl<Reply> {
    pub fn start(port: u16,
                 reply: Reply)
                 -> io::Result<(mio::Sender<MioMessage<Reply>>, RaiiThreadJoiner)> {
        let serialised_reply = try!(serialise(&reply).map_err(|_| {
            Error::new(ErrorKind::Other, "Serialisation Error. TODO: Improve this")
        }));
        let serialised_seek_peers_request =
            try!(serialise::<DiscoveryMsg<Reply>>(&DiscoveryMsg::Request).map_err(|_| {
                Error::new(ErrorKind::Other, "Serialisation Error. TODO: Improve this")
            }));

        let bind_addr = try!(SocketAddr::from_str(&format!("0.0.0.0:{}", port))
                                 .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e))));
        let udp_socket = try!(UdpSocket::bound(&bind_addr));

        let mut discovery_impl = ServiceDiscoveryImpl {
            guid: 0,
            seek_peers_on: try!(SocketAddr::from_str(&format!("255.255.255.255:{}", port))
                                    .map_err(|_| Error::new(ErrorKind::Other, "TODO"))),
            broadcast_listen: false,
            socket: udp_socket,
            // read_buf: RingBuf::new(1024),
            read_buf: [0; 1024],
            serialised_reply: serialised_reply,
            serialised_seek_peers_request: serialised_seek_peers_request,
            reply_to: VecDeque::new(),
            observers: Vec::new(),
        };

        let mut event_loop = try!(EventLoop::new());
        try!(event_loop.register(&discovery_impl.socket,
                                 DISCOVERY,
                                 EventSet::readable(),
                                 PollOpt::edge() | PollOpt::oneshot()));

        let mio_msg_sender = event_loop.channel();

        let raii_joiner = RaiiThreadJoiner::new(thread!("MioServiceDiscovery", move || {
            if let Err(err) = event_loop.run(&mut discovery_impl) {
                error!("Could not run the event loop for Service Discovery - {:?}",
                       err);
                event_loop.shutdown();
            }
        }));

        Ok((mio_msg_sender, raii_joiner))
    }

    fn readable(&mut self, event_loop: &mut EventLoop<Self>) -> io::Result<()> {
        // if let Some((bytes_read, peer_addr)) = try!(self.socket.recv_from(unsafe {
        //     self.read_buf.mut_bytes()
        // })) {
        if let Some((_bytes_read, peer_addr)) = try!(self.socket.recv_from(&mut self.read_buf)) {
            let msg: DiscoveryMsg<Reply> = match deserialise(&self.read_buf[..]) {
                Ok(msg) => msg,
                Err(_) => return Ok(()),
            };

            match msg {
                DiscoveryMsg::Request => {
                    if self.broadcast_listen {
                        self.reply_to.push_back(peer_addr);
                        try!(event_loop.reregister(&self.socket,
                                                   DISCOVERY,
                                                   EventSet::writable(),
                                                   PollOpt::edge() | PollOpt::oneshot()));
                    } else {
                        try!(event_loop.reregister(&self.socket,
                                                   DISCOVERY,
                                                   EventSet::readable(),
                                                   PollOpt::edge() | PollOpt::oneshot()));
                    }
                }
                DiscoveryMsg::Response { guid, content } => {
                    if guid != self.guid {
                        self.observers.retain(|observer| observer.send(content.clone()).is_ok());
                    }
                    try!(event_loop.reregister(&self.socket,
                                               DISCOVERY,
                                               EventSet::readable(),
                                               PollOpt::edge() | PollOpt::oneshot()));
                }
            }
        }

        Ok(())
        // Ok(self.read_buf.clear())
    }

    fn writable(&mut self, event_loop: &mut EventLoop<Self>, token: Token) -> io::Result<()> {
        if token == DISCOVERY {
            while let Some(peer_addr) = self.reply_to.pop_front() {
                let mut sent_bytes = 0;
                while sent_bytes != self.serialised_reply.len() {
                    match try!(self.socket
                                   .send_to(&self.serialised_reply[sent_bytes..], &peer_addr)) {
                        Some(bytes_tx) => {
                            sent_bytes += bytes_tx;
                        }
                        None => {
                            try!(event_loop.reregister(&self.socket,
                                                       DISCOVERY,
                                                       EventSet::writable(),
                                                       PollOpt::edge() | PollOpt::oneshot()));
                            return Ok(());
                        }
                    }
                }
            }
        } else if token == SEEK_PEERS {
            let mut sent_bytes = 0;
            while sent_bytes != self.serialised_seek_peers_request.len() {
                match try!(self.socket
                               .send_to(&self.serialised_seek_peers_request[sent_bytes..],
                                        &self.seek_peers_on)) {
                    Some(bytes_tx) => {
                        sent_bytes += bytes_tx;
                    }
                    None => {
                        try!(event_loop.reregister(&self.socket,
                                                   SEEK_PEERS,
                                                   EventSet::writable(),
                                                   PollOpt::edge() | PollOpt::oneshot()));
                        return Ok(());
                    }
                }
            }
        }

        Ok(try!(event_loop.reregister(&self.socket,
                                      DISCOVERY,
                                      EventSet::readable(),
                                      PollOpt::edge() | PollOpt::oneshot())))
    }
}
