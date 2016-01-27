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
extern crate void;
// extern crate libc;
extern crate rand;

use std::sync::mpsc;
use std::str::FromStr;
use std::net::{SocketAddr, ToSocketAddrs};
use std::collections::VecDeque;
use std::io;

use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::{serialise, deserialise};

use mio::udp::UdpSocket;
use mio::{EventLoop, EventSet, Token, Handler, PollOpt};

// use bytes::RingBuf;
// use bytes::buf::{Buf, MutBuf};

use rustc_serialize::{Encodable, Decodable};

use void::Void;

const DISCOVERY: Token = Token(0);
const SEEK_PEERS: Token = Token(1);

/// ServiceDiscovery is a RAII API for the purposes of discovering peers on the local network. To
/// stop the process of discovery completely, it is sufficient to drop the instance of this struct.
pub struct ServiceDiscovery<Reply: 'static + Encodable + Decodable + Send + Clone> {
    sender: mio::Sender<MioMessage<Reply>>,
    requested_port: u16,
    bound_port: u16,
    _raii_joiner: RaiiThreadJoiner,
}

impl<Reply: 'static + Encodable + Decodable + Send + Clone> ServiceDiscovery<Reply> {
    /// Obtain a new RAII instance of ServiceDiscovery. By default listening to peers searching for
    /// us is disabled.
    pub fn new(port: u16, reply: Reply) -> io::Result<Self> {
        let (mio_msg_sender, raii_joiner, bound_port) =
            try!(ServiceDiscoveryImpl::<Reply>::start(port, reply));

        Ok(ServiceDiscovery {
            sender: mio_msg_sender,
            requested_port: port,
            bound_port: bound_port,
            _raii_joiner: raii_joiner,
        })
    }

    /// Register a new observer to be notified whenever we successfully find peers by interrogating
    /// the network. Return value indicates acknowledgement of the request.
    pub fn register_seek_peer_observer(&self, observer: mpsc::Sender<Reply>) -> bool {
        self.sender.send(MioMessage::RegisterObserver(observer)).is_ok()
    }

    /// Enable or disable listening and responding to peers searching for us. This will
    /// correspondingly allow or disallow others from finding us by interrogating the network.
    /// Return value indicates acknowledgement of the request.
    pub fn set_listen_for_peers(&self, listen: bool) -> bool {
        self.requested_port == self.bound_port &&
        self.sender.send(MioMessage::SetBroadcastListen(listen)).is_ok()
    }

    /// Interrogate the network to find peers. Return value indicates acknowledgement of the
    /// request.
    pub fn seek_peers(&self) -> bool {
        self.sender.send(MioMessage::SeekPeers).is_ok()
    }
}

impl<Reply: 'static + Encodable + Decodable + Send + Clone> Drop for ServiceDiscovery<Reply> {
    fn drop(&mut self) {
        let _ = self.sender.send(MioMessage::Shutdown);
    }
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
    reply: Reply,
    serialised_seek_peers_request: Vec<u8>,
    reply_to: VecDeque<SocketAddr>,
    observers: Vec<mpsc::Sender<Reply>>,
}

impl<Reply: 'static + Send + Clone + Encodable + Decodable> Handler for ServiceDiscoveryImpl<Reply> {
    type Timeout = Void;
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
            MioMessage::RegisterObserver(observer) => {
                self.observers.push(observer);
            }
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
            MioMessage::Shutdown => {
                event_loop.shutdown();
            }
        }
    }
}

impl<Reply: 'static + Encodable + Decodable + Send + Clone> ServiceDiscoveryImpl<Reply> {
    pub fn start(port: u16,
                 reply: Reply)
                 -> io::Result<(mio::Sender<MioMessage<Reply>>, RaiiThreadJoiner, u16)> {
        let guid = rand::random();
        // Checking right at the begginning if it can be serialised so that we can simply
        // unwrap_result!() later
        let _ = try!(serialise(&reply).map_err(|_| {
            io::Error::new(io::ErrorKind::Other,
                           "Serialisation Error. TODO: Improve this")
        }));
        let serialised_seek_peers_request =
            try!(serialise::<DiscoveryMsg<Reply>>(&DiscoveryMsg::Request).map_err(|_| {
                io::Error::new(io::ErrorKind::Other,
                               "Serialisation Error. TODO: Improve this")
            }));

        let bind_addr = unwrap_option!(try!(("0.0.0.0", port).to_socket_addrs()).next(),
                                       "Failed to parse socket address");

        let udp_socket = try!(UdpSocket::v4());
        // try!(enable_so_reuseport(&udp_socket));
        try!(udp_socket.set_broadcast(true));
        let bound_port = match udp_socket.bind(&bind_addr) {
            Ok(()) => port,
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::AddrInUse => {
                        let addr = try!(SocketAddr::from_str("0.0.0.0:0").map_err(|_| {
                            io::Error::new(io::ErrorKind::Other, "failed to parse addr")
                        }));
                        try!(udp_socket.bind(&addr));
                        let addr = try!(udp_socket.local_addr());
                        addr.port()
                    }
                    _ => return Err(e),
                }
            }
        };

        let mut discovery_impl = ServiceDiscoveryImpl {
            guid: guid,
            seek_peers_on: try!(SocketAddr::from_str(&format!("255.255.255.255:{}", port))
                                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "TODO"))),
            broadcast_listen: false,
            socket: udp_socket,
            // read_buf: RingBuf::new(1024),
            read_buf: [0; 1024],
            reply: reply,
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

        Ok((mio_msg_sender, raii_joiner, bound_port))
    }

    fn readable(&mut self, event_loop: &mut EventLoop<Self>) -> io::Result<()> {
        // if let Some((bytes_read, peer_addr)) = try!(self.socket.recv_from(unsafe {
        //     self.read_buf.mut_bytes()
        // })) {
        if let Some((bytes_read, peer_addr)) = try!(self.socket.recv_from(&mut self.read_buf)) {
            let msg: DiscoveryMsg<Reply> = match deserialise(&self.read_buf[..bytes_read]) {
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
                let discovery_response = DiscoveryMsg::Response {
                    guid: self.guid,
                    content: self.reply.clone(),
                };
                let serialised_response = try!(serialise(&discovery_response).map_err(|_| {
                    io::Error::new(io::ErrorKind::Other,
                                   "Serialisation Error. TODO: Improve this")
                }));
                let mut sent_bytes = 0;
                while sent_bytes != serialised_response.len() {
                    match try!(self.socket
                                   .send_to(&serialised_response[sent_bytes..], &peer_addr)) {
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

// TODO(canndrew): Look into using this reuseport stuff so that we can have multiple peers on the
// same machine all listening for peers
//
// #[cfg(target_os = "linux")]
// #[allow(unsafe_code)]
// fn enable_so_reuseport(sock: &UdpSocket) -> io::Result<()> {
// use std::os::unix::io::AsRawFd;
//
// let one: libc::c_int = 1;
// let raw_fd = sock.as_raw_fd();
// let one_ptr: *const libc::c_int = &one;
// unsafe {
// if libc::setsockopt(raw_fd,
// libc::SOL_SOCKET,
// libc::SO_REUSEADDR,
// one_ptr as *const libc::c_void,
// std::mem::size_of::<libc::c_int>() as libc::socklen_t
// ) < 0
// {
// return Err(io::Error::last_os_error());
// };
// }
// Ok(())
// }
//


#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn three_peer_localhost_discovery() {
        let (tx0, _rx0) = mpsc::channel();
        let sd0 = unwrap_result!(ServiceDiscovery::new(45666, 0u32));
        assert!(sd0.register_seek_peer_observer(tx0));
        assert!(sd0.set_listen_for_peers(true));

        let (tx1, rx1) = mpsc::channel();
        let sd1 = unwrap_result!(ServiceDiscovery::new(45666, 1u32));
        assert!(sd1.register_seek_peer_observer(tx1));
        assert!(sd1.seek_peers());

        thread::sleep(Duration::from_millis(100));
        match rx1.try_recv() {
            Ok(0u32) => (),
            x => panic!("Unexpected result: {:?}", x),
        };
    }
}
