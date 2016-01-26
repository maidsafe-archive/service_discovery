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
extern crate maidsafe_utilities;

extern crate rand;
extern crate ip;
extern crate net2;
extern crate rustc_serialize;

use rand::random;
use rustc_serialize::Encodable;
use std::error::Error;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::net;
use std::str::FromStr;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;
use ip::SocketAddrExt;
use net2::UdpSocketExt;
use maidsafe_utilities::thread::RaiiThreadJoiner;
use maidsafe_utilities::serialisation::serialise;



pub struct ServiceDiscovery<Reply> {
    udp_socket: UdpSocket,
    stop_flag: Arc<AtomicBool>,
    _raii_joiner: RaiiThreadJoiner,
    reply: Reply
}

impl<Reply: Encodable> ServiceDiscovery<Reply> {
    pub fn new(port: u16, reply: Reply) -> Result<ServiceDiscovery> {
        let serialised_reply = try!(serialise(&reply));
        let udp_socket = try!(UdpSocket::bind(format!("0.0.0.0:{}", port)));
        let cloned_udp_socket = try!(udp_socket.try_clone());

        let stop_flag = Arc::new(AtomicBool::new(false));
        let cloned_stop_flag = stop_flag.clone();

        let joiner = RaiiThreadJoiner::new(thread!("ServiceDiscoveryThread", move || {
          ServiceDiscovery::start_accept(cloned_udp_socket, cloned_stop_flag, serialised_reply);
        }));

        Ok(ServiceDiscovery {
            udp_socket: udp_socket,
            stop_flag: stop_flag,
            _raii_joiner: joiner,
            reply: reply
        })
    }

    pub fn seek_peers() -> Result<Vec<Reply>> {
        let stuff_to_send = StuffToSend;
        let mut result = Vec::with_capacity(10);

        for attempt in 0..num_attempts {
            self.udp_socket.send_to(self.reply, format!("255.255.255.255:{}", self.port));
        }

    let udp_response_thread = RaiiThreadJoiner::new(thread!("Accept Serice Discovery replies", move || {
                                       loop {
                                           let mut buffer = [0u8; 8];
                                           let (size, source) = try!(socket.recv_from(&mut buffer));
                                           match size {
                                               // FIXME Use better ways
                                               2usize => {
                                                   // The response is a serialised port
                                                   let _ = tx.send({
                                                       let port = parse_port(&buffer);
                                                       match source {
                                                            net::SocketAddr::V4(a) => {
                                                                SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(*a.ip(), port)))
                                                            }
                                                            // FIXME(dirvine) Hanlde ip6 :10/01/2016
                                                            _ => unimplemented!(),
                                                            //                                SocketAddr::V6(a) => {
                                                            //     SocketAddr::V6(SocketAddrV6::new(*a.ip(), port,
                                                            //                                      a.flowinfo(),
                                                            //                                      a.scope_id()))
                                                            // }
                                                       }
                                                   });
                                               }
                                               8usize => {
                                                   // The response is a shutdown signal
                                                   if parse_shutdown_value(&buffer) ==
                                                      shutdown_value &&
                                                      util::is_loopback(&SocketAddrExt::ip(&source)) {
                                                       break;
                                                   } else {
                                                       continue;
                                                   }
                                               }
                                               _ => {
                                                   // The response is invalid
                                                   continue;
                                               }
                                           };
                                       }
                                       Ok(())
                                   }));
        wait_for_results;
        return;
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn start_accept(udp_socket: UdpSocket, stop_flag: Arc<AtomicBool>, reply: Vec<u8>) {
        try!(udp_socket.set_read_timeout(Some(Duration::from_secs(UDP_RX_TIMEOUT_SECS))));

        let mut buf = [0u8; 1024];

        loop {
            let (bytes_read, peer_ep) = try!(udp_socket.recv_from(&mut buf));

            if stop_flag.load(Ordering::SeqCst) {
                return;
            }

            if bytes_read > 0 {
                let mut total_bytes_written = 0;
                while total_bytes_written <= reply.len() {
                    total_bytes_written += try!(udp_socket.send_to(&reply[total_bytes_written..],
                                                                   peer_addr));
                }
            }
        }
    }
}

impl Drop for BroadcastAcceptor {
    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}















#[cfg(test)]
mod test {
    use super::*;
    use std::thread;
    use std::net;
    use std::str::FromStr;
    use endpoint::{Protocol, Endpoint};
    use transport;
    use transport::{Message, Handshake};
    use socket_addr::SocketAddr;

    #[test]
    fn test_beacon() {
        let acceptor = unwrap_result!(BroadcastAcceptor::new(0));
        let acceptor_port = acceptor.beacon_port();

        let t1 = thread::Builder::new().name("test_beacon sender".to_owned()).spawn(move || {
            let mut transport = acceptor.accept().unwrap().1;
            unwrap_result!(transport.sender
                                    .send(&Message::UserBlob("hello beacon"
                                                                 .to_owned()
                                                                 .into_bytes())));
        });

        let t2 = thread::Builder::new().name("test_beacon receiver".to_owned()).spawn(move || {
            let endpoint = unwrap_result!(seek_peers(acceptor_port, None))[0];
            let transport =
                unwrap_result!(transport::connect(Endpoint::from_socket_addr(Protocol::Tcp,
                                                                             endpoint)));
            let dummy_handshake = Handshake {
                mapper_port: None,
                external_addr: None,
                remote_addr: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
            };
            let (_, mut transport) =
                unwrap_result!(transport::exchange_handshakes(dummy_handshake, transport));

            let msg = unwrap_result!(transport.receiver.receive());
            let msg = unwrap_result!(String::from_utf8(match msg {
                Message::UserBlob(msg) => msg,
                _ => panic!("Wrong message type"),
            }));
            assert_eq!(msg, "hello beacon");
        });

        let t1 = unwrap_result!(t1);
        let t2 = unwrap_result!(t2);
        unwrap_result!(t1.join());
        unwrap_result!(t2.join());
    }

    #[test]
    fn test_avoid_beacon() {
        let acceptor = unwrap_result!(BroadcastAcceptor::new(0));
        let acceptor_port = acceptor.beacon_port();
        let my_guid = acceptor.guid.clone();

        let t1 = thread::Builder::new()
                     .name("test_avoid_beacon acceptor".to_owned())
                     .spawn(move || {
                         let _ = unwrap_result!(acceptor.accept());
                     });

        let t2 = thread::Builder::new()
                     .name("test_avoid_beacon seek_peers 1".to_owned())
                     .spawn(move || {
                         assert!(unwrap_result!(seek_peers(acceptor_port, Some(my_guid)))
                                     .is_empty());
                     });

        // This one is just so that the first thread breaks.
        let t3 = thread::Builder::new()
                     .name("test_avoid_beacon seek_peers 2".to_owned())
                     .spawn(move || {
                         thread::sleep(::std::time::Duration::from_millis(700));
                         let endpoint = unwrap_result!(seek_peers(acceptor_port, None))[0];
                         let transport = unwrap_result!(transport::connect(Endpoint::from_socket_addr(Protocol::Tcp, endpoint)));
                         let dummy_handshake = Handshake {
                             mapper_port: None,
                             external_addr: None,
                             remote_addr: SocketAddr(net::SocketAddr::from_str("0.0.0.0:0").unwrap()),
                         };
                         let _ = unwrap_result!(transport::exchange_handshakes(dummy_handshake, transport));
                     });

        let t1 = unwrap_result!(t1);
        let t2 = unwrap_result!(t2);
        let t3 = unwrap_result!(t3);
        unwrap_result!(t1.join());
        unwrap_result!(t2.join());
        unwrap_result!(t3.join());
    }
}
