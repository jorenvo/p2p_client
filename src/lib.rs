// Copyright 2018, Joren Van Onder (joren.vanonder@gmail.com)
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use std::collections::HashMap;
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;
use std::{io, thread};

pub struct Config {
    pub broker: String,
    pub username: String,
}

impl Config {
    pub fn new(mut args: Vec<String>) -> Result<Config, String> {
        let program_name = args.remove(0);

        if args.len() < 2 {
            Err(format!(
                "Usage: {} <broker_address> <client_name>",
                program_name
            ))
        } else {
            Ok(Config {
                broker: args.remove(0),
                username: args.remove(0),
            })
        }
    }
}

fn set_up_socket() -> Result<UdpSocket, String> {
    for port in 63326..63334 {
        // Don't bind to 127.0.0.1, it will bind to the loopback interface
        // which makes it impossible to send_to.
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        match UdpSocket::bind(socket_addr) {
            Ok(socket) => {
                println!("Client running on {}", socket.local_addr().unwrap());
                return Ok(socket);
            }
            Err(e) => println!("Failed to bind to {} (error: {})", port, e),
        }
    }

    Err(String::from("couldn't find any port to bind to."))
}

fn list(socket: &UdpSocket, broker: &SocketAddr) -> HashMap<String, SocketAddr> {
    // each client: 4 bytes IP, 2 bytes port, 32 bytes name
    const BYTES_PER_CLIENT_NAME: usize = 32;
    const BYTES_PER_CLIENT: usize = 4 + 2 + BYTES_PER_CLIENT_NAME;
    const MAX_CLIENTS: usize = 16;
    let mut buf = [0; BYTES_PER_CLIENT * MAX_CLIENTS];
    let mut clients = HashMap::new();

    println!("Listing users currently connected to {}...", broker);
    socket.send_to(b"LIST", broker).unwrap();
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let mut offset = 0;

    while offset < amt {
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                buf[offset + 0],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            )),
            ((buf[offset + 4] as u16) << 8) + buf[offset + 5] as u16,
        );
        let name = String::from_utf8(buf[offset + 6..offset + BYTES_PER_CLIENT].to_vec()).unwrap();
        let name = String::from(name.trim_matches('\0'));
        clients.insert(name, addr);

        offset += BYTES_PER_CLIENT;
    }

    for (name, addr) in &clients {
        println!(
            "{name:<width$}{addr}",
            name = name,
            width = BYTES_PER_CLIENT_NAME,
            addr = addr
        );
    }

    clients
}

fn register(socket: &UdpSocket, broker: &SocketAddr, name: &str) -> Ipv4Addr {
    println!("Registering as {} with {}...", name, broker);
    socket
        .send_to(format!("REGISTER{}", name).as_bytes(), broker)
        .unwrap();

    let mut buf = [0; 4];
    let (_amt, _src) = socket.recv_from(&mut buf).unwrap();

    let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
    println!("My public IP: {}", ip);

    ip
}

fn ask(socket: &UdpSocket, broker: &SocketAddr, dest_address: &SocketAddr) {
    let ip = match dest_address.ip() {
        IpAddr::V4(ip) => ip,
        _ => panic!("Only v4 is supported\n"),
    };
    let port = dest_address.port();

    let mut msg: Vec<u8> = "ASK\0\0\0\0\0".as_bytes().to_vec();
    msg.append(&mut ip.octets().to_vec());
    msg.push((port >> 8) as u8);
    msg.push((port & 0xff) as u8);
    socket.send_to(&msg, broker).unwrap();
}

fn send(socket: &UdpSocket, buf: &Vec<u8>) {
    let client = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])),
        ((buf[4] as u16) << 8) + buf[5] as u16,
    );

    let one_sec = Duration::from_secs(1);
    thread::sleep(one_sec);

    println!("punching through {:?}", client);
    socket
        .send_to(b"MSG\0\0\0\0\0punching hole as requested", client)
        .unwrap();
}

fn prompt() -> String {
    let mut input = String::new();

    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            // remove newline
            input.pop();
            input
        }
        Err(_) => String::new(),
    }
}

fn prompt_to_connect() -> Option<String> {
    println!("Type \"listen<RET>\" to listen for incoming connections, type \"<username><RET>\" to connect to it.");

    let input = prompt();
    if input == "listen" {
        None
    } else {
        Some(input)
    }
}

pub fn run(config: Config) {
    let socket = set_up_socket().unwrap();

    // just take the first resolved SocketAddr
    let broker = format!("{}:63325", config.broker)
        .to_socket_addrs()
        .expect(&format!("Can't resolve {}.", config.broker))
        .next()
        .unwrap();
    register(&socket, &broker, &config.username);

    let clients = list(&socket, &broker);
    let user_to_connect_to = prompt_to_connect();

    if let Some(user_to_connect_to) = user_to_connect_to {
        let dest_address = clients.get(&user_to_connect_to).expect("Unknown user.");
        println!("punching hole in own NAT to {}", dest_address);
        socket
            .send_to(b"punch hole in own NAT", dest_address)
            .unwrap();
        ask(&socket, &broker, dest_address);
    }

    println!("Listening for incoming connections...");
    loop {
        let mut buf = [0; 32];
        let (_amt, src) = socket.recv_from(&mut buf).unwrap();

        let msg_type = String::from_utf8(buf[..4].to_vec()).unwrap();

        // Only respond to SEND, probably also need MSG\0 or something
        println!("received {} from {}", msg_type, src);

        if msg_type.starts_with("SEND") {
            send(&socket, &buf[4..].to_vec());
        } else if msg_type.starts_with("MSG") {
            println!("{}", String::from_utf8(buf[8..].to_vec()).unwrap());
            print!("> ");
            stdout().flush().unwrap();
            let mut response = String::from("MSG\0\0\0\0\0");
            response += &prompt();
            socket.send_to(response.as_bytes(), src).unwrap();
        } else {
            println!("invalid msg");
        }
    }
}
