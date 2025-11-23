use simple_socks5::conn::request::CMD;
use simple_socks5::{ATYP, Socks5, conn::reply::Rep, error::SocksError, parse::AddrPort};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), SocksError> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();

    // Both IPv4 and IPv6 work
    let mut server = Socks5::bind("127.0.0.1:1080").await?;
    server.allow_no_auth();

    // Example with a username and password if you need authentication
    // server.allow_userpass(|u, p| u == "admin" && p == "admin");

    let server = Arc::new(server);

    info!("SOCKS5 proxy listening on {}", server.local_addr()?);

    loop {
        let (client, addr) = server.accept().await?;
        let server_ref = Arc::clone(&server);

        tokio::spawn(async move {
            if let Err(e) = handle_client(server_ref, client, addr).await {
                error!("Client {addr} error: {e}");
            }
        });
    }
}

async fn handle_client(
    server: Arc<Socks5>,
    mut stream: TcpStream,
    addr: std::net::SocketAddr,
) -> Result<(), SocksError> {
    info!("New client connected from {addr}");

    if let Err(e) = server.authenticate(&mut stream).await {
        warn!("Authentication failed for {addr}: {e}");
        let _ = stream.shutdown().await;
        return Ok(());
    }
    info!("Authentication succeeded for {addr}");

    let req = match Socks5::read_conn_request(&mut stream).await {
        Ok(r) => {
            info!(client=%addr, "Connection request");
            info!(request=%r, "Request format");
            r
        }
        Err(e) => {
            error!("Failed to read connection request from {addr}: {e}");
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    match req.cmd {
        CMD::Connect => {
            info!(client=%addr, dest=%req.dst, "Connecting to destination");

            let mut target = match req.dst {
                AddrPort::V4(ip, port) => TcpStream::connect((ip, port)).await?,
                AddrPort::V6(ip, port) => TcpStream::connect((ip, port)).await?,
                AddrPort::Domain(ref host, port) => {
                    TcpStream::connect((host.as_str(), port)).await?
                }
            };

            let local_addr = target.local_addr()?;
            let bnd = match local_addr.ip() {
                IpAddr::V4(ip) => AddrPort::V4(ip, local_addr.port()),
                IpAddr::V6(ip) => AddrPort::V6(ip, local_addr.port()),
            };

            let atyp = match bnd {
                AddrPort::V4(_, _) => ATYP::V4,
                AddrPort::V6(_, _) => ATYP::V6,
                _ => ATYP::DomainName,
            };

            info!(client=%addr, bind=%bnd, atyp=%atyp, "Connection established");

            Socks5::send_conn_reply(&mut stream, Rep::Succeeded, atyp, bnd).await?;

            if let Err(e) = io::copy_bidirectional(&mut stream, &mut target).await {
                warn!("TCP connection with {addr} closed with error: {e}");
            } else {
                info!("TCP connection with {addr} closed");
            }
        }

        _ => {
            warn!("Unsupported command from {addr}: {}", req.cmd);
            Socks5::send_conn_reply(
                &mut stream,
                Rep::CommandNotSupported,
                ATYP::V4,
                AddrPort::V4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await?;
        }
    }

    Ok(())
}
