use std::net::ToSocketAddrs;

use actix_web::{
    dev::PeerAddr, error, http::header, middleware, web, App, Error, HttpRequest, HttpResponse,
    HttpServer,
};
use anyhow::Context;
use awc::Client;
use clap::Parser;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use tiny_keccak::{Hasher, Keccak};
use tokio::fs;
use url::Url;
use std::{time::Duration};

/// Forwards the incoming HTTP request using `awc`.
async fn forward(
    req: HttpRequest,
    payload: web::Payload,
    peer_addr: Option<PeerAddr>,
    url: web::Data<Url>,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    let mut new_url = (**url).clone();
    new_url.set_path(req.uri().path());
    new_url.set_query(req.uri().query());
    let forwarded_req = client
        .request_from(new_url.as_str(), req.head())
        .no_decompress().timeout(Duration::new(60, 0));

    let forwarded_req = match peer_addr {
        Some(PeerAddr(addr)) => {
            forwarded_req.insert_header(("x-forwarded-for", addr.ip().to_string()))
        }
        None => forwarded_req,
    };

    // get the host header value
    let host_header = req
        .headers()
        .get(header::HOST)
        .context("could not find Host header")
        .and_then(|x| x.to_str().context("could not parse Host header"));
    let host_header = host_header.unwrap().to_owned();

    let mut res = forwarded_req
        .send_stream(payload)
        .await
        .map_err(error::ErrorInternalServerError)?;

    let signer = k256::ecdsa::SigningKey::from_slice(
        fs::read("/app/secp.sec")
            .await
            .context("failed to read signer key")
            .unwrap()
            .as_slice(),
    )
    .context("invalid signer key")
    .unwrap();

    let mut hasher = Keccak::v256();

    hasher.update(b"|oyster-hasher|");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    hasher.update(b"|timestamp|");
    hasher.update(&timestamp.to_be_bytes());

    hasher.update(b"|request|");
    hasher.update(b"|method|");
    hasher.update(req.method().to_string().as_bytes());
    hasher.update(b"|pathandquery|");
    hasher.update(
        req.uri()
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or("")
            .as_bytes(),
    );
    let body = res.body().await?;
    hasher.update(b"|body|");
    hasher.update(&body);
    hasher.update(b"|host|");
    hasher.update(host_header.as_bytes());

    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    let (rs, v) = signer.sign_prehash_recoverable(&hash).unwrap();

    let signature = rs.to_bytes().append(27 + v.to_byte());

    let mut client_resp = HttpResponse::build(res.status());
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.insert_header((header_name.clone(), header_value.clone()));
    }

    client_resp.insert_header(("X-Oyster-Timestamp", timestamp.to_string()));
    client_resp.insert_header(("X-Oyster-Signature", hex::encode(signature.as_slice())));
    Ok(client_resp.body(body))
}

#[derive(clap::Parser, Debug)]
struct CliArguments {
    listen_addr: String,
    listen_port: u16,
    forward_addr: String,
    forward_port: u16,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let args = CliArguments::parse();

    let forward_socket_addr = (args.forward_addr, args.forward_port)
        .to_socket_addrs()?
        .next()
        .expect("given forwarding address was not valid");

    let forward_url = format!("http://{forward_socket_addr}");
    let forward_url = Url::parse(&forward_url).unwrap();

    log::info!(
        "starting HTTP server at http://{}:{}",
        &args.listen_addr,
        args.listen_port
    );

    log::info!("forwarding to {forward_url}");



    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Client::default()))
            .app_data(web::Data::new(forward_url.clone()))
            .wrap(middleware::Logger::default())
            .default_service(web::to(forward))
    })
    .bind((args.listen_addr, args.listen_port))?
    .workers(2)
    .run()
    .await
}
