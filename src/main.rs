use std::{net::ToSocketAddrs, str::from_utf8};

use actix_web::web::Bytes;
use actix_web::web::BytesMut;
use actix_web::{
    dev::PeerAddr, error, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer,
};
use anyhow::Context;
use awc::error::PayloadError;
use awc::Client;
use clap::Parser;
use ethabi::Token;
use futures_util::StreamExt;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tiny_keccak::{Hasher, Keccak};
use tokio::fs;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct OllamaResponse {
    pub model: String,
    pub created_at: String,
    pub response: String,
    pub done: bool,
    pub context: Vec<u32>,
    pub total_duration: u128,
    pub load_duration: u128,
    pub prompt_eval_duration: u128,
    pub eval_count: u128,
    pub eval_duration: u128,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OllamaConvertedResponse {
    pub model: String,
    pub created_at: String,
    pub response: String,
    pub done: bool,
    pub msg: String,
}


#[derive(Debug, PartialEq)]
pub struct OllamaSignatureParameters {
    pub model: String,
    pub prompt: String,
    pub request_context: String,
    pub response_context: String,
    pub response: String,
}

/// Forwards the incoming HTTP request using `awc`.
async fn forward(
    req: HttpRequest,
    payload: web::Payload,
    peer_addr: Option<PeerAddr>,
    url: web::Data<Url>,
    client: web::Data<Client>,
    redirect_destination: web::Data<String>,
) -> Result<HttpResponse, Error> {
    let mut new_url = (**url).clone();
    new_url.set_path(req.uri().path());
    new_url.set_query(req.uri().query());
    log::info!("Redirect destination: {}", redirect_destination.to_string());
    let forwarded_req = client
        .request_from(new_url.as_str(), req.head())
        .no_decompress()
        .timeout(Duration::new(300, 0));

    let forwarded_req = match peer_addr {
        Some(PeerAddr(_addr)) => {
            forwarded_req.insert_header(("Host", redirect_destination.to_string()))
        }
        None => forwarded_req,
    };

    let res = forwarded_req
        .send_stream(payload)
        .await
        .map_err(error::ErrorInternalServerError)?;

    let mut client_resp = HttpResponse::build(res.status());
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.insert_header((header_name.clone(), header_value.clone()));
    }

    let stream_res = res.map(|chunks| {
        let ollama_json_value: OllamaResponse = serde_json::from_slice(&chunks.unwrap())
            .map_err(|e| {
                error::ErrorInternalServerError(format!("Error deserializing JSON: {}", e))
            })
            .unwrap();
        print!("{:#?}", ollama_json_value);
        let converted_res = OllamaConvertedResponse {
            done: ollama_json_value.done,
            created_at: ollama_json_value.created_at,
            model: ollama_json_value.model,
            response: ollama_json_value.response,
            msg: "Sample".to_string(),
        };

        let final_response: Result<Bytes, PayloadError> =
            Ok(Bytes::from(serde_json::to_string(&converted_res).unwrap()));
        final_response
    });
    // Processed each item, no action needed here
    Ok(client_resp.streaming(stream_res))
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

    let redirect_destination = format!("{}:{}", args.forward_addr, args.forward_port);

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
            .app_data(web::Data::new(redirect_destination.clone()))
            .wrap(middleware::Logger::default())
            .default_service(web::to(forward))
    })
    .bind((args.listen_addr, args.listen_port))?
    .workers(2)
    .run()
    .await
}
