use std::sync::Mutex;
use std::{net::ToSocketAddrs, str::from_utf8};

use actix_cors::Cors;
use actix_web::get;
use actix_web::http::header;
use actix_web::web::Bytes;
use actix_web::web::BytesMut;
use actix_web::Responder;
use actix_web::{
    dev::PeerAddr, error, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer,
};
use anyhow::Context;
use awc::error::PayloadError;
use awc::http::StatusCode;
use awc::Client;
use clap::Parser;
use ethabi::Token;
use futures_util::StreamExt;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::time::Duration;
use tiny_keccak::{Hasher, Keccak};
use tokio::fs;
use url::Url;

pub struct PersonQueue {
    pub queue: Mutex<VecDeque<String>>,
}

impl PersonQueue {
    fn new() -> Self {
        PersonQueue {
            queue: Mutex::new(VecDeque::new()),
        }
    }

    fn enqueue(&self, person: String) {
        self.queue.lock().unwrap().push_back(person);
    }

    fn position_of(&self, person: &str) -> Option<usize> {
        self.queue.lock().unwrap().iter().position(|p| p == person)
    }

    fn remove(&self, person: &str) -> Option<String> {
        let mut queue = self.queue.lock().unwrap();
        if let Some(index) = queue.iter().position(|p| p == person) {
            Some(queue.remove(index)?)
        } else {
            None
        }
    }
}

#[derive(Deserialize)]
struct PositionInQueueParams {
    req_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OllamaResponse {
    pub model: String,
    pub created_at: String,
    pub response: String,
    pub done: bool,
    pub context: Option<Vec<u32>>,
    pub total_duration: Option<u128>,
    pub load_duration: Option<u128>,
    pub prompt_eval_duration: Option<u128>,
    pub eval_count: Option<u128>,
    pub eval_duration: Option<u128>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OllamaConvertedResponseForOngoingInferencing {
    pub model: String,
    pub created_at: String,
    pub response: String,
    pub done: bool,
    pub oyster_signature: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OllamaConvertedResponseForCompletedInferencing {
    pub model: String,
    pub created_at: String,
    pub done: bool,
    pub context: Option<Vec<u32>>,
    pub total_duration: Option<u128>,
    pub load_duration: Option<u128>,
    pub prompt_eval_duration: Option<u128>,
    pub eval_count: Option<u128>,
    pub eval_duration: Option<u128>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OllamaRequest {
    pub model: String,
    pub prompt: String,
    pub stream: Option<bool>,
    pub context: Option<Vec<u128>>,
    pub req_id: String,
}

#[derive(Debug, PartialEq)]
pub struct OllamaSignatureParameters {
    pub model: String,
    pub prompt: String,
    pub request_context: String,
    pub response_context: String,
    pub response: String,
}

#[get("/getPositionInQueue")]
async fn get_position_in_queue(
    person_queue: web::Data<PersonQueue>,
    query_params: web::Query<PositionInQueueParams>,
) -> impl Responder {
    if let Some(position) = person_queue.position_of(&query_params.req_id) {
        let response = json!({"Queue position":position+1,"in-queue":true});
        HttpResponse::build(StatusCode::OK).json(response)
    } else {
        let response = json!({"Queue position":"Not in the queue","in-queue":false});
        HttpResponse::build(StatusCode::OK).json(response)
    }
}

/// Forwards the incoming HTTP request using `awc`.
async fn forward(
    req: HttpRequest,
    mut payload: web::Payload,
    peer_addr: Option<PeerAddr>,
    url: web::Data<Url>,
    client: web::Data<Client>,
    redirect_destination: web::Data<String>,
    person_queue: web::Data<PersonQueue>,
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

    let mut ollama_request_bytes = BytesMut::new();
    while let Some(item) = payload.next().await {
        let item = item?;
        ollama_request_bytes.extend_from_slice(&item);
    }

    let ollama_request_body: OllamaRequest =
        serde_json::from_str(from_utf8(&ollama_request_bytes)?)?;

    person_queue.enqueue(ollama_request_body.req_id.clone());

    let model_prompt = ollama_request_body.prompt.clone();
    let model_request_context = match &ollama_request_body.context.clone() {
        Some(data) => serde_json::to_string(data)?,
        None => "[]".to_string(),
    };

    let res = forwarded_req
        .send_json(&ollama_request_body)
        .await
        .map_err(error::ErrorInternalServerError)?;

    let mut client_resp = HttpResponse::build(res.status());
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.insert_header((header_name.clone(), header_value.clone()));
    }

    let signer = k256::ecdsa::SigningKey::from_slice(
        fs::read("../app/secp256k1.sec")
            .await
            .context("failed to read signer key")
            .unwrap()
            .as_slice(),
    )
    .context("invalid signer key")
    .unwrap();

    let stream_res = res.map(move |chunk_wrapped| {
        let chunk = chunk_wrapped.unwrap();
        let ollama_json_value: OllamaResponse = serde_json::from_slice(&chunk)
            .map_err(|e| {
                error::ErrorInternalServerError(format!("Error deserializing JSON: {}", e))
            })
            .unwrap();

        let mut hasher = Keccak::v256();

        hasher.update(b"|oyster-hasher|");

        let model_name = ollama_json_value.model;
        let model_response = ollama_json_value.response;
        let timestamp = ollama_json_value.created_at.clone();

        let receipt = ethabi::encode(&[
            Token::String(model_name.clone()),
            Token::String(model_prompt.clone()),
            Token::String(model_request_context.clone()),
            Token::String(model_response.clone()),
            Token::String(timestamp),
        ]);

        hasher.update(b"|ollama_signature_parameters|");
        hasher.update(&receipt);

        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        let (rs, v) = signer.sign_prehash_recoverable(&hash).unwrap();

        let signature = rs.to_bytes().append(27 + v.to_byte());
        if ollama_json_value.done == true {
            person_queue.remove(&ollama_request_body.req_id);
            let converted_resp_for_completed_inferencing =
                OllamaConvertedResponseForCompletedInferencing {
                    done: ollama_json_value.done,
                    created_at: ollama_json_value.created_at,
                    model: model_name,
                    context: ollama_json_value.context,
                    eval_count: ollama_json_value.eval_count,
                    eval_duration: ollama_json_value.eval_duration,
                    load_duration: ollama_json_value.load_duration,
                    prompt_eval_duration: ollama_json_value.prompt_eval_duration,
                    total_duration: ollama_json_value.total_duration,
                };
            let final_response: Result<Bytes, PayloadError> = Ok(Bytes::from(
                serde_json::to_string(&converted_resp_for_completed_inferencing).unwrap(),
            ));
            return final_response;
        } else {
            let converted_resp_for_completed_inferencing =
                OllamaConvertedResponseForOngoingInferencing {
                    done: ollama_json_value.done,
                    created_at: ollama_json_value.created_at,
                    model: model_name,
                    response: model_response,
                    oyster_signature: Some(hex::encode(signature.as_slice())),
                };
            let final_response: Result<Bytes, PayloadError> = Ok(Bytes::from(
                serde_json::to_string(&converted_resp_for_completed_inferencing).unwrap() + "\n",
            ));
            return final_response;
        };
    });
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
    let new_person_queue = PersonQueue::new();

    let person_queue = web::Data::new(PersonQueue {
        queue: new_person_queue.queue,
    });

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
            .app_data(person_queue.clone())
            .app_data(web::Data::new(Client::default()))
            .app_data(web::Data::new(forward_url.clone()))
            .app_data(web::Data::new(redirect_destination.clone()))
            .wrap(
                Cors::default()
                    .allowed_origin("http://localhost:3000")
                    .allowed_origin("https://oyster.chat")
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                    .allowed_header(header::CONTENT_TYPE),
            )
            .wrap(middleware::Logger::default())
            .default_service(web::to(forward))
            .service(get_position_in_queue)
    })
    .bind((args.listen_addr, args.listen_port))?
    .workers(2)
    .run()
    .await
}
