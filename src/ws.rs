use std::fmt::Display;
use std::sync::Arc;

use anyhow::Result;
use futures::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{WebSocketStream, accept_async};

use crate::img_mgt::save_image;
use crate::text_mgt::save_text;
use crate::{BIND_IP, SSL_CRT, SSL_KEY, WS_BIND_PORT};

// Define a new trait that combines the required traits
pub trait AsyncReadWriteUnpin: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncReadWriteUnpin for T {}

pub enum StreamType {
    TLS(tokio_rustls::server::TlsStream<TcpStream>),
    PLAIN(TcpStream),
}

// Update the return type to use the new trait
impl StreamType {
    pub fn get_stream(self) -> Box<dyn AsyncReadWriteUnpin + Send> {
        match self {
            StreamType::TLS(s) => Box::new(s),
            StreamType::PLAIN(s) => Box::new(s),
        }
    }
}

#[derive()]
pub struct WebSocket {
    pub tx: SplitSink<WebSocketStream<Box<dyn AsyncReadWriteUnpin + Send + 'static>>, Message>,
    pub rx: SplitStream<WebSocketStream<Box<dyn AsyncReadWriteUnpin + Send + 'static>>>,
}

impl WebSocket {
    pub async fn send_text(&mut self, text: impl AsRef<str>) -> Result<()> {
        let payload = text.as_ref();
        println!("[TX]: {}", payload);
        self.tx.send(Message::Text(payload.into())).await?;
        Ok(())
    }

    pub async fn send_binary(&mut self, data: Vec<u8>) -> Result<()> {
        println!("[TX]: Sending binary data of length {}", data.len());
        self.tx.send(Message::Binary(data.into())).await?;
        Ok(())
    }

    pub async fn send_ping(&mut self, data: Vec<u8>) -> Result<()> {
        println!("[TX]: Sending ping with data: {:?}", data);
        self.tx.send(Message::Ping(data.into())).await?;
        Ok(())
    }

    pub async fn send_pong(&mut self, data: Vec<u8>) -> Result<()> {
        println!("[TX]: Sending pong with data: {:?}", data);
        self.tx.send(Message::Pong(data.into())).await?;
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        println!("[TX]: Closing WebSocket connection");
        self.tx.close().await?;
        Ok(())
    }

    pub async fn new(ws_stream: StreamType) -> Result<Self> {
        let (write, read) = match accept_async(ws_stream.get_stream()).await {
            Ok(ws) => ws.split(),
            Err(e) => {
                eprintln!("WebSocket handshake failed: {}", e);
                return Err(anyhow::anyhow!("WebSocket handshake failed: {}", e));
            }
        };
        println!("WebSocket connection established");
        Ok(WebSocket { tx: write, rx: read })
    }

    pub async fn next(&mut self) -> Option<Result<Message>> {
        self.rx
            .next()
            .await
            .map(|msg| msg.map_err(|e| anyhow::anyhow!("WebSocket error: {}", e)))
    }
}

#[derive(Debug, Deserialize)]
pub struct IncomingImage {
    #[serde(rename = "type")]
    pub file_type: String,
    pub mime: String, // MIME type of the image
    pub data: String, // base64 string
}

impl IncomingImage {
    pub fn base64_data(&self) -> &str {
        self.data.split_once(',').map(|(_, b64)| b64).unwrap_or(&self.data)
    }
}

impl Display for IncomingImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IncomingImage(type: {},  data length: {})",
            self.file_type,
            self.data.len()
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IncomingImageReply {
    pub status: String,
    pub file_type: String,
    pub len: usize,
    pub name: String,
    pub uri: String,
}

impl IncomingImageReply {
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn error(error: impl AsRef<str>) -> Self {
        IncomingImageReply {
            status: format!("Error: {}", error.as_ref()),
            file_type: String::new(),
            len: 0,
            name: String::new(),
            uri: String::new(),
        }
    }
}

pub async fn ws_server() -> anyhow::Result<()> {
    let addr_tls = BIND_IP.to_string() + ":" + WS_BIND_PORT.to_string().as_str();

    let crt_key = PrivateKeyDer::from_pem_file(SSL_KEY).unwrap();
    let crt = CertificateDer::pem_file_iter(SSL_CRT)
        .unwrap()
        .collect::<Vec<_>>()
        .into_iter()
        .map(|e| e.unwrap())
        .collect::<Vec<_>>();

    let tls_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(crt, crt_key)
            .unwrap(),
    );

    let tcp_listener_tls = TcpListener::bind(&addr_tls).await?;

    println!("{:#<100}", "");
    println!("Binding WebSocket server to: {:#?}", &addr_tls);
    println!("{:#<100}", "");

    loop {
        match tcp_listener_tls.accept().await {
            Ok((tcp_stream, _)) => {
                println!("New TLS connection from: {:#?}", tcp_stream.peer_addr());
                // let acceptor = tls_acceptor.accept(tcp_stream).into_fallible();
                let tls_acceptor = TlsAcceptor::from(tls_config.clone());

                tokio::spawn(async move {
                    let mut buf = [0u8; 1];
                    let peekable_stream = tcp_stream;

                    match peekable_stream.peek(&mut buf).await {
                        Ok(0) => {
                            println!("Connection closed before reading any data.");
                            return;
                        }
                        Ok(1) if buf[0] == 0x16 => {
                            println!("Peeked first byte: {:#x}, TLS Connection", buf[0]);
                            ws_handler(StreamType::TLS(tls_acceptor.accept(peekable_stream).await.unwrap())).await;
                        }
                        Ok(_) => {
                            println!("Peeked first byte: {:#x}, not a TLS handshake.", buf[0]);
                            ws_handler(StreamType::PLAIN(peekable_stream)).await;
                        }
                        Err(e) => {
                            eprintln!("Error peeking stream: {}", e);
                            return;
                        }
                    };
                });
            }
            Err(e) => {
                eprintln!("Error accepting TLS connection: {}", e);
            }
        }
    }
}

async fn ws_handler(ws_stream: StreamType) {
    println!("Handling WebSocket connection...");

    // Classic way to manage ws using split
    // let (mut write, mut read) = match accept_async(ws_stream.get_stream()).await {
    //     Ok(ws) => ws.split(),
    //     Err(e) => {
    //         eprintln!("WebSocket handshake failed: {}", e);
    //         return;
    //     }
    // };

    let mut ws = WebSocket::new(ws_stream).await.unwrap();

    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Text(msg)) => match serde_json::from_str::<IncomingImage>(&msg) {
                Ok(incoming_data) => {
                    println!("Received image: {}", incoming_data);
                    let reply = match &incoming_data.mime {
                        mime if mime.starts_with("image/") => {
                            println!("Processing image data...");
                            save_image(&incoming_data).await
                        }

                        mime if mime.starts_with("text/") => {
                            println!("Processing text data...");
                            save_text(&incoming_data).await
                        }

                        _ => {
                            eprintln!("Received unknown data: {}", incoming_data.mime);
                            Ok(IncomingImageReply {
                                status: "Error, Received unknown data".to_string(),
                                file_type: incoming_data.file_type.clone(),
                                len: 0,
                                name: "".to_string(),
                                uri: "".to_string(),
                            })
                        }
                    };
                    let _ = match reply {
                        Ok(reply) => ws.send_text(reply.to_json()).await,
                        Err(e) => {
                            eprintln!("Error processing image: {}", e);
                            ws.send_text(IncomingImageReply::error(e.to_string()).to_json()).await
                        }
                    };
                }
                Err(e) => {
                    eprintln!("Failed to deserialize incoming image: {}", e);
                }
            },
            Ok(Message::Ping(b)) => {
                println!("Received ping: {:?}", b);
                if let Err(e) = ws.send_pong(b.to_vec()).await {
                    eprintln!("Error sending pong: {}", e);
                }
            }

            Ok(Message::Pong(b)) => {
                println!("Received pong {}", String::from_utf8_lossy(&b));
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
                break;
            }
        }
    }
}
