#[macro_use]
extern crate rocket;

pub mod img_mgt;
pub mod text_mgt;
pub mod ws;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use base64::Engine;
use rocket::fs::{FileServer, relative};
use rocket::http::Status;
use rocket::response::Redirect;
use rocket_dyn_templates::Template;
use tokio::fs;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReadDirStream;
use ws::ws_server;

pub static SSL_KEY: &str = "./crt/192.168.1.46.pem";
pub static SSL_CRT: &str = "./crt/192.168.1.46.crt";
pub static BIND_IP: &str = "0.0.0.0";
pub static WS_BIND_PORT: u16 = 54321;

#[get("/")]
fn index() -> Redirect {
    Redirect::to(uri!("/html/BlackHole.html"))
}

#[get("/black_hole/<file..>")]
async fn display_image(file: PathBuf) -> Result<Template, Status> {
    let base_dir = Path::new("./DATA");

    // Convert Option to Result to handle errors properly
    let file_name = file.file_name().and_then(|f| f.to_str()).ok_or(Status::NotFound)?;

    let file_list = list_files_recursive(base_dir.to_path_buf()).await;

    println!("file list: {:#?}", file_list);

    let matched_path = file_list
        .into_iter()
        .find(|path| path.file_name().and_then(|f| f.to_str()) == Some(file_name))
        .ok_or(Status::NotFound)?;

    println!("Matched file path: {:?}", matched_path);

    // Read the file bytes
    let file_bytes = fs::read(&matched_path).await.map_err(|_| Status::NotFound)?;
    println!("File bytes read successfully, length: {}", file_bytes.len());
    // Determine the MIME type of the file
    let mime_type = tree_magic_mini::from_u8(&file_bytes);
    println!("MIME type: {}", mime_type);

    match mime_type {
        val if val.starts_with("image") => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(file_bytes);
            let mut payload = HashMap::new();
            payload.insert("base64_image", b64);
            return Ok(Template::render("display_image", &payload));
        }
        val if val.starts_with("text") => {
            println!("File is MIME type: {}", val);
            let mut payload = HashMap::new();
            payload.insert("content", String::from_utf8(file_bytes).unwrap());
            return Ok(Template::render("display_text", &payload));
        }
        _ => {
            println!("Unsupported file type: {}", mime_type);
            return Err(Status::NotFound);
        }
    }
    // Base64 encode
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http_config = rocket::Config {
        address: BIND_IP.parse::<IpAddr>().unwrap(),
        port: 80,
        ..rocket::Config::default()
    };

    let rocket_http = rocket::custom(http_config)
        .attach(rocket_dyn_templates::Template::fairing())
        .mount("/", routes![index])
        .mount("/html", FileServer::from(relative!("html")))
        .mount("/", routes![display_image]);

    let rocket_https = rocket::custom(rocket::Config {
        address: BIND_IP.parse::<IpAddr>().unwrap(),
        port: 443,
        tls: Some(rocket::config::TlsConfig::from_paths(SSL_CRT, SSL_KEY)),
        ..rocket::Config::default()
    });

    tokio::spawn(async move {
        println!("Starting HTTP server on port 80...");
        rocket_http.launch().await.unwrap();
    });

    // Spawn the WebSocket server in a task
    tokio::spawn(async {
        if let Err(e) = ws_server().await {
            eprintln!("WebSocket server error: {}", e);
        }
    });

    println!("Starting HTTPS server on port 443...");
    // Build and launch Rocket
    rocket_https
        .attach(rocket_dyn_templates::Template::fairing())
        .mount("/", routes![index])
        .mount("/html", FileServer::from(relative!("html")))
        .mount("/", routes![display_image])
        .launch()
        .await?;

    Ok(())
}

async fn list_files_recursive(dir: PathBuf) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut dirs_to_visit = vec![dir];

    while let Some(current_dir) = dirs_to_visit.pop() {
        let read_dir = match fs::read_dir(&current_dir).await {
            Ok(rd) => rd,
            Err(e) => {
                eprintln!("Failed to read dir {}: {}", current_dir.display(), e);
                continue;
            }
        };

        let mut stream = ReadDirStream::new(read_dir);
        while let Some(entry_result) = stream.next().await {
            match entry_result {
                Ok(entry) => {
                    let path = entry.path();
                    match entry.file_type().await {
                        Ok(ft) if ft.is_dir() => dirs_to_visit.push(path),
                        Ok(ft) if ft.is_file() => files.push(path),
                        Ok(_) => {} // Ignore symlinks/special
                        Err(e) => eprintln!("Failed to get type for {}: {}", path.display(), e),
                    }
                }
                Err(e) => eprintln!("Failed to read entry: {}", e),
            }
        }
    }

    files
}
