use anyhow::Result;
use base64::Engine;

use crate::ws::{IncomingImage, IncomingImageReply};

static DATA_DIR: &str = "./DATA/IMG/";
static DATA_URI: &str = "black_hole";

pub async fn save_image(img: &IncomingImage) -> Result<IncomingImageReply> {
    use std::fs;
    use std::path::Path;

    let file_name = uuid::Uuid::new_v4().to_string();

    fs::create_dir_all(DATA_DIR)?;

    // Construct the file path
    let file_path = Path::new(DATA_DIR).join(&file_name);

    // Decode the base64 data
    let mut decoded_data = vec![];
    base64::engine::general_purpose::STANDARD
        .decode_vec(&img.base64_data(), &mut decoded_data)
        .map_err(|e| anyhow::anyhow!("Failed to decode base64 data: {}", e))?;

    // Write the decoded data to the file
    fs::write(file_path, &decoded_data)?;

    let reply = IncomingImageReply {
        status: "OK".to_string(),
        file_type: img.file_type.clone(),
        len: decoded_data.len(),
        name: file_name.clone(),
        uri: format!("{}/{}", DATA_URI, file_name),
    };
    // Return the file name
    println!("Saved image: {:#?}", reply);
    Ok(reply)
}
