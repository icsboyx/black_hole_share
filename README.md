# Black Hole Share

Black Hole Share is a simple web-based tool for uploading, pasting, and sharing images or text It features a drag-and-drop interface, clipboard support, and real-time uploads via WebSockets, with all assets stored locally on the server.

## Features

- **Unified Upload & Paste:** Drag, drop, paste, or select images and text to upload.
- **WebSocket-based Uploads:** Fast, real-time transfer of files and text.
- **Automatic Previews:** See image previews or text content before sharing.
- **Shareable Links:** Get a direct link to each uploaded asset for easy sharing.
- **Dark/Light Theme Toggle:** User-friendly interface with theme support.
- **Local Storage:** All files are stored in the `DATA/IMG` and `DATA/TEXT` directories on the server.

## Project Structure

```
.
├── Cargo.toml
├── src/
│   ├── main.rs         # Rocket web server and route handlers
│   ├── ws.rs           # WebSocket server and protocol
│   ├── img_mgt.rs      # Image saving logic
│   ├── text_mgt.rs     # Text saving logic
├── html/
│   ├── BlackHole.html  # Main frontend UI
│   ├── style.css       # Stylesheet
├── templates/
│   ├── display_image.html.tera # Image display template
│   ├── display_text.html.tera  # Text/code display template
├── DATA/
│   ├── IMG/            # Uploaded images
│   ├── TEXT/           # Uploaded text files
├── crt/                # TLS certificates for HTTPS/WSS
```

## Usage

1. **Build and Run the Server**

   ```sh
   cargo run
   ```

    The server listens on both HTTP (port 80) and HTTPS (port 443), and WebSocket on port 54321. 
    Ensure you have the necessary TLS certificates in the `crt/` directory for secure connections.
    If you want to run the server without TLS, you can modify the `main.rs` file to disable HTTPS and WebSocket secure connections.

   If you are using port 80 and 443, you may need to run the server with elevated privileges (e.g., using `sudo` on Linux). Alternatively, you can change the ports in `src/main.rs` to non-privileged ports (e.g., 8080 for HTTP and 8443 for HTTPS).

   ```sh
   sudo -E cargo run --release
   ```


2. **Access the Web Interface**

   Open your browser and navigate to:

   ```
   http://<server-ip>/html/BlackHole.html
   ```

   or (for HTTPS):

   ```
   https://<server-ip>/html/BlackHole.html
   ```

3. **Upload or Paste**

   - Drag and drop an image or text, paste from clipboard, or click to select a file.
   - After upload, a shareable link is provided.

## Configuration

- **TLS Certificates:** Place your `.crt` and `.pem` files in the `./crt/` directory. \
  SSL KEY server.pem \
  SSL CERT server.crt

- **Data Storage:** Uploaded files are saved in `DATA/IMG` (images) and `DATA/TEXT` (text).
- **WebSocket Port:** Default is `54321` (see [`WS_BIND_PORT`](src/main.rs)).

## Dependencies

- [Rocket](https://rocket.rs/) (web framework)
- [tokio](https://tokio.rs/) (async runtime)
- [serde](https://serde.rs/) (serialization)
- [base64](https://crates.io/crates/base64) (encoding/decoding)
- [uuid](https://crates.io/crates/uuid) (unique file names)
- [tree_magic_mini](https://crates.io/crates/tree_magic_mini) (MIME type detection)

## Security

- All uploads are local to the server.
- HTTPS/WSS is supported for secure transfers (requires valid certificates).

## License

MIT [LICENSE](LICENSE)

---

