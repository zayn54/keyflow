use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt};
use sled;
use bcrypt::{hash, verify, DEFAULT_COST};
use indicatif::{ProgressBar, ProgressStyle, ProgressDrawTarget};
use tokio::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use base64::engine::general_purpose;
use base64::Engine;
use ed25519_dalek::{PublicKey as EdPublicKey, Signature as EdSignature, Verifier};
use tokio::sync::mpsc;

// Simple JSON framed protocol: length-prefix (u32 BE) + JSON payload

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum Message {
    Register { username: String, public_key_b64: String, password: String, id_pk_b64: String, sig_b64: String },
    Login { username: String, password: String },
    GetPublicKey { username: String },
    PublicKey { username: String, public_key_b64: String },
    Typing { from: String, to: String, typing: bool },
    Encrypted { from: String, to: String, nonce_b64: String, ciphertext_b64: String },
    Shutdown { msg: String },
    Error { msg: String },
}

struct ClientHandle {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    public_key_b64: String,
}

struct ServerState {
    clients: HashMap<String, ClientHandle>,
    offline: HashMap<String, Vec<Vec<u8>>>,
    db: sled::Db,
}

#[tokio::main]
async fn main() -> Result<()> {
    // show a startup progress bar while opening DB and binding
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_message("starting server...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let db = sled::open("chat_server_db")?;

    let listener = TcpListener::bind("0.0.0.0:4000").await?;
    pb.finish_with_message("server started");
    println!("Server listening on 0.0.0.0:4000");

    // Shared state: clients and offline message queues
    let state: Arc<Mutex<ServerState>> = Arc::new(Mutex::new(ServerState { clients: HashMap::new(), offline: HashMap::new(), db }));

    // shutdown signal (watch) - send true to shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // spawn a task to read server stdin and trigger shutdown on line "shut down"
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = stdin.next_line().await {
            let l = line.trim().to_lowercase();
            if l == "shut down" || l == "shutdown" {
                println!("Shutdown requested via stdin");
                let _ = shutdown_tx_clone.send(true);
                break;
            }
        }
    });

    loop {
        tokio::select! {
            biased;
            // if shutdown signal received, break the accept loop
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    println!("Shutting down server...");
                    // notify all connected clients that server is shutting down
                    let mut st = state.lock().await;

                    // collect client usernames so we can log after sending
                    let client_names: Vec<String> = st.clients.keys().cloned().collect();

                    for (_name, handle) in st.clients.iter() {
                        let shutdown_msg = Message::Shutdown { msg: "server shutting down".to_string() };
                        // try to send Shutdown first
                        let _ = handle.tx.send(serde_json::to_vec(&shutdown_msg).unwrap());
                        // follow up with Error for backward compatibility
                        let err = Message::Error { msg: "server shutting down".to_string() };
                        let _ = handle.tx.send(serde_json::to_vec(&err).unwrap());
                    }

                    // drop all senders by clearing clients map so writer tasks observe channel closed
                    st.clients.clear();

                    // allow a short grace period for writer tasks to flush their outbound frames
                    drop(st);
                    tokio::time::sleep(Duration::from_millis(500)).await;

                    for name in client_names.iter() {
                        println!("Notified {} of shutdown", name);
                    }

                    break;
                }
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((socket, _)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(socket, state).await {
                                eprintln!("Connection error: {:?}", e);
                            }
                        });
                    }
                    Err(e) => eprintln!("accept error: {:?}", e),
                }
            }
        }
    }
    // finished accept loop (shutdown requested)
    Ok(())
}

async fn handle_connection(socket: TcpStream, state: Arc<Mutex<ServerState>>) -> Result<()> {
    // Create channel to send bytes to this connection writer task
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // Writer task
    let (mut read_socket, mut write_socket) = tokio::io::split(socket);
    tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            if let Err(e) = write_all_frame(&mut write_socket, &buf).await {
                eprintln!("Writer error: {:?}", e);
                break;
            }
        }
    });

    // Reader loop
    let mut username_opt: Option<String> = None;

    loop {
        let msg_bytes = match read_frame(&mut read_socket).await {
            Ok(b) => b,
            Err(_) => break,
        };

        let msg: Message = serde_json::from_slice(&msg_bytes)?;

        match msg {
            Message::Register { username, public_key_b64, password, id_pk_b64, sig_b64 } => {
                // check DB for existing username
                let mut st = state.lock().await;
                let users = st.db.open_tree("users")?;
                if users.get(username.as_bytes())?.is_some() {
                    let err = Message::Error { msg: format!("username {} already taken", username) };
                    tx.send(serde_json::to_vec(&err)?)?;
                    continue;
                }

                // require non-empty password
                if password.trim().is_empty() {
                    let err = Message::Error { msg: "password cannot be empty".to_string() };
                    tx.send(serde_json::to_vec(&err)?)?;
                    continue;
                }

                // hash password using bcrypt
                let password_hash = hash(password, DEFAULT_COST)?;
                users.insert(username.as_bytes(), password_hash.as_bytes())?;

                // verify identity signature and persist identity public key and x25519 pubkey
                let id_pk_bytes = general_purpose::STANDARD.decode(&id_pk_b64)?;
                let sig_bytes = general_purpose::STANDARD.decode(&sig_b64)?;
                let id_pk = EdPublicKey::from_bytes(&id_pk_bytes).map_err(|e| anyhow::anyhow!(e))?;
                let sig = EdSignature::from_bytes(&sig_bytes).map_err(|e| anyhow::anyhow!(e))?;
                // payload the client is expected to sign: username + public_key_b64
                let payload = format!("{}:{}", username, public_key_b64);
                id_pk.verify(payload.as_bytes(), &sig).map_err(|_| anyhow::anyhow!("invalid signature"))?;

                let pubkeys = st.db.open_tree("pubkeys")?;
                pubkeys.insert(username.as_bytes(), public_key_b64.as_bytes())?;
                let idtree = st.db.open_tree("idkeys")?;
                idtree.insert(username.as_bytes(), id_pk_bytes)?;

                // register connection
                st.clients.insert(username.clone(), ClientHandle { tx: tx.clone(), public_key_b64: public_key_b64.clone() });
                username_opt = Some(username.clone());
                println!("{} registered", username);

                // deliver any queued offline messages
                if let Some(queue) = st.offline.remove(&username) {
                    for pkt in queue {
                        let _ = tx.send(pkt);
                    }
                }
                // broadcast public key to everyone (optional)
                for (_other, handle) in st.clients.iter() {
                    let pk_msg = Message::PublicKey { username: username.clone(), public_key_b64: public_key_b64.clone() };
                    let pkt = serde_json::to_vec(&pk_msg)?;
                    let _ = handle.tx.send(pkt);
                }
            }

            Message::Login { username, password } => {
                println!("Login attempt for {}", username);
                let mut st = state.lock().await;
                let users = st.db.open_tree("users")?;
                if let Some(stored) = users.get(username.as_bytes())? {
                    let stored_str = std::str::from_utf8(&stored)?;
                    let auth_ok = if stored_str.is_empty() {
                        // account created without password: accept only empty password
                        password.is_empty()
                    } else {
                        verify(password, stored_str).unwrap_or(false)
                    };

                    if auth_ok {
                        // successful login - attach tx and restore stored public key (if any)
                        let pubkeys = st.db.open_tree("pubkeys")?;
                        let stored_pk = if let Some(v) = pubkeys.get(username.as_bytes())? {
                            String::from_utf8(v.to_vec())?
                        } else {
                            String::new()
                        };

                        st.clients.insert(username.clone(), ClientHandle { tx: tx.clone(), public_key_b64: stored_pk.clone() });
                        username_opt = Some(username.clone());
                        println!("{} logged in", username);

                        // send a success response back to the client (include stored public key if present)
                        let ok = Message::PublicKey { username: username.clone(), public_key_b64: stored_pk.clone() };
                        tx.send(serde_json::to_vec(&ok)?)?;

                        // deliver any queued offline messages for this user
                        if let Some(queue) = st.offline.remove(&username) {
                            for pkt in queue {
                                let _ = tx.send(pkt);
                            }
                        }

                        // broadcast public key to everyone (if we have one)
                        if !stored_pk.is_empty() {
                            for (_other, handle) in st.clients.iter() {
                                let pk_msg = Message::PublicKey { username: username.clone(), public_key_b64: stored_pk.clone() };
                                let pkt = serde_json::to_vec(&pk_msg)?;
                                let _ = handle.tx.send(pkt);
                            }
                        }
                    } else {
                        let err = Message::Error { msg: "invalid credentials".to_string() };
                        tx.send(serde_json::to_vec(&err)?)?;
                    }
                } else {
                    let err = Message::Error { msg: format!("user {} not found", username) };
                    tx.send(serde_json::to_vec(&err)?)?;
                }
            }

            Message::GetPublicKey { username } => {
                let st = state.lock().await;
                if let Some(handle) = st.clients.get(&username) {
                    let reply = Message::PublicKey { username: username.clone(), public_key_b64: handle.public_key_b64.clone() };
                    let pkt = serde_json::to_vec(&reply)?;
                    tx.send(pkt)?;
                } else {
                    // try persisted pubkey
                    let pubkeys = st.db.open_tree("pubkeys")?;
                    if let Some(v) = pubkeys.get(username.as_bytes())? {
                        let pk_str = String::from_utf8(v.to_vec())?;
                        let reply = Message::PublicKey { username: username.clone(), public_key_b64: pk_str.clone() };
                        let pkt = serde_json::to_vec(&reply)?;
                        tx.send(pkt)?;
                        println!("Provided stored public key for {}", username);
                    } else {
                        let err = Message::Error { msg: format!("user {} not found", username) };
                        tx.send(serde_json::to_vec(&err)?)?;
                    }
                }
            }

            Message::Typing { from, to, typing } => {
                // forward typing notifications to recipient if connected
                let st = state.lock().await;
                // prefer the authenticated username if available to avoid trivial spoofing
                let sender_name = username_opt.clone().unwrap_or(from.clone());
                if sender_name != from {
                    eprintln!("Warning: Typing claimed from {} but connection authenticated as {}", from, sender_name);
                }
                if let Some(recipient) = st.clients.get(&to) {
                    let pkt = serde_json::to_vec(&Message::Typing { from: sender_name.clone(), to: to.clone(), typing })?;
                    if let Err(e) = recipient.tx.send(pkt) {
                        eprintln!("Failed to forward typing to {}: {:?}", to, e);
                    }
                } else {
                    // recipient offline — ignore typing notifications
                }
            }

            Message::Encrypted { from, to, nonce_b64, ciphertext_b64 } => {
                // We'll try to forward the message with a small progress indicator.
                // Acquire the state lock only to grab necessary handles/values, then drop it
                // so we don't block other connections while showing the progress bar or sleeping.
                let mut st = state.lock().await;
                if let Some(recipient_handle) = st.clients.get(&to) {
                    let recipient_tx = recipient_handle.tx.clone();

                    // get sender public key (either live or persisted)
                    let sender_pk = if let Some(sender_handle) = st.clients.get(&from) {
                        sender_handle.public_key_b64.clone()
                    } else {
                        let pubkeys = st.db.open_tree("pubkeys")?;
                        if let Some(v) = pubkeys.get(from.as_bytes())? {
                            String::from_utf8(v.to_vec())?
                        } else {
                            String::new()
                        }
                    };

                    // drop the lock before doing any sleeps or blocking work
                    drop(st);

                    // textual log for non-interactive logs
                    println!("Forwarding {} -> {} ...", from, to);

                    // show a more visible linear progress bar for forwarding
                    let pb = ProgressBar::new(10);
                    // ensure we draw to stdout so it's visible in the terminal
                    pb.set_draw_target(ProgressDrawTarget::stdout());
                    pb.set_style(ProgressStyle::with_template("[{bar:40.cyan/blue}] {pos}/{len} {msg}").unwrap());
                    pb.set_message("preparing");
                    pb.inc(1);
                    tokio::time::sleep(Duration::from_millis(200)).await;

                    if !sender_pk.is_empty() {
                        let pk_msg = Message::PublicKey { username: from.clone(), public_key_b64: sender_pk };
                        let pk_pkt = serde_json::to_vec(&pk_msg)?;
                        let _ = recipient_tx.send(pk_pkt);
                    }

                    pb.set_message("forwarding");
                    pb.inc(2);
                    tokio::time::sleep(Duration::from_millis(200)).await;

                    let forward = Message::Encrypted { from: from.clone(), to: to.clone(), nonce_b64, ciphertext_b64 };
                    let pkt = serde_json::to_vec(&forward)?;
                    match recipient_tx.send(pkt.clone()) {
                        Ok(()) => {
                            println!("Forwarded message to {}", to);
                            pb.inc(7);
                            pb.finish_with_message("delivered");
                            println!("Forwarding {} -> {} done", from, to);
                        }
                        Err(e) => {
                            // recipient channel closed: queue for offline delivery (re-lock to modify state)
                            eprintln!("Failed to send to {}: {:?}, queueing", to, e);
                            let mut st = state.lock().await;
                            st.offline.entry(to.clone()).or_insert_with(Vec::new).push(pkt);
                            pb.finish_with_message("queued");
                            println!("Forwarding {} -> {} queued", from, to);
                        }
                    }
                } else {
                    // recipient offline, queue message for offline delivery
                    let forward = Message::Encrypted { from: from.clone(), to: to.clone(), nonce_b64, ciphertext_b64 };
                    let pkt = serde_json::to_vec(&forward)?;
                    st.offline.entry(to.clone()).or_insert_with(Vec::new).push(pkt);
                    let ack = Message::Error { msg: format!("recipient {} not connected, message queued", to) };
                    tx.send(serde_json::to_vec(&ack)?)?;
                }
            }

            other => {
                // ignore other messages at server
                eprintln!("Unhandled message on server: {:?}", other);
            }
        }
    }

    // Connection closed -> remove client
    if let Some(username) = username_opt {
        let mut st = state.lock().await;
        st.clients.remove(&username);
        println!("{} disconnected", username);
    }

    Ok(())
}

// --- framing helpers ---
use tokio::io::{AsyncRead, AsyncWrite};

async fn read_frame<R>(socket: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_all_frame<W>(socket: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let len = (data.len() as u32).to_be_bytes();
    socket.write_all(&len).await?;
    socket.write_all(data).await?;
    Ok(())
}
