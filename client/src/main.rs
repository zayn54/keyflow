use base64::Engine;
use base64::engine::general_purpose;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use chrono::Local;
use colored::Colorize;
use ed25519_dalek::{
    Keypair as EdKeypair, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, Signer as EdSigner,
};
use getrandom::getrandom;
use hkdf::Hkdf;
use indicatif::{ProgressBar, ProgressStyle};
use rpassword;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::{Duration, sleep};
use x25519_dalek::{PublicKey, StaticSecret};
use std::io::{self, Write};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum Message {
    Register {
        username: String,
        public_key_b64: String,
        password: String,
        id_pk_b64: String,
        sig_b64: String,
    },
    Login {
        username: String,
        password: String,
    },
    GetPublicKey {
        username: String,
    },
    PublicKey {
        username: String,
        public_key_b64: String,
    },
    Encrypted {
        from: String,
        to: String,
        nonce_b64: String,
        ciphertext_b64: String,
    },
    Shutdown { msg: Option<String>, grace_seconds: Option<u64> },
    Error {
        msg: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // args: <username> [login] [origin]
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: client <username> [login] [origin]");
        std::process::exit(1);
    }
    let username = args[0].clone();
    let login_mode = args.get(1).map(|s| s == "login").unwrap_or(false);
    let origin = args
        .get(if login_mode { 2 } else { 1 })
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    // Ask user for Ngrok address (IP port)
    print!("Enter Ngrok address (e.g. 0.tcp.in.ngrok.io:4000): ");
    io::stdout().flush().unwrap();
    let mut ngrok_addr = String::new();
    io::stdin().read_line(&mut ngrok_addr).unwrap();
    let ngrok_addr = ngrok_addr.trim().to_string();


    // 1) load or create persistent x25519 static secret and public key
    use std::fs;
    use std::path::Path;
    let secret_path = Path::new(".chat_secret");
    let my_secret = if secret_path.exists() {
        let data = fs::read(secret_path)?;
        if data.len() != 32 {
            return Err(anyhow::anyhow!("invalid secret file length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[..32]);
        StaticSecret::from(arr)
    } else {
        let mut secret_bytes = [0u8; 32];
        getrandom(&mut secret_bytes).map_err(|e| anyhow::anyhow!(e))?;
        fs::write(secret_path, &secret_bytes)?;
        StaticSecret::from(secret_bytes)
    };
    let my_public = PublicKey::from(&my_secret);

    // 2) connect to server (show line progress bar)
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::with_template("{bar:40.cyan/blue} {pos:>3}% {msg}")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message(format!("connecting to {}...", ngrok_addr));

    // Smooth progress: tick an interval and update the bar until connect completes
    let mut interval = tokio::time::interval(Duration::from_millis(80));
    let connect_fut = TcpStream::connect(&ngrok_addr);
    tokio::pin!(connect_fut);
    let mut pos = 0u64;
    let mut socket = loop {
        tokio::select! {
            biased;
            // try to complete connect
            res = &mut connect_fut => {
                let s = res.map_err(|e| anyhow::anyhow!(e))?;
                pos = 100;
                pb.set_position(pos);
                break s;
            }
            _ = interval.tick() => {
                // advance smoothly and wrap slowly to avoid hitting 100% before connect
                if pos < 98 { pos = (pos + 3).min(98); }
                pb.set_position(pos);
            }
        }
    };
    pb.set_position(100);
    pb.finish_with_message("connected");

    // prompt for password
    let mut password = rpassword::prompt_password("Password: ")?;

    // load or create ed25519 identity keypair (.chat_id)
    let id_path = std::path::Path::new(".chat_id");
    let ed_keypair: EdKeypair = if id_path.exists() {
        let data = fs::read(id_path)?;
        if data.len() != SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH {
            return Err(anyhow::anyhow!("invalid id file length"));
        }
        // ed25519-dalek expects bytes: secret(32) + public(32)
        let kp = EdKeypair::from_bytes(&data)?;
        kp
    } else {
        // generate new keypair using getrandom (avoid rand_core version conflicts)
        let mut seed = [0u8; 32];
        getrandom(&mut seed).map_err(|e| anyhow::anyhow!(e))?;
        let secret = ed25519_dalek::SecretKey::from_bytes(&seed)?;
        let public = ed25519_dalek::PublicKey::from(&secret);
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&secret.to_bytes());
        bytes[32..].copy_from_slice(&public.to_bytes());
        fs::write(id_path, &bytes)?;
        let kp = EdKeypair::from_bytes(&bytes)?;
        kp
    };

    // prepare id pk and signature for registration payload
    let id_pk_b64 = general_purpose::STANDARD.encode(ed_keypair.public.to_bytes());

    // register or login depending on flag
    if login_mode {
        let login = Message::Login {
            username: username.clone(),
            password: password.clone(),
        };
        send_frame(&mut socket, &serde_json::to_vec(&login)?).await?;
        println!("{}", "Attempting login...".yellow());
    } else {
        // sign payload username:public_key_b64
        let payload = format!(
            "{}:{}",
            username,
            general_purpose::STANDARD.encode(my_public.as_bytes())
        );
        let sig = ed_keypair.sign(payload.as_bytes());
        let sig_b64 = general_purpose::STANDARD.encode(sig.to_bytes());

        let reg = Message::Register {
            username: username.clone(),
            public_key_b64: general_purpose::STANDARD.encode(my_public.as_bytes()),
            password: password.clone(),
            id_pk_b64: id_pk_b64.clone(),
            sig_b64: sig_b64.clone(),
        };
        send_frame(&mut socket, &serde_json::to_vec(&reg)?).await?;
        println!("{}", "Attempting registration...".green());
    }

    // spawn reader task that forwards parsed messages to `rx`
    let (mut read_socket, mut write_socket) = socket.into_split();
    let (tx, mut rx) = unbounded_channel::<Message>();

    tokio::spawn(async move {
        loop {
            match read_frame(&mut read_socket).await {
                Ok(bytes) => {
                    if let Ok(msg) = serde_json::from_slice::<Message>(&bytes) {
                        // send parsed message to main task
                        if let Err(e) = tx.send(msg) {
                            eprintln!("channel send error: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("read error: {:?}", e);
                    break;
                }
            }
        }
    });

    // registration/login flow: if server returns "already taken" we'll attempt login automatically
    // CLI + incoming message handling
    // We'll keep a cache of public keys and a pending queue for messages awaiting a public key.
    let mut pubkeys: HashMap<String, PublicKey> = HashMap::new();
    let mut pending_incoming: HashMap<String, Vec<(String, Vec<u8>, Vec<u8>)>> = HashMap::new();
    let mut pending_outgoing: HashMap<String, Vec<String>> = HashMap::new();
    let mut pending_getshow: HashMap<String, Vec<()>> = HashMap::new();

    // Async stdin lines
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    loop {
        tokio::select! {
            // incoming parsed messages from server
            Some(msg) = rx.recv() => {
                match msg {
                    Message::PublicKey { username: u, public_key_b64 } => {
                        // store public key in cache
                        if let Ok(pk_bytes) = general_purpose::STANDARD.decode(&public_key_b64) {
                            if let Ok(arr) = <[u8;32]>::try_from(pk_bytes.as_slice()) {
                                let pk = PublicKey::from(arr);
                                pubkeys.insert(u.clone(), pk);
                                // if we have pending incoming messages for this user, attempt to decrypt and print
                                if let Some(list) = pending_incoming.remove(&u) {
                                    for (from, nonce_bytes, ciphertext) in list {
                                        if let Some(sender_pk) = pubkeys.get(&from) {
                                            if let Ok(plaintext) = decrypt_message(&my_secret, sender_pk, &nonce_bytes, &ciphertext) {
                                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
                                                println!("{} [{}] {}", from.blue(), ts.to_string().dimmed(), plaintext);
                                            } else {
                                                eprintln!("failed to decrypt message from {}", from);
                                            }
                                        }
                                    }
                                }
                                // if someone requested getshow for this user, print fingerprint
                                if let Some(_reqs) = pending_getshow.remove(&u) {
                                    // compute SHA-256 fingerprint of public key
                                    let fp = Sha256::digest(arr);
                                    println!("Public key for {}: {}", u, hex::encode(fp));
                                }
                                // if we have pending outgoing messages waiting for this user's key, send them
                                if let Some(list) = pending_outgoing.remove(&u) {
                                    for plaintext in list {
                                        if let Some(pk) = pubkeys.get(&u) {
                                            // derive and send
                                            let shared = my_secret.diffie_hellman(pk);
                                            // HKDF-based key derivation
                                            let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
                                            let mut okm = [0u8;32];
                                            hk.expand(b"chat encryption key", &mut okm).map_err(|_| anyhow::anyhow!("hkdf expand failed"))?;
                                            let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&okm));
                                            let mut nonce_bytes = [0u8; 24];
                                            getrandom(&mut nonce_bytes).map_err(|e| anyhow::anyhow!(e))?;
                                            let nonce = XNonce::from_slice(&nonce_bytes);
                                            let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).expect("encryption failure");

                                            // show a tiny progress bar for sending
                                            let pb = ProgressBar::new(3);
                                            pb.set_style(ProgressStyle::with_template("{spinner:.green} {msg}").unwrap());
                                            pb.set_message("Encrypting...");
                                            pb.inc(1);
                                            sleep(Duration::from_millis(100)).await;
                                            pb.set_message("Sending...");
                                            let packet = Message::Encrypted {
                                                from: username.clone(),
                                                to: u.clone(),
                                                nonce_b64: general_purpose::STANDARD.encode(&nonce_bytes),
                                                ciphertext_b64: general_purpose::STANDARD.encode(&ciphertext),
                                            };
                                            send_frame(&mut write_socket, &serde_json::to_vec(&packet)?).await?;
                                            pb.inc(1);
                                            sleep(Duration::from_millis(100)).await;
                                            pb.finish_with_message("sent");
                                            let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
                                            println!("{} [{}] {}", username.green(), ts.to_string().dimmed(), "message sent");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Message::Encrypted { from, nonce_b64, ciphertext_b64, to: _ } => {
                        // decode nonce + ciphertext
                        match (general_purpose::STANDARD.decode(&nonce_b64), general_purpose::STANDARD.decode(&ciphertext_b64)) {
                            (Ok(nonce_bytes), Ok(ciphertext)) => {
                                // try to find sender's public key
                                if let Some(sender_pk) = pubkeys.get(&from) {
                                    match decrypt_message(&my_secret, sender_pk, &nonce_bytes, &ciphertext) {
                                        Ok(pt) => {
                                            let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
                                            println!("{} [{}] {}", from.blue(), ts.to_string().dimmed(), pt);
                                        }
                                        Err(err) => {
                                            eprintln!("failed to decrypt message from {}: {}", from, err);
                                            // Diagnostic info: sender pubkey fingerprint, derived HKDF prefix, nonce/ciphertext sizes
                                            let pk_bytes = sender_pk.as_bytes();
                                            let pk_fp = Sha256::digest(pk_bytes);
                                            eprintln!("sender pubkey sha256: {}", hex::encode(pk_fp));
                                            // derive HKDF key to show prefix
                                            // Compute derived key (same as decrypt) for visibility
                                            let shared = my_secret.diffie_hellman(sender_pk);
                                            let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
                                            let mut okm = [0u8;32];
                                            if hk.expand(b"chat encryption key", &mut okm).is_ok() {
                                                eprintln!("derived key (prefix): {}", hex::encode(&okm[..8]));
                                            }
                                            eprintln!("nonce len: {}, ciphertext len: {}", nonce_bytes.len(), ciphertext.len());
                                            eprintln!("nonce prefix: {}", hex::encode(&nonce_bytes[..std::cmp::min(8, nonce_bytes.len())]));
                                            eprintln!("ciphertext prefix: {}", hex::encode(&ciphertext[..std::cmp::min(8, ciphertext.len())]));
                                        }
                                    }
                                } else {
                                    // request sender's public key and queue message
                                    let req = Message::GetPublicKey { username: from.clone() };
                                    if let Err(e) = send_frame(&mut write_socket, &serde_json::to_vec(&req)?).await {
                                        eprintln!("failed to request public key: {}", e);
                                    } else {
                                        pending_incoming.entry(from.clone()).or_default().push((from.clone(), nonce_bytes, ciphertext));
                                        println!("{}", format!("received encrypted message from {} (queued until public key arrives)", from).yellow());
                                    }
                                }
                            }
                            _ => eprintln!("received malformed encrypted message"),
                        }
                    }
                    Message::Shutdown { msg, grace_seconds } => {
                        // Friendly shutdown message from server
                        if let Some(m) = msg {
                            println!("Server shutdown: {}", m);
                        } else {
                            println!("Server requested shutdown");
                        }
                        // Determine grace period: prefer message-specified value, then env var, else default 5s
                        let default_grace = std::env::var("CHAT_SHUTDOWN_GRACE").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(5u64);
                        let grace = grace_seconds.unwrap_or(default_grace);
                        println!("Disconnecting in {} seconds...", grace);
                        sleep(Duration::from_secs(grace)).await;
                        let _ = write_socket.shutdown().await;
                        break;
                    }

                    Message::Error { msg } => {
                        eprintln!("Server error: {}", msg);
                        let msg_l = msg.to_lowercase();
                        if msg.contains("already taken") {
                            // attempt login using the previously provided password
                            let login = Message::Login { username: username.clone(), password: password.clone() };
                            if let Err(e) = send_frame(&mut write_socket, &serde_json::to_vec(&login)?).await {
                                eprintln!("failed to send login: {}", e);
                            }
                        } else if (msg_l.contains("invalid") && (msg_l.contains("password") || msg_l.contains("credentials") || msg_l.contains("login") || msg_l.contains("incorrect")))
                               || (msg_l.contains("wrong") && msg_l.contains("password"))
                        {
                            // Authentication failed - prompt the user for password again (non-blocking for the runtime)
                            match tokio::task::spawn_blocking(|| rpassword::prompt_password("Password (try again): ")).await {
                                Ok(Ok(pw)) => {
                                    password = pw;
                                    let login = Message::Login { username: username.clone(), password: password.clone() };
                                    if let Err(e) = send_frame(&mut write_socket, &serde_json::to_vec(&login)?).await {
                                        eprintln!("failed to send login: {}", e);
                                    }
                                }
                                Ok(Err(e)) => eprintln!("failed to read password: {}", e),
                                Err(e) => eprintln!("prompt task failed: {}", e),
                            }
                        }
                    }
                    _ => {}
                }
            }

            // stdin commands
            maybe_line = lines.next_line() => {
                match maybe_line {
                    Ok(Some(line)) => {
                        let mut parts = line.split_whitespace();
                        if let Some(cmd) = parts.next() {
                            match cmd {
                                "get" => {
                                    if let Some(target) = parts.next() {
                                        let req = Message::GetPublicKey { username: target.to_string() };
                                        send_frame(&mut write_socket, &serde_json::to_vec(&req)?).await?;
                                    }
                                }
                                "getshow" => {
                                    if let Some(target) = parts.next() {
                                        let req = Message::GetPublicKey { username: target.to_string() };
                                        send_frame(&mut write_socket, &serde_json::to_vec(&req)?).await?;
                                        pending_getshow.entry(target.to_string()).or_default().push(());
                                    }
                                }
                                "send" => {
                                    if let Some(target) = parts.next() {
                                        let rest: Vec<&str> = parts.collect();
                                        let plaintext = rest.join(" ");

                                        // Always request the latest public key from server and queue the message.
                                        let req = Message::GetPublicKey { username: target.to_string() };
                                        send_frame(&mut write_socket, &serde_json::to_vec(&req)?).await?;
                                        pending_outgoing.entry(target.to_string()).or_default().push(plaintext);
                                        println!("requested public key for {}. message queued and will be sent automatically when key arrives.", target);
                                    }
                                }
                                "quit" | "exit" => {
                                    println!("disconnecting...");
                                    // close the write socket by shutting down the write half
                                    let _ = write_socket.shutdown().await;
                                    break;
                                }
                                _ => println!("unknown cmd; use: get <user>  |  send <user> <message>"),
                            }
                        }
                    }
                    Ok(None) => break, // EOF
                    Err(e) => { eprintln!("stdin read error: {}", e); break; }
                }
            }
        }
    }

    Ok(())
}

// framing helpers (same as server)
async fn read_frame<R: AsyncRead + Unpin>(socket: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn send_frame<W: AsyncWrite + Unpin>(socket: &mut W, data: &[u8]) -> anyhow::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    socket.write_all(&len).await?;
    socket.write_all(data).await?;
    Ok(())
}

fn decrypt_message(
    my_secret: &StaticSecret,
    sender_pk: &PublicKey,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<String, anyhow::Error> {
    // derive shared secret and derive key via HKDF-SHA256 (must match sender)
    let shared = my_secret.diffie_hellman(sender_pk);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"chat encryption key", &mut okm)
        .map_err(|_| anyhow::anyhow!("hkdf expand failed"))?;
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&okm));
    let nonce = XNonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!(e))?;
    let s = String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!(e))?;
    Ok(s)
}
