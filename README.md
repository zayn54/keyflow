# Keyflow — The Future of Secure, Decentralized Communication

**Keyflow** is a next-generation **privacy-first communication system** built for developers, innovators, and freedom seekers.
It bridges the gap between **client-side encryption** and **server-side performance**, enabling secure, peer-to-peer communication that works seamlessly across devices — from **Linux** and **Windows** to **Android (via Termux)**.

Whether you’re experimenting locally or deploying globally, Keyflow gives you **total control, freedom, and transparency**.

---

## Inspiration

The creation of **Keyflow** was inspired by growing concerns about privacy — particularly after President William Ruto of Kenya (our current president 2025) signed a bill allowing government access to citizens’ messages and data.
Keyflow was developed as a **response to digital surveillance**, ensuring that no authority, company, or entity can invade your private communications.

> *“Privacy is freedom. Keyflow was built to protect it.”*

---

## Project Structure

```
keyflow/
├── client/      # Handles user-side encryption, connections, and CLI interactions
│   ├── src/
│   ├── Cargo.toml
│   └── keyflow (compiled binary)
│
└── server/      # Manages sessions, database, and relays secure messages
    ├── src/
    ├── chat_server_db/
    ├── Cargo.toml
    └── main.rs
```

Each part can be built and run independently, or together for full system functionality.

---

## Installation & Setup

### Linux (Ubuntu/Debian)

```bash
# Clone the repository
git clone https://github.com/zayn54/keyflow.git
cd keyflow

# Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build both server and client
cd server && cargo build --release
cd ../client && cargo build --release
```

### Windows

1. Install [Rust](https://www.rust-lang.org/tools/install)
2. Clone the repository:

   ```powershell
   git clone https://github.com/zayn54/keyflow.git
   cd keyflow\client
   cargo build --release
   ```
3. Executables (`keyflow.exe`) will be found in `target\release\`.

### Android (Termux)

```bash
pkg update && pkg upgrade
pkg install git rust wget unzip -y

git clone https://github.com/zayn54/keyflow.git
cd keyflow/client
cargo build --release
```

Your binary will be located at:

```
~/keyflow/client/target/release/keyflow
```

---

## Running the App with Ngrok

Ngrok lets you securely expose your local Keyflow server to the internet.
The free plan assigns a new address every session — so you’ll need to share the updated address with clients whenever you restart Ngrok.

### 1. Start the Server

```bash
cd server
cargo run --release
```

### 2. Start Ngrok

If you don’t have Ngrok yet:

```bash
wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-arm64.zip
unzip ngrok-stable-linux-arm64.zip
ngrok authtoken <your_token>
```

Or install with Snap:

```bash
sudo snap install ngrok
ngrok authtoken <your_token>
```

Expose your server:

```bash
ngrok tcp 4000
```

You’ll get a forwarding address like:

```
tcp://0.tcp.ngrok.io:XXXX
```

### 3. Connect the Client

To **register**:

```bash
./keyflow <username>
```

To **login**:

```bash
./keyflow <username> login
```

---

## Hosting Your Own Public Server (Decentralized Network)

Keyflow is designed so **anyone** can run a server on their machine and expose it over the internet (for example, to host sessions for friends or an ad-hoc community). Running many independent servers increases resilience and privacy for the network.

**How anyone can host & share a server**

### Steps:

1. Start your server:

   ```bash
   cd server
   cargo run --release
   ```

2. Run Ngrok on the same machine:

   ```bash
   ngrok tcp 4000
   ```

3. Share your generated forwarding address (e.g. `0.tcp.ngrok.io:XXXX`) with others.
   They can connect using:

   ```bash
   ./keyflow <username>
   ./keyflow <username> login
   ```

**Why this helps security & privacy**

* **IP masking:** Ngrok hides the host's real public IP by providing a tunnel endpoint, reducing direct exposure of the server to the open internet.
* **Decentralization:** With many people running servers across different locations and networks, it becomes harder for an outside observer to identify a single source or block the whole network.
* **Resilience:** Multiple independent servers increase availability—if one host goes offline, others remain reachable.

**Important security notes**

* Hiding an IP isn’t foolproof—hosts should still secure their servers:

  * Use strong authentication/keys for clients.
  * Keep software up to date.
  * Restrict access via allowed client identifiers where possible.
  * Monitor logs and avoid exposing sensitive admin interfaces.
* Do **not** use Keyflow or any hosting method to perform illegal activities. Respect local laws and the terms of service of tunnel providers.
* Ngrok free plans rotate addresses and have rate limits—consider a paid account for stable, long-running public endpoints.

---

## Example Commands

| Action                | Command                            |
| --------------------- | ---------------------------------- |
| Run server            | `cargo run --release --bin server` |
| Run client            | `cargo run --release --bin client` |
| Connect as new client | `./keyflow <username>`             |
| Send message          | `send "What's up"`                 |
| Show public key       | `getshow <username>`               |
| Shut down server      | `shutdown`                         |

---

## Contributing

We’re building something **bold** — a decentralized, privacy-first communication layer that puts power back into users’ hands.

To contribute:

1. Fork this repo
2. Create a new branch

   ```bash
   git checkout -b feature-branch
   ```
3. Commit and push changes
4. Submit a pull request

---

## Community

Got ideas, bugs, or feedback?
Open an **issue** or start a **discussion** — we’d love to hear from you and make Keyflow even better.

---

## License

This project is licensed under the **MIT License** — free to use, modify, and distribute.

---

*Built to protect freedom, one connection at a time.*
