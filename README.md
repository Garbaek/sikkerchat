# sikkerchat
Simple P2P chat demo with end-to-end encryption (WebRTC + ECDH → AES-GCM). Two users enter the same passphrase to connect directly, no central server for messages. Shows how easy secure, private communication can be built.

Key features:
Passphrase based rooms → Two users enter the same 3–4 word passphrase, which is normalized and hashed into a unique room ID.
WebRTC peer connection → Direct P2P channel established via browser APIs, with only minimal signaling handled by the PHP file.
Modern cryptography → ECDH (P-256) key exchange combined with AES-GCM for message encryption and authentication.
No central storage of messages → The server never sees chat content; it only provides temporary signaling (offer/answer exchange).
Lightweight by design → Entire demo runs in a single PHP file with embedded HTML, CSS, and JavaScript.

The goal of sikkerchat.php is educational: to show that strong encryption is neither complicated nor exotic. Anyone can set up private communication that remains outside the reach of centralized scanning or monitoring.
