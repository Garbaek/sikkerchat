<?php
// chat.php — single-file WebRTC demo med simpel PHP-baseret signaling via delt passfrase.
// Server-delen herunder gemmer midlertidigt offer/answer i /tmp (eller systemets temp-mappe)
// og bruges KUN til signaling. Selve beskeder er P2P + E2E-krypterede i browseren.

// ---------- Server: minimal signaling API ----------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json; charset=utf-8');

    // Filnavn baseret på "room" (allerede en SHA-256 fra klienten)
    $room = preg_replace('/[^a-f0-9]/', '', $_POST['room'] ?? '');
    if (strlen($room) !== 64) {
        http_response_code(400);
        echo json_encode(['ok'=>false, 'error'=>'Bad room']);
        exit;
    }

    $tmp = sys_get_temp_dir();
    $file = $tmp . DIRECTORY_SEPARATOR . "p2p_room_$room.json";

    // Hjælpere
    $load = function() use ($file) {
        if (!is_file($file)) return ['offer'=>null,'answer'=>null,'ts'=>time()];
        $raw = @file_get_contents($file);
        if ($raw === false) return ['offer'=>null,'answer'=>null,'ts'=>time()];
        $j = json_decode($raw, true);
        if (!is_array($j)) $j = ['offer'=>null,'answer'=>null,'ts'=>time()];
        return $j;
    };
    $save = function($data) use ($file) {
        // lille TTL: auto-clean efter 2 timer
        $data['ts'] = time();
        @file_put_contents($file, json_encode($data, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
    };

    // Slet gamle filer > 2 timer (best effort)
    foreach (glob(sys_get_temp_dir().DIRECTORY_SEPARATOR.'p2p_room_*.json') as $f) {
        $st = @stat($f);
        if ($st && time() - ($st['mtime'] ?? time()) > 7200) @unlink($f);
    }

    $action = $_POST['action'];
    if ($action === 'post-offer') {
        $offer = json_decode($_POST['offer'] ?? 'null', true);
        if (!$offer || !isset($offer['sdp'],$offer['type'],$offer['pub'])) {
            http_response_code(400);
            echo json_encode(['ok'=>false,'error'=>'Bad offer']);
            exit;
        }
        $state = $load();
        $state['offer'] = $offer;
        // nulstil evt. gammel answer hvis man genopretter offer
        $state['answer'] = null;
        $save($state);
        echo json_encode(['ok'=>true]);

    } elseif ($action === 'get-offer') {
        $state = $load();
        echo json_encode(['ok'=>true,'offer'=>$state['offer']]);

    } elseif ($action === 'post-answer') {
        $answer = json_decode($_POST['answer'] ?? 'null', true);
        if (!$answer || !isset($answer['sdp'],$answer['type'],$answer['pub'])) {
            http_response_code(400);
            echo json_encode(['ok'=>false,'error'=>'Bad answer']);
            exit;
        }
        $state = $load();
        if (!$state['offer']) {
            http_response_code(409);
            echo json_encode(['ok'=>false,'error'=>'No offer yet']);
            exit;
        }
        $state['answer'] = $answer;
        $save($state);
        echo json_encode(['ok'=>true]);

    } elseif ($action === 'get-answer') {
        $state = $load();
        echo json_encode(['ok'=>true,'answer'=>$state['answer']]);

    } elseif ($action === 'clear') {
        @unlink($file);
        echo json_encode(['ok'=>true]);

    } else {
        http_response_code(400);
        echo json_encode(['ok'=>false,'error'=>'Unknown action']);
    }
    exit;
}
?>
<!doctype html>
<html lang="da">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Peer2Peer E2E chat (passfrase)</title>
<style>
 body{font-family:system-ui,Segoe UI,Arial;margin:16px}
 textarea{width:100%;height:120px}
 input[type=text]{width:100%}
 .row{display:flex;gap:8px;flex-wrap:wrap}
 button{padding:8px 12px;cursor:pointer}
 #log{height:200px;overflow:auto;border:1px solid #ccc;padding:8px;margin-top:8px;background:#fafafa}
 .muted{color:#666;font-size:.9em}
 .ok{color:green}
 .warn{color:#b26b00}
</style>
</head>
<body>
<h2>Peer → Peer E2E chat (passfrase)</h2>
<p class="muted">
Indtast samme “hemmelige sætning” (3–4 ord) på begge enheder. Store/små bogstaver ignoreres, ligesom tal og specialtegn — det er altså ordene i sig selv, der tæller.
Der bruges kun denne side til <em>signaling</em> (tilbyder/svarer). Selve chatten er direkte P2P og krypteres ende-til-ende (ECDH → AES-GCM).
</p>

<label for="phrase"><b>Hemmelig sætning</b> (fx: “Rød bil kage kaffe”)</label>
<input id="phrase" type="text" placeholder="Skriv din sætning her…" />

<div class="row" style="margin-top:8px">
  <button id="create" title="Starter forbindelsen (offer)">Opret</button>
  <button id="join"   title="Tilslut til eksisterende (answer)">Join</button>
  <button id="reset"  title="Nulstil signaling (ryd rummet)">Ryd</button>
</div>

<div id="status" class="muted" style="margin-top:6px"></div>

<h3>Chat</h3>
<div id="log"></div>
<div class="row">
  <input id="msg" type="text" placeholder="Skriv besked…" />
  <button id="send" disabled>Send (krypteret)</button>
</div>

<script>
// ====== UI helpers ======
const $ = (id)=>document.getElementById(id);
const log = (t)=>{ let el=$('log'); el.innerHTML += t+'<br>'; el.scrollTop=el.scrollHeight; };
const setStatus = (t, cls='muted')=>{ const el=$('status'); el.className=cls; el.textContent=t; };

// ====== Base64 helpers ======
const b64 = (b)=> btoa(String.fromCharCode(...new Uint8Array(b)));
const fromB64 = (s)=> Uint8Array.from(atob(s), c=>c.charCodeAt(0));

// ====== Normalisering af passfrase → rum-id (SHA-256 hex) ======
// - Gem kun bogstaver (inkl. danske æøå), ignorer tal/specialtegn
// - Lowercase
// - Slå sammen og SHA-256 → 64 hex char
function normalizeWords(s){
  if (!s) return '';
  // behold bogstaver a-z + æøå
  const onlyLetters = (s.normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-zæøå]+/g,'') // ignorer tal og specialtegn
  );
  return onlyLetters;
}

async function sha256Hex(str){
  const enc = new TextEncoder().encode(str);
  const h = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function getRoomId(){
  const phrase = $('phrase').value.trim();
  if (!phrase) throw new Error('Tom sætning');
  const norm = normalizeWords(phrase);
  if (norm.length < 8) throw new Error('Skriv gerne 3–4 rigtige ord (minimumslængde ikke opfyldt).');
  return await sha256Hex(norm);
}

// ====== Crypto (ECDH → AES-GCM) ======
let localKeyPair, aesKey;
async function genECDH(){
  localKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
  const pub = await crypto.subtle.exportKey("raw", localKeyPair.publicKey);
  return b64(pub);
}
async function importRemotePub(rawB64){
  const raw = fromB64(rawB64).buffer;
  const pubKey = await crypto.subtle.importKey(
    "raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []
  );
  aesKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: pubKey },
    localKeyPair.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt","decrypt"]
  );
}
async function encryptMsg(text){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(text);
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, aesKey, enc);
  const combined = new Uint8Array(iv.byteLength + ct.byteLength);
  combined.set(iv,0); combined.set(new Uint8Array(ct), iv.byteLength);
  return b64(combined.buffer);
}
async function decryptMsg(b64data){
  const buf = fromB64(b64data).buffer;
  const arr = new Uint8Array(buf);
  const iv = arr.slice(0,12);
  const ct = arr.slice(12);
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv}, aesKey, ct);
  return new TextDecoder().decode(pt);
}

// ====== WebRTC ======
let pc, dc;
const servers = { iceServers: [{ urls: "stun:stun.l.google.com:19302" }] };

function setupDataChannel(channel){
  channel.onopen = ()=>{
    setStatus('Forbundet. Krypteret data-kanal er åben.', 'ok');
    $('send').disabled = false;
  };
  channel.onclose = ()=>{ setStatus('Forbindelsen blev lukket.', 'warn'); };
  channel.onmessage = async (ev)=>{
    try{
      const pt = await decryptMsg(ev.data);
      addMessage('Peer', pt);
    } catch(e){ log(`<span class="warn">Fejl ved dekryptering: ${e}</span>`); }
  };
}

function addMessage(who, text){
  log(`<b>${who}:</b> ${escapeHtml(text)}`);
}
function escapeHtml(s){
  return s.replace(/[&<>"']/g, (m)=>({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[m]));
}

function waitForIceGatheringComplete(pc){
  return new Promise((res)=>{
    if(pc.iceGatheringState === "complete") return res();
    function check(){
      if(pc.iceGatheringState === "complete"){
        pc.removeEventListener('icegatheringstatechange', check);
        res();
      }
    }
    pc.addEventListener('icegatheringstatechange', check);
    setTimeout(()=>res(), 5000); // fallback
  });
}

// ====== Simple fetch wrapper ======
async function api(action, payload){
  const form = new FormData();
  form.append('action', action);
  Object.entries(payload || {}).forEach(([k,v])=> form.append(k, v));
  const r = await fetch(location.href, { method:'POST', body: form, credentials:'same-origin' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const j = await r.json();
  if (j && j.ok === false) throw new Error(j.error || 'API error');
  return j;
}

// ====== Roles: create (offerer) / join (answerer) ======
let pollTimer = null;

$('create').onclick = async ()=>{
  try{
    $('send').disabled = true;
    setStatus('Starter…', 'muted');

    const room = await getRoomId();
    const myPubB64 = await genECDH();

    pc = new RTCPeerConnection(servers);
    dc = pc.createDataChannel("chat");
    setupDataChannel(dc);

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await waitForIceGatheringComplete(pc);

    const out = { sdp: pc.localDescription.sdp, type: pc.localDescription.type, pub: myPubB64 };
    await api('post-offer', { room, offer: JSON.stringify(out) });
    setStatus('Offer sendt. Venter på answer…', 'muted');

    // Poll for answer
    clearInterval(pollTimer);
    pollTimer = setInterval(async ()=>{
      try{
        const j = await api('get-answer', { room });
        if (j.answer){
          await importRemotePub(j.answer.pub);
          await pc.setRemoteDescription({ type: j.answer.type, sdp: j.answer.sdp });
          clearInterval(pollTimer); pollTimer=null;
          setStatus('Answer modtaget. Forbinder…', 'muted');
        }
      }catch(e){ /* ignore transient errors */ }
    }, 1500);

  } catch(e){
    setStatus(`Fejl: ${e.message}`, 'warn');
  }
};

$('join').onclick = async ()=>{
  try{
    $('send').disabled = true;
    setStatus('Leder efter offer…', 'muted');

    const room = await getRoomId();
    const myPubB64 = await genECDH();

    // Poll for offer til det findes
    const offerObj = await waitForOffer(room);

    pc = new RTCPeerConnection(servers);
    pc.ondatachannel = (ev)=>{ dc = ev.channel; setupDataChannel(dc); };

    await importRemotePub(offerObj.pub);
    await pc.setRemoteDescription({ type: offerObj.type, sdp: offerObj.sdp });

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await waitForIceGatheringComplete(pc);

    const out = { sdp: pc.localDescription.sdp, type: pc.localDescription.type, pub: myPubB64 };
    await api('post-answer', { room, answer: JSON.stringify(out) });
    setStatus('Answer sendt. Forbinder…', 'muted');

  } catch(e){
    setStatus(`Fejl: ${e.message}`, 'warn');
  }
};

$('reset').onclick = async ()=>{
  try{
    const room = await getRoomId();
    await api('clear', { room });
    setStatus('Rummet er ryddet.', 'ok');
  } catch(e){
    setStatus(`Kunne ikke rydde: ${e.message}`, 'warn');
  }
};

// Poll helper for joiner
async function waitForOffer(room){
  const start = Date.now();
  while(true){
    const j = await api('get-offer', { room });
    if (j.offer) return j.offer;
    await sleep(1200);
    // valgfrit timeout-signal i UI
    if (Date.now() - start > 120000) setStatus('Stadig ingen offer… sikre jer at den anden har trykket "Opret".', 'warn');
  }
}
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

// ====== Send besked ======
$('send').onclick = async ()=>{
  if (!dc || dc.readyState!=='open') return;
  const txt = $('msg').value.trim();
  if (!txt) return;
  $('msg').value='';
  const ct = await encryptMsg(txt);
  dc.send(ct);
  addMessage('Mig', txt);
};

// ENTER for send
$('msg').addEventListener('keydown', (e)=>{
  if (e.key === 'Enter') $('send').click();
});
</script>
</body>
</html>
