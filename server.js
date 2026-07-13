/* =====================================================================
   ZYX Envíos — Backend real con persistencia (Node + Express)
   ---------------------------------------------------------------------
   - Persistencia en archivo JSON (data.json). Cero dependencias nativas.
   - Auth por enlace mágico (token de sesión firmado con HMAC).
   - Endpoints: quotes, shipments (cobra saldo), wallet, recargas,
     y admin (margen, overrides, promos, aprobar recargas, usuarios, guías).
   - Proxy a la Partners API de env.com.mx si defines ENV_API_KEY;
     si no, corre en modo simulado (mismas fórmulas) para poder probar.
   - Sirve el frontend desde /public.

   Puesta en marcha:
     npm install
     cp .env.example .env   # y edita tus valores
     npm start
     abre http://localhost:3000
===================================================================== */
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- Config ---------- */
const PORT        = process.env.PORT || 3000;
const SECRET      = process.env.SESSION_SECRET || 'cambia-este-secreto-en-produccion';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@zyx.mx').toLowerCase();
const APP_URL     = process.env.APP_URL || '';
const ENV_API_KEY = process.env.ENV_API_KEY || '';
const ENV_API_BASE= process.env.ENV_API_BASE || 'https://api.envia.com';
const ALLOW_DEV_LOGIN = (process.env.ALLOW_DEV_LOGIN || 'true') === 'true';
const DB_FILE     = process.env.DB_FILE || path.join(__dirname, 'data.json');

/* ---------- Paqueterías (catálogo + precios simulados) ---------- */
const CARRIERS = [
  {carrier_name:'Estafeta',code:'EST',color:'#e2001a',service_name:'Terrestre',service_type:'ground',days:4,base:95,perKg:11,feats:['tracking']},
  {carrier_name:'Estafeta',code:'EST',color:'#e2001a',service_name:'Día Siguiente',service_type:'express',days:1,base:180,perKg:18,feats:['tracking','express','insurance']},
  {carrier_name:'FedEx',code:'FDX',color:'#4d148c',service_name:'Express Saver',service_type:'express',days:2,base:165,perKg:16,feats:['tracking','insurance']},
  {carrier_name:'DHL',code:'DHL',color:'#ffcc00',ink:'#d40511',service_name:'Express Nacional',service_type:'express',days:1,base:205,perKg:20,feats:['tracking','express','insurance','signature']},
  {carrier_name:'Redpack',code:'RPK',color:'#e2001a',service_name:'Ecoexpress',service_type:'ground',days:3,base:88,perKg:10,feats:['tracking']},
  {carrier_name:'Paquetexpress',code:'PQX',color:'#0a2e5c',service_name:'Estándar',service_type:'ground',days:3,base:92,perKg:12,feats:['tracking','insurance']},
  {carrier_name:'99minutos',code:'99M',color:'#00c389',ink:'#0b0b0b',service_name:'Nacional',service_type:'ground',days:2,base:110,perKg:9,feats:['tracking','eco']}
];

/* ---------- Persistencia ---------- */
function seed(){
  return {
    settings:{
      margin:20, overrides:{},
      bank:{banco:'BBVA',titular:'ZYX Logística SA de CV',clabe:'012 180 01234567890',cuenta:'0123456789'},
      promos:[{min:500,bonus:3},{min:1000,bonus:5},{min:2500,bonus:8},{min:5000,bonus:10},{min:10000,bonus:12}]
    },
    users:{}, recharges:[], shipments:[], counters:{rc:1000,sh:1000}
  };
}
const DATABASE_URL = process.env.DATABASE_URL || '';
let db = seed();
let pg = null;
async function loadStore(){
  if(DATABASE_URL){
    const { Client } = require('pg');
    const ext = /\.render\.com|amazonaws|neon|supabase|sslmode=require/.test(DATABASE_URL);
    pg = new Client({ connectionString: DATABASE_URL, ssl: ext ? { rejectUnauthorized:false } : false });
    await pg.connect();
    await pg.query('CREATE TABLE IF NOT EXISTS kv (k text primary key, v text)');
    const r = await pg.query("SELECT v FROM kv WHERE k='main'");
    if(r.rows.length){ db = JSON.parse(r.rows[0].v); } else { db = seed(); await persistNow(); }
    console.log('✓ Persistencia: PostgreSQL');
  } else {
    try { db = JSON.parse(fs.readFileSync(DB_FILE,'utf8')); } catch { db = seed(); }
    console.log('✓ Persistencia: archivo local ('+DB_FILE+')');
  }
}
async function persistNow(){
  if(pg){ await pg.query("INSERT INTO kv(k,v) VALUES('main',$1) ON CONFLICT (k) DO UPDATE SET v=$1",[JSON.stringify(db)]); }
  else { fs.writeFileSync(DB_FILE, JSON.stringify(db,null,2)); }
}
let saveTimer=null;
function save(){ clearTimeout(saveTimer); saveTimer=setTimeout(()=>{ persistNow().catch(e=>console.error('save error',e.message)); },50); }
function user(email){ return (db.users[email] ||= {email, balance:0, createdAt:new Date().toISOString().slice(0,10)}); }
function marginFor(carrier){ const o=db.settings.overrides[carrier]; return (o===undefined||o===null||o==='')?db.settings.margin:Number(o); }
function bonusFor(amount){ let pct=0; db.settings.promos.slice().sort((a,b)=>a.min-b.min).forEach(t=>{ if(amount>=t.min)pct=t.bonus; }); return Math.round(amount*pct/100); }
const now = () => new Date().toISOString().slice(0,16).replace('T',' ');

/* ---------- Sesión (token firmado) ---------- */
function sign(email){ const h=crypto.createHmac('sha256',SECRET).update(email).digest('hex').slice(0,32); return Buffer.from(email).toString('base64url')+'.'+h; }
function verifyToken(tk){ if(!tk)return null; const [b,h]=tk.split('.'); if(!b||!h)return null; let email; try{email=Buffer.from(b,'base64url').toString();}catch{return null;} return sign(email)===tk?email:null; }
function auth(req,res,next){ const email=verifyToken((req.headers.authorization||'').replace('Bearer ','')); if(!email)return res.status(401).json({errors:['No autenticado']}); req.email=email; req.isAdmin=(email===ADMIN_EMAIL); next(); }
function adminOnly(req,res,next){ if(!req.isAdmin)return res.status(403).json({errors:['Solo administrador']}); next(); }

/* ---------- Envío de enlace mágico (opcional, vía SMTP) ---------- */
async function sendMagicLink(email, link){
  if(!process.env.SMTP_HOST) return false;
  try{
    const nodemailer = require('nodemailer');
    const t = nodemailer.createTransport({ host:process.env.SMTP_HOST, port:Number(process.env.SMTP_PORT||587), secure:false, auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS} });
    await t.sendMail({ from:process.env.SMTP_FROM||'ZYX Envíos <no-reply@zyx.mx>', to:email, subject:'Tu acceso a ZYX Envíos',
      html:`<p>Hola,</p><p>Entra a tu cuenta ZYX con este enlace (válido para iniciar sesión):</p><p><a href="${link}">${link}</a></p>` });
    return true;
  }catch(e){ console.error('SMTP error:', e.message); return false; }
}

/* =====================================================================
   AUTH — enlace mágico
===================================================================== */
app.post('/api/auth/request', async (req,res)=>{
  const email = String(req.body.email||'').trim().toLowerCase();
  if(!email.includes('@')) return res.status(422).json({errors:['Correo inválido']});
  const role = email===ADMIN_EMAIL ? 'admin' : 'user';
  if(role==='user') user(email), save();
  const tk = sign(email);
  const base = APP_URL || `${req.headers['x-forwarded-proto']||req.protocol}://${req.headers.host}`;
  const link = `${base}/?token=${tk}`;
  const emailed = await sendMagicLink(email, link);
  const out = { ok:true, role };
  if(!emailed && ALLOW_DEV_LOGIN) out.token = tk; // sin SMTP → login directo (dev)
  if(emailed) out.emailed = true;
  res.json(out);
});

/* ---------- Login/registro con contraseña ---------- */
function hashPassword(pw){ const salt=crypto.randomBytes(16).toString('hex'); const h=crypto.scryptSync(String(pw),salt,32).toString('hex'); return salt+':'+h; }
function verifyPassword(pw,stored){ try{ if(!stored||!stored.includes(':'))return false; const [salt,h]=stored.split(':'); const hh=crypto.scryptSync(String(pw),salt,32).toString('hex'); const a=Buffer.from(h,'hex'), b=Buffer.from(hh,'hex'); return a.length===b.length && crypto.timingSafeEqual(a,b); }catch{ return false; } }
app.post('/api/auth/login', (req,res)=>{
  const email = String(req.body.email||'').trim().toLowerCase();
  const pw = String(req.body.password||'');
  const u = db.users[email];
  if(!u || !u.passwordHash || !verifyPassword(pw, u.passwordHash)) return res.status(401).json({errors:['Correo o contraseña incorrectos']});
  res.json({ ok:true, token: sign(email), role: email===ADMIN_EMAIL?'admin':'user' });
});
app.post('/api/auth/set-password', auth, (req,res)=>{
  const pw = String(req.body.password||'');
  if(pw.length < 6) return res.status(422).json({errors:['La contraseña debe tener al menos 6 caracteres']});
  const u = user(req.email); u.passwordHash = hashPassword(pw); save();
  res.json({ ok:true });
});

/* ---------- Bootstrap: carga inicial de datos según rol ---------- */
app.get('/api/bootstrap', auth, (req,res)=>{
  if(req.isAdmin){
    return res.json({ email:req.email, role:'admin',
      settings: db.settings,
      users: Object.values(db.users),
      recharges: db.recharges,
      shipments: db.shipments });
  }
  const u = user(req.email);
  res.json({ email:req.email, role:'user',
    me:{email:u.email, balance:u.balance, createdAt:u.createdAt, hasPassword:!!u.passwordHash},
    settings:{ promos:db.settings.promos, bank:db.settings.bank },
    recharges: db.recharges.filter(r=>r.email===req.email),
    shipments: db.shipments.filter(s=>s.email===req.email) });
});

/* =====================================================================
   COTIZAR
===================================================================== */
function volWeight(l,w,h){ return (l*w*h)/5000; }
function quoteRatesMock(quote){
  const p=quote.parcels[0]; const w=Math.max(p.weight, volWeight(p.length,p.width,p.height));
  const distF=1+Math.abs((+quote.origin_postal_code||0)-(+quote.destination_postal_code||0))/900000;
  return CARRIERS.map((c,i)=>{ const cost=Math.round((c.base+c.perKg*w)*distF*1.16); const sell=Math.round(cost*(1+marginFor(c.carrier_name)/100));
    return { service_id:'srv-'+i, carrier_name:c.carrier_name, service_name:c.service_name, days:c.days,
      total:sell, currency:'MXN', has_pickup:c.service_type!=='ground'?true:i%2===0,
      description:c.days+(c.days===1?' día hábil':' días hábiles'), features:c.feats, _color:c.color, _ink:c.ink||'#fff' };
  });
}
function enviaErr(j){ const m=(j&&j.error&&(j.error.message||j.error))||(j&&j.message)||'Error en la API de envia.com'; return typeof m==='string'?m:JSON.stringify(m); }
function enviaPackage(quote){ const p=quote.parcels[0]||{}; return { type:'box', content:'Mercancía', amount:1, declaredValue:Number(quote.declared_value)||0,
  weightUnit:'KG', lengthUnit:'CM', weight:Number(p.weight)||1,
  dimensions:{ length:Number(p.length)||1, width:Number(p.width)||1, height:Number(p.height)||1 } }; }
async function geocode(pc){
  try{ const r = await fetch(`https://geocodes.envia.com/zipcode/MX/${encodeURIComponent(String(pc||''))}`);
    const j = await r.json(); const d = Array.isArray(j)?j[0]:(Array.isArray(j.data)?j.data[0]:j.data); if(!d) return {};
    const st = d.state;
    const state = (st && (st.code?.['2digit'] || st.code?.['3digit'] || st.name)) || (typeof st==='string'?st:'') || '';
    return { city:d.locality||d.city||'', state }; }
  catch{ return {}; }
}
const MX_CARRIERS = (process.env.ENV_CARRIERS || 'fedex,dhl,estafeta,redpack,paquetexpress,sendex,99minutos,ampm').split(',').map(s=>s.trim()).filter(Boolean);
async function rateOneCarrier(baseBody, carrier){
  try{
    const body = Object.assign({}, baseBody, { shipment:{ type:1, carrier } });
    const r = await fetch(`${ENV_API_BASE}/ship/rate/`, {method:'POST',headers:{'Authorization':`Bearer ${ENV_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(body)});
    const j = await r.json();
    if(!r.ok || j.meta==='error' || !Array.isArray(j.data)) return [];
    return j.data;
  }catch{ return []; }
}
async function quoteRatesReal(quote){
  const [og,dg] = await Promise.all([ geocode(quote.origin_postal_code), geocode(quote.destination_postal_code) ]);
  const baseBody = {
    origin:{ country:'MX', postalCode:String(quote.origin_postal_code||''), city:og.city||'N/D', state:og.state||'' },
    destination:{ country:'MX', postalCode:String(quote.destination_postal_code||''), city:dg.city||'N/D', state:dg.state||'' },
    packages:[ enviaPackage(quote) ], settings:{ currency:'MXN' }
  };
  const lists = await Promise.all(MX_CARRIERS.map(c=>rateOneCarrier(baseBody, c)));
  const all = lists.flat();
  if(!all.length) throw new Error('Sin tarifas disponibles para esta ruta con las paqueterías contratadas en tu cuenta de envia.com.');
  return all.map((rate,i)=>{ const cost=Number(rate.totalPrice)||0; const sell=Math.round(cost*(1+marginFor(rate.carrierDescription||rate.carrier)/100));
    const dd=rate.deliveryDate||{}; const days=(typeof dd.dateDifference==='number')?dd.dateDifference:(parseInt(rate.deliveryEstimate,10)||1);
    return { service_id:`${rate.carrier}||${rate.service}||${i}`, carrier_name:rate.carrierDescription||rate.carrier, service_name:rate.serviceDescription||rate.service, days,
      total:sell, currency:rate.currency||'MXN', has_pickup:!Number(rate.dropOff), description:rate.deliveryEstimate||(days+(days===1?' día':' días')),
      features:['tracking'], _color:'#f9550d', _ink:'#fff', _real:true, _cost:cost, _carrier:rate.carrier, _service:rate.service }; });
}
app.post('/api/quotes', auth, async (req,res)=>{
  try{ const quote=req.body.quote||req.body; const data = ENV_API_KEY ? await quoteRatesReal(quote) : quoteRatesMock(quote);
    res.json({ data }); }
  catch(err){ res.status(502).json({errors:[err.message]}); }
});

/* =====================================================================
   GENERAR GUÍA — cobra del saldo
===================================================================== */
app.post('/api/shipments', auth, async (req,res)=>{
  try{
    const { service_id, quote, destinatario={}, remitente={} } = req.body;
    const u = user(req.email);
    let cost, carrierName, serviceName, days, tracking, seq, labelUrl='';

    if(ENV_API_KEY){
      // Modo real: genera la guía en envia.com y toma el costo real
      const parts = String(service_id).split('||'); const carrier=parts[0]||''; const service=parts[1]||'';
      const [og,dg] = await Promise.all([ geocode(quote.origin_postal_code), geocode(quote.destination_postal_code) ]);
      const addr = (a,pc,g)=>({ name:a.name||a.nombre||'—', company:a.company||a.empresa||'', email:a.email||a.correo||'', phone:String(a.phone||a.telefono||a.tel||'0000000000'),
        street:a.street||a.calle||'—', number:String(a.number||a.numero||a.num||'0'), district:a.district||a.colonia||a.neighborhood||'',
        city:a.city||a.ciudad||g.city||'N/D', state:a.state||a.estado||g.state||'', country:'MX',
        postalCode:String(a.postalCode||a.postal_code||a.cp||a.zip||pc||''), reference:a.reference||a.referencia||'' });
      const body = { origin:addr(remitente, quote.origin_postal_code, og), destination:addr(destinatario, quote.destination_postal_code, dg),
        packages:[ enviaPackage(quote) ], shipment:{ type:1, carrier, service }, settings:{ printFormat:'PDF', printSize:'STOCK_4X6' } };
      const r = await fetch(`${ENV_API_BASE}/ship/generate/`,{method:'POST',headers:{'Authorization':`Bearer ${ENV_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(body)});
      const j = await r.json(); if(!r.ok || j.meta==='error' || !Array.isArray(j.data) || !j.data.length) return res.status(502).json({errors:[enviaErr(j)]});
      const d=j.data[0]; cost=Number(d.totalPrice)||0; carrierName=d.carrierDescription||d.carrier; serviceName=d.serviceDescription||d.service; days=0; tracking=d.trackingNumber; seq='SH-'+(d.shipmentId||(++db.counters.sh)); labelUrl=d.label||'';
    } else {
      const i = parseInt(String(service_id).split('-')[1],10); const c = CARRIERS[i]; if(!c) return res.status(404).json({errors:['Servicio no encontrado']});
      const p=quote.parcels[0]; const w=Math.max(p.weight, volWeight(p.length,p.width,p.height));
      const distF=1+Math.abs((+quote.origin_postal_code||0)-(+quote.destination_postal_code||0))/900000;
      cost=Math.round((c.base+c.perKg*w)*distF*1.16); carrierName=c.carrier_name; serviceName=c.service_name; days=c.days;
      tracking=Array(12).fill(0).map(()=>Math.floor(Math.random()*10)).join(''); seq='SH-'+(++db.counters.sh);
    }
    const sell = Math.round(cost*(1+marginFor(carrierName)/100));
    if(u.balance < sell) return res.status(402).json({errors:['Saldo insuficiente'], required:sell, balance:u.balance});
    u.balance -= sell;
    const record = { id:seq, email:req.email, dest:destinatario.name||destinatario.nombre||'—', city:destinatario.city||destinatario.ciudad||'', carrier:carrierName, service:serviceName, cost, sell, tracking, label:labelUrl, date:now() };
    db.shipments.unshift(record); save();
    res.status(201).json({ balance:u.balance, shipment:record, sequential_id:seq, tracking_number:tracking, carrier_name:carrierName, service_name:serviceName, estimated_delivery_days:days, sell });
  }catch(err){ res.status(502).json({errors:[err.message]}); }
});

/* =====================================================================
   MONEDERO / RECARGAS
===================================================================== */
app.post('/api/recharges', auth, (req,res)=>{
  const amount = Number(req.body.amount); if(!amount||amount<=0) return res.status(422).json({errors:['Monto inválido']});
  const bonus = bonusFor(amount);
  const rc = { id:'RC-'+(++db.counters.rc), email:req.email, amount, bonus, reference:req.body.reference||'—', status:'pending', date:now() };
  db.recharges.unshift(rc); save();
  res.status(201).json({ recharge:rc });
});

/* =====================================================================
   ADMIN
===================================================================== */
app.put('/api/admin/settings', auth, adminOnly, (req,res)=>{
  if(req.body.margin!=null) db.settings.margin=Number(req.body.margin);
  if(req.body.overrides) db.settings.overrides=req.body.overrides;
  if(req.body.promos) db.settings.promos=req.body.promos.filter(t=>t.min>0).sort((a,b)=>a.min-b.min);
  if(req.body.bank) db.settings.bank=Object.assign({}, db.settings.bank, req.body.bank);
  save(); res.json(db.settings);
});
app.post('/api/admin/recharges/:id/:action', auth, adminOnly, (req,res)=>{
  const rc = db.recharges.find(r=>r.id===req.params.id);
  if(!rc||rc.status!=='pending') return res.status(404).json({errors:['Recarga no encontrada o ya procesada']});
  if(req.params.action==='approve'){ rc.status='approved'; user(rc.email).balance += rc.amount+(rc.bonus||0); }
  else if(req.params.action==='reject'){ rc.status='rejected'; }
  else return res.status(400).json({errors:['Acción inválida']});
  save(); res.json({ recharge:rc });
});

/* SPA fallback */
app.get('*', (req,res)=> res.sendFile(path.join(__dirname,'public','index.html')));

loadStore().catch(e=>console.error('loadStore error:',e.message)).finally(()=>{
  app.listen(PORT, ()=> console.log(`✦ ZYX Envíos en ${APP_URL||('http://localhost:'+PORT)}  ·  modo: ${ENV_API_KEY?'API REAL':'simulado'}  ·  admin: ${ADMIN_EMAIL}`));
});
