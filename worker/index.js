const firstNames = ['Avery','Jordan','Taylor','Morgan','Riley','Quinn','Parker','Casey','Jamie','Reese','Rowan','Blake','Skyler','Hayden','Emerson','Finley','Cameron','Dakota','Harper','Logan','Sage','Ellis','Charlie','Drew','Arden','Kendall','Bailey','Elliot','Micah','Robin'];
const lastNames = ['Hawthorne','Bennett','Carter','Foster','Brooks','Hayes','Reed','Sullivan','Parker','Morgan','Griffin','Coleman','Turner','Walsh','Miller','Ramsey','Collins','Holland','Rivers','Hughes','Wells','Knight','Hart','Ellis','Rowe','Harper','Stone','Pierce','Lane','Cruz'];
const encoder = new TextEncoder();
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2,'0')).join('');
const randomHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const digest = async str => hex(await crypto.subtle.digest('SHA-256', encoder.encode(str)));
async function passwordHash(password, salt) {
 const material = await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);
 return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:encoder.encode(salt),iterations:210000,hash:'SHA-256'},material,256));
}
function json(data,status=200,origin='') {return new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','access-control-allow-origin':origin,'access-control-allow-headers':'content-type, authorization','access-control-allow-methods':'GET,POST,DELETE,OPTIONS','vary':'Origin'}})}
function originFor(req,env){const origin=req.headers.get('Origin')||'';const allowed=(env.ALLOWED_ORIGIN||'').split(',').map(s=>s.trim());return allowed.includes(origin)?origin:'';}
function normalizeName(s){return typeof s==='string'?s.trim().toLowerCase():'';}
function bad(message,status,origin){return json({error:message},status,origin);}
async function auth(req,env){let value=req.headers.get('Authorization')||'';if(!value.startsWith('Bearer '))return null;let token=value.slice(7);if(!/^[a-f0-9]{64}$/.test(token))return null;let hash=await digest(token);return await env.MAIL_DB.prepare('SELECT users.id,users.login FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?').bind(hash,Date.now()).first();}
async function sendSession(user,env,origin){let token=randomHex(32);await env.MAIL_DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await digest(token),user.id,Date.now()+30*86400000).run();return json({token,user:{id:user.id,login:user.login}},200,origin);}
async function loadJSON(req){if(Number(req.headers.get('content-length')||0)>10000)throw Error('Payload too large');return req.json();}
async function dispatch(req,env){const origin=originFor(req,env),method=req.method,url=new URL(req.url),p=url.pathname;
 if(req.headers.get('Origin') && !origin)return bad('Origin not permitted',403,'');
 if(method==='OPTIONS')return new Response(null,{status:204,headers:{'access-control-allow-origin':origin,'access-control-allow-headers':'content-type, authorization','access-control-allow-methods':'GET,POST,DELETE,OPTIONS','vary':'Origin'}});
 if(p==='/health'&&method==='GET')return json({ok:true,domain:env.MAIL_DOMAIN},200,origin);
 if(p==='/auth/register'&&method==='POST'){
 const data=await loadJSON(req),login=normalizeName(data.login),password=data.password;
 if(!/^[a-z0-9_]{3,30}$/.test(login))return bad('Username must be 3–30 letters, numbers, or underscores',400,origin);
 if(typeof password!=='string'||password.length<12||password.length>128)return bad('Password must be 12–128 characters',400,origin);
 const ip=req.headers.get('CF-Connecting-IP')||'unknown',key=await digest(ip+'|'+(env.RATE_SALT||'signup'));
 const attempts=await env.MAIL_DB.prepare('SELECT COUNT(*) AS n FROM signup_attempts WHERE ip_hash=? AND at>?').bind(key,Date.now()-3600000).first();
 if(attempts?.n>=5)return bad('Too many signups; try again later',429,origin);
 await env.MAIL_DB.prepare('INSERT INTO signup_attempts(ip_hash,at) VALUES(?,?)').bind(key,Date.now()).run();
 const id=crypto.randomUUID(),salt=randomHex(16),hashed=await passwordHash(password,salt);
 try{await env.MAIL_DB.prepare('INSERT INTO users(id,login,salt,password_hash,created_at) VALUES(?,?,?,?,?)').bind(id,login,salt,hashed,Date.now()).run();}catch{return bad('Username already exists',409,origin);}
 return sendSession({id,login},env,origin);
 }
 if(p==='/auth/login'&&method==='POST'){
 const data=await loadJSON(req),login=normalizeName(data.login),password=data.password;
 if(typeof password!=='string'||password.length>128)return bad('Invalid credentials',401,origin);
 const user=await env.MAIL_DB.prepare('SELECT * FROM users WHERE login=?').bind(login).first();
 const salt=user?.salt||'0'.repeat(32);const hashed=await passwordHash(password,salt);
 if(!user||hashed!==user.password_hash)return bad('Invalid credentials',401,origin);
 return sendSession(user,env,origin);
 }
 const user=await auth(req,env);if(!user)return bad('Please log in',401,origin);
 if(p==='/auth/me'&&method==='GET')return json({user},200,origin);
 if(p==='/auth/logout'&&method==='POST'){
 const token=req.headers.get('Authorization').slice(7);await env.MAIL_DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(token)).run();return json({ok:true},200,origin);
 }
 if(p==='/mailboxes'&&method==='GET'){
 const rows=await env.MAIL_DB.prepare('SELECT id,address,created_at FROM addresses WHERE user_id=? ORDER BY created_at DESC').bind(user.id).all();return json({mailboxes:rows.results},200,origin);
 }
 if(p==='/mailboxes'&&method==='POST'){
 const count=await env.MAIL_DB.prepare('SELECT COUNT(*) AS n FROM addresses WHERE user_id=?').bind(user.id).first();if(count.n>=20)return bad('20 addresses per account maximum',400,origin);
 const domain=env.MAIL_DOMAIN||'temp.mase-tech.online';
 for(let i=0;i<10;i++){
 const f=firstNames[crypto.getRandomValues(new Uint32Array(1))[0]%firstNames.length],l=lastNames[crypto.getRandomValues(new Uint32Array(1))[0]%lastNames.length];
 const address=`${f}.${l}.${randomHex(3)}@${domain}`.toLowerCase(),id=crypto.randomUUID();
 try{await env.MAIL_DB.prepare('INSERT INTO addresses(id,user_id,address,created_at) VALUES(?,?,?,?)').bind(id,user.id,address,Date.now()).run();return json({id,address},201,origin);}catch{}
 }return bad('Unable to create unique address',500,origin);
 }
 if(p==='/messages'&&method==='GET'){
 const id=url.searchParams.get('id');const box=await env.MAIL_DB.prepare('SELECT id FROM addresses WHERE id=? AND user_id=?').bind(id,user.id).first();if(!box)return bad('Inbox not found',404,origin);
 const rows=await env.MAIL_DB.prepare('SELECT id,sender,recipient,subject,text_body,html_body,received_at FROM mail_items WHERE address_id=? ORDER BY received_at DESC LIMIT 100').bind(id).all();
 return json({messages:rows.results},200,origin);
 }
 return bad('Not found',404,origin);
}
export default {
 async fetch(req,env){try{return await dispatch(req,env)}catch(err){console.error('API error:',err);return bad('Server error',500,originFor(req,env))}},
 async email(message,env,ctx){
  const to=message.to.toLowerCase();const box=await env.MAIL_DB.prepare('SELECT id FROM addresses WHERE address=?').bind(to).first();
  if(!box){message.setReject('Address does not exist');return;}
  const {default:PostalMime}=await import('postal-mime');
  const parsed=await new PostalMime().parse(message.raw);
  const id=crypto.randomUUID(),sender=String(message.from||'').slice(0,320),subject=String(parsed.subject||'').slice(0,998);
  await env.MAIL_DB.prepare('INSERT INTO mail_items(id,address_id,sender,recipient,subject,text_body,html_body,received_at) VALUES(?,?,?,?,?,?,?,?)').bind(id,box.id,sender,to,subject,String(parsed.text||'').slice(0,200000),String(parsed.html||'').slice(0,200000),Date.now()).run();
 }
};
