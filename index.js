const JSON_HEADERS = {"content-type":"application/json; charset=utf-8","cache-control":"no-store"};
const json = (data,status=200,headers={}) => new Response(JSON.stringify(data),{status,headers:{...JSON_HEADERS,...headers}});
const fail = (message,status=400) => json({error:message},status);
const categories = new Set(["races","classes","subclasses","backgrounds","creatures","items","spells","rules"]);
const editions = new Set(["2014","2024","both","any"]);
const SESSION_SECONDS = 60*60*24*30;
function cookie(request,name){const raw=request.headers.get("Cookie")||"";for(const part of raw.split(";")){const [k,...v]=part.trim().split("=");if(k===name)return v.join("=")}return null}
function sessionCookie(value,maxAge=SESSION_SECONDS){return `codex_session=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`}
function b64(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes)))}
function fromB64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
async function hashPassword(password,salt){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},key,256);return b64(bits)}
async function makePassword(password){const salt=crypto.getRandomValues(new Uint8Array(16));return {salt:b64(salt),hash:await hashPassword(password,salt)}}
async function verifyPassword(password,salt,expected){const actual=await hashPassword(password,fromB64(salt));return actual===expected}
async function getUser(request,env){const token=cookie(request,"codex_session");if(!token)return null;const row=await env.DB.prepare("SELECT users.id, users.username FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?").bind(await sha(token),Date.now()).first();return row||null}
async function sha(value){const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));return b64(digest)}
async function body(request){try{return await request.json()}catch{return null}}
async function route(request,env){
 const url=new URL(request.url),path=url.pathname,method=request.method;
 if(path==="/api/health"&&method==="GET")return json({status:"ok",database:!!env.DB});
 if(path==="/api/auth/register"&&method==="POST"){
  const b=await body(request);if(!b)return fail("Некорректный JSON");
  const username=String(b.username||"").trim(),password=String(b.password||"");
  if(!/^[a-zA-Z0-9_]{3,24}$/.test(username))return fail("Имя: 3–24 символа, латиница, цифры и _");
  if(password.length<8||password.length>128)return fail("Пароль должен содержать от 8 до 128 символов");
  const exists=await env.DB.prepare("SELECT id FROM users WHERE username_lower=?").bind(username.toLowerCase()).first();if(exists)return fail("Это имя пользователя уже занято",409);
  const pw=await makePassword(password),id=crypto.randomUUID(),now=Date.now();
  await env.DB.prepare("INSERT INTO users(id,username,username_lower,password_hash,password_salt,created_at) VALUES(?,?,?,?,?,?)").bind(id,username,username.toLowerCase(),pw.hash,pw.salt,now).run();
  const token=b64(crypto.getRandomValues(new Uint8Array(32)));await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(await sha(token),id,now+SESSION_SECONDS*1000,now).run();
  return json({user:{id,username} },201,{"set-cookie":sessionCookie(token)});
 }
 if(path==="/api/auth/login"&&method==="POST"){
  const b=await body(request);if(!b)return fail("Некорректный JSON");const username=String(b.username||"").trim().toLowerCase(),password=String(b.password||"");
  const user=await env.DB.prepare("SELECT id,username,password_hash,password_salt FROM users WHERE username_lower=?").bind(username).first();
  if(!user||!(await verifyPassword(password,user.password_salt,user.password_hash)))return fail("Неверное имя пользователя или пароль",401);
  const token=b64(crypto.getRandomValues(new Uint8Array(32))),now=Date.now();await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(await sha(token),user.id,now+SESSION_SECONDS*1000,now).run();
  return json({user:{id:user.id,username:user.username}},200,{"set-cookie":sessionCookie(token)});
 }
 if(path==="/api/auth/logout"&&method==="POST"){
  const token=cookie(request,"codex_session");if(token)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha(token)).run();
  return json({ok:true},200,{"set-cookie":sessionCookie("",0)});
 }
 if(path==="/api/auth/me"&&method==="GET"){const user=await getUser(request,env);return json({user:user?{id:user.id,username:user.username}:null})}
 if(path==="/api/entries"&&method==="GET"){
  const cat=url.searchParams.get("category"),q=url.searchParams.get("q");let sql="SELECT e.id,e.name,e.category AS cat,e.edition,e.tag,e.description AS desc,e.is_homebrew,e.owner_id,u.username AS author FROM entries e LEFT JOIN users u ON u.id=e.owner_id WHERE e.status='published'",args=[];
  if(cat&&categories.has(cat)){sql+=" AND e.category=?";args.push(cat)}
  if(q){sql+=" AND (e.name LIKE ? OR e.description LIKE ? OR e.tag LIKE ?)";args.push(`%${q}%`,`%${q}%`,`%${q}%`)}
  sql+=" ORDER BY e.created_at DESC LIMIT 300";const {results}=await env.DB.prepare(sql).bind(...args).all();return json({entries:results});
 }
 if(path==="/api/entries"&&method==="POST"){
  const user=await getUser(request,env);if(!user)return fail("Войди в аккаунт, чтобы публиковать записи",401);
  const b=await body(request);if(!b)return fail("Некорректный JSON");
  const name=String(b.name||"").trim(),desc=String(b.desc||"").trim(),cat=String(b.cat||""),edition=String(b.edition||"both"),tag=String(b.tag||"Хоумбрю").trim();
  if(name.length<2||name.length>70)return fail("Название должно содержать от 2 до 70 символов");
  if(!categories.has(cat))return fail("Неизвестная категория");
  if(!editions.has(edition))return fail("Неизвестная редакция");
  if(desc.length<3||desc.length>5000)return fail("Описание должно содержать от 3 до 5000 символов");
  const id=crypto.randomUUID(),now=Date.now();await env.DB.prepare("INSERT INTO entries(id,name,category,edition,tag,description,is_homebrew,owner_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,'published',?,?)").bind(id,name,cat,edition,tag.slice(0,50),desc,user.id,now,now).run();
  return json({id},201);
 }
 const match=path.match(/^\/api\/entries\/([0-9a-f-]+)$/i);
 if(match&&method==="DELETE"){
  const user=await getUser(request,env);if(!user)return fail("Нужно войти в аккаунт",401);
  const result=await env.DB.prepare("DELETE FROM entries WHERE id=? AND owner_id=? AND is_homebrew=1").bind(match[1],user.id).run();
  if(!result.meta.changes)return fail("Запись не найдена или принадлежит другому пользователю",404);
  return json({ok:true});
 }
 return null;
}
export default {async fetch(request,env){
 if(new URL(request.url).pathname.startsWith("/api/")){try{return await route(request,env)||fail("Маршрут не найден",404)}catch(e){return fail("Ошибка сервера: "+(env.ENVIRONMENT==="development"?e.message:"попробуй позже"),500)}}
 return env.ASSETS.fetch(request);
}};