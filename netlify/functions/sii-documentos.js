const https = require("https");
const { URLSearchParams } = require("url");

const SII_RUT = process.env.SII_RUT;
const SII_CLAVE = process.env.SII_CLAVE;

function parsearRut(rut) {
  const clean = rut.replace(/\./g, "").trim();
  const idx = clean.lastIndexOf("-");
  return { num: clean.substring(0, idx), dv: clean.substring(idx + 1).toLowerCase() };
}

function req(url, opts = {}, body = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const o = {
      hostname: u.hostname,
      port: 443,
      path: u.pathname + u.search,
      method: opts.method || "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "es-CL,es;q=0.9",
        "Accept-Encoding": "identity",
        "Connection": "keep-alive",
        ...opts.headers,
      },
      rejectUnauthorized: false,
    };
    const r = https.request(o, res => {
      let d = "";
      res.on("data", c => d += c);
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, location: res.headers.location, body: d }));
    });
    r.on("error", reject);
    if (body) r.write(body);
    r.end();
  });
}

// Jar por dominio
const jars = {};
function getJar(domain) {
  if (!jars[domain]) jars[domain] = {};
  return jars[domain];
}
function parseCookies(hostname, headers) {
  const jar = getJar(hostname);
  (headers["set-cookie"] || []).forEach(c => {
    const p = c.split(";")[0].trim();
    const i = p.indexOf("=");
    if (i > 0) jar[p.substring(0, i).trim()] = p.substring(i + 1).trim();
  });
}
function cookieStr(hostname) {
  return Object.entries(getJar(hostname)).map(([k, v]) => `${k}=${v}`).join("; ");
}

async function get(url, extra = {}) {
  const hostname = new URL(url).hostname;
  const r = await req(url, { headers: { Cookie: cookieStr(hostname), ...extra } });
  parseCookies(hostname, r.headers);
  return r;
}

async function post(url, params, extra = {}) {
  const hostname = new URL(url).hostname;
  const body = params.toString();
  const r = await req(url, {
    method: "POST",
    headers: {
      Cookie: cookieStr(hostname),
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(body),
      ...extra,
    }
  }, body);
  parseCookies(hostname, r.headers);
  return r;
}

async function loginSII() {
  const { num, dv } = parsearRut(SII_RUT);

  // 1. GET zeusr login page
  const r1 = await get("https://zeusr.sii.cl/AUT2000/InicioAutenticacion/IngresarNormalAuto.html", {
    Referer: "https://homer.sii.cl/"
  });
  console.log("zeusr page:", r1.status, "cookies:", Object.keys(getJar("zeusr.sii.cl")));

  // 2. POST credenciales
  const params = new URLSearchParams({ rutcont: num, dvcontrib: dv, clave: SII_CLAVE, referencia: "https://homer.sii.cl/" });
  const r2 = await post("https://zeusr.sii.cl/cgi_AUT2000/autInicio.cgi", params, {
    Referer: "https://zeusr.sii.cl/AUT2000/InicioAutenticacion/IngresarNormalAuto.html",
    Origin: "https://zeusr.sii.cl",
  });
  console.log("login:", r2.status, "location:", r2.location, "cookies:", Object.keys(getJar("zeusr.sii.cl")));

  // 3. Seguir redirecciones hasta homer.sii.cl
  let loc = r2.location;
  for (let i = 0; i < 8 && loc; i++) {
    const base = loc.startsWith("http") ? loc : `https://homer.sii.cl${loc}`;
    const hostname = new URL(base).hostname;
    console.log(`redir ${i} -> ${hostname}: ${base.substring(0, 70)}`);
    const rr = await get(base, { Referer: loc });
    console.log(`redir ${i} status: ${rr.status} cookies[${hostname}]:`, Object.keys(getJar(hostname)));
    if (rr.body && rr.body.toLowerCase().includes("errorp")) throw new Error("Credenciales incorrectas");
    loc = rr.location;
    if (rr.status === 200 && !rr.location) break;
  }

  // 4. Ahora navegar a www4.sii.cl con la sesión activa
  console.log("Navegando a www4.sii.cl...");
  const r4 = await get("https://www4.sii.cl/consdcvinternetui/index.html", {
    Referer: "https://homer.sii.cl/",
  });
  console.log("www4 index:", r4.status, "location:", r4.location, "cookies:", Object.keys(getJar("www4.sii.cl")));

  // Seguir redirecciones de www4 si las hay
  let loc4 = r4.location;
  for (let i = 0; i < 4 && loc4; i++) {
    const base = loc4.startsWith("http") ? loc4 : `https://www4.sii.cl${loc4}`;
    console.log(`www4 redir ${i}:`, base.substring(0, 80));
    const rr = await get(base, { Referer: "https://www4.sii.cl/" });
    console.log(`www4 redir ${i} status:`, rr.status, "cookies:", Object.keys(getJar(new URL(base).hostname)));
    loc4 = rr.location;
    if (rr.status === 200 && !rr.location) break;
  }

  console.log("Cookies www4.sii.cl:", Object.keys(getJar("www4.sii.cl")));
  console.log("Cookies homer.sii.cl:", Object.keys(getJar("homer.sii.cl")));
  console.log("Cookies zeusr.sii.cl:", Object.keys(getJar("zeusr.sii.cl")));
}

async function obtenerDTERecibidos() {
  const { num, dv } = parsearRut(SII_RUT);
  const hoy = new Date();
  const docs = [];

  for (let i = 0; i < 3; i++) {
    const d = new Date(hoy.getFullYear(), hoy.getMonth() - i, 1);
    const periodo = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}`;

    try {
      const url = `https://www4.sii.cl/consdcvinternetui/services/data/facturacion/listadoDTE?rutEmpresa=${num}${dv}&periodo=${periodo}&tipo=COMPRAS`;
      const r = await req(url, {
        headers: {
          Cookie: cookieStr("www4.sii.cl"),
          Accept: "application/json, */*",
          Referer: "https://www4.sii.cl/consdcvinternetui/index.html",
          "X-Requested-With": "XMLHttpRequest",
        }
      });
      parseCookies("www4.sii.cl", r.headers);
      console.log(`DTE ${periodo}: ${r.status} — ${r.body.substring(0, 200)}`);

      if (r.status === 200) {
        try {
          const data = JSON.parse(r.body);
          const lista = data.data || data.listado || data.documentos || data || [];
          if (Array.isArray(lista)) lista.forEach(x => docs.push({ ...x, periodo }));
        } catch(e) { console.log("parse err:", e.message); }
      }
    } catch(e) { console.log(`err ${periodo}:`, e.message); }
  }

  return docs;
}

exports.handler = async (event) => {
  const headers = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };
  if (!SII_RUT || !SII_CLAVE) return { statusCode: 500, headers, body: JSON.stringify({ error: "Variables no configuradas" }) };

  try {
    await loginSII();
    const docs = await obtenerDTERecibidos();
    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        ok: true, total: docs.length, documentos: docs,
        cookieKeys: {
          zeusr: Object.keys(getJar("zeusr.sii.cl")),
          homer: Object.keys(getJar("homer.sii.cl")),
          www4: Object.keys(getJar("www4.sii.cl")),
        }
      })
    };
  } catch(e) {
    console.error("Error:", e.message);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: e.message }) };
  }
};
