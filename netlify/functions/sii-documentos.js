const https = require("https");
const { URLSearchParams } = require("url");

const SII_RUT = process.env.SII_RUT;
const SII_CLAVE = process.env.SII_CLAVE;

function parsearRut(rut) {
  const clean = rut.replace(/\./g, "").trim();
  const idx = clean.lastIndexOf("-");
  return { num: clean.substring(0, idx), dv: clean.substring(idx + 1).toLowerCase() };
}

function httpsGet(url, cookieJar = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const cookieStr = Object.entries(cookieJar).map(([k,v]) => `${k}=${v}`).join("; ");
    const options = {
      hostname: urlObj.hostname,
      port: 443,
      path: urlObj.pathname + urlObj.search,
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "es-CL,es;q=0.9",
        "Accept-Encoding": "identity",
        ...(cookieStr ? { Cookie: cookieStr } : {}),
      },
      rejectUnauthorized: false,
    };
    const req = https.request(options, res => {
      let body = "";
      // Capturar cookies
      (res.headers["set-cookie"] || []).forEach(c => {
        const part = c.split(";")[0].trim();
        const eqIdx = part.indexOf("=");
        if (eqIdx > 0) cookieJar[part.substring(0, eqIdx).trim()] = part.substring(eqIdx + 1).trim();
      });
      res.on("data", chunk => body += chunk);
      res.on("end", () => resolve({ status: res.statusCode, location: res.headers.location, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

function httpsPost(url, params, cookieJar = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const body = params.toString();
    const cookieStr = Object.entries(cookieJar).map(([k,v]) => `${k}=${v}`).join("; ");
    const options = {
      hostname: urlObj.hostname,
      port: 443,
      path: urlObj.pathname + urlObj.search,
      method: "POST",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "es-CL,es;q=0.9",
        "Accept-Encoding": "identity",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        "Referer": "https://homer.sii.cl/",
        "Origin": "https://homer.sii.cl",
        ...(cookieStr ? { Cookie: cookieStr } : {}),
      },
      rejectUnauthorized: false,
    };
    const req = https.request(options, res => {
      let respBody = "";
      // Capturar cookies
      (res.headers["set-cookie"] || []).forEach(c => {
        const part = c.split(";")[0].trim();
        const eqIdx = part.indexOf("=");
        if (eqIdx > 0) cookieJar[part.substring(0, eqIdx).trim()] = part.substring(eqIdx + 1).trim();
      });
      res.on("data", chunk => respBody += chunk);
      res.on("end", () => resolve({ status: res.statusCode, location: res.headers.location, body: respBody }));
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

async function loginSII() {
  const { num, dv } = parsearRut(SII_RUT);
  const jar = {};

  // 1. GET homer para obtener cookies iniciales
  const r1 = await httpsGet("https://homer.sii.cl/", jar);
  console.log("homer.sii.cl status:", r1.status, "cookies:", Object.keys(jar).join(","));

  // 2. Si hay redirección, seguirla
  if (r1.status === 302 && r1.location) {
    const r1b = await httpsGet(r1.location, jar);
    console.log("redirect status:", r1b.status);
  }

  // 3. POST login
  const params = new URLSearchParams({
    rutcont: num,
    dvcontrib: dv,
    clave: SII_CLAVE,
    referencia: "https://homer.sii.cl/",
  });

  const r2 = await httpsPost("https://hercules.sii.cl/cgi_AUT2000/autInicio.cgi", params, jar);
  console.log("login POST status:", r2.status, "location:", r2.location, "cookies:", Object.keys(jar).join(","));

  // 4. Seguir redirecciones post-login (puede haber varias)
  let location = r2.location;
  let intentos = 0;
  while (location && intentos < 5) {
    const base = location.startsWith("http") ? location : `https://homer.sii.cl${location}`;
    const redir = await httpsGet(base, jar);
    console.log("redir", intentos, "->", base.substring(0, 60), "status:", redir.status, "cookies:", Object.keys(jar).join(","));
    location = redir.location;
    intentos++;
    if (redir.status === 200) break;
  }

  console.log("Jar final:", Object.keys(jar).join(","));

  // Verificar que tenemos cookies de sesión válidas
  const tieneToken = Object.keys(jar).some(k =>
    k.includes("TOKEN") || k.includes("SII") || k.includes("JSESSIONID") || k.includes("AUT")
  );

  if (!tieneToken && Object.keys(jar).length === 0) {
    throw new Error("Login fallido — no se obtuvieron cookies de sesión");
  }

  return jar;
}

async function obtenerDocumentos(jar) {
  const { num, dv } = parsearRut(SII_RUT);
  const hoy = new Date();
  const documentos = [];

  for (let i = 0; i < 3; i++) {
    const fecha = new Date(hoy.getFullYear(), hoy.getMonth() - i, 1);
    const periodo = `${fecha.getFullYear()}${String(fecha.getMonth() + 1).padStart(2, "0")}`;
    const cookieStr = Object.entries(jar).map(([k,v]) => `${k}=${v}`).join("; ");

    try {
      // Intentar con el endpoint del DCV
      const url = `https://www4.sii.cl/consdcvinternetui/services/data/facturacion/listadoDTE?rutEmpresa=${num}${dv}&periodo=${periodo}&tipo=COMPRAS`;

      const resp = await new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const req = https.request({
          hostname: urlObj.hostname,
          port: 443,
          path: urlObj.pathname + urlObj.search,
          method: "GET",
          headers: {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "identity",
            "Cookie": cookieStr,
            "Referer": "https://www4.sii.cl/consdcvinternetui/index.html",
          },
          rejectUnauthorized: false,
        }, res => {
          let body = "";
          res.on("data", c => body += c);
          res.on("end", () => resolve({ status: res.statusCode, body }));
        });
        req.on("error", reject);
        req.end();
      });

      console.log(`DCV ${periodo}: HTTP ${resp.status} — ${resp.body.substring(0, 150)}`);

      if (resp.status === 200) {
        try {
          const data = JSON.parse(resp.body);
          const lista = data.data || data.listado || data.documentos || [];
          if (Array.isArray(lista)) lista.forEach(d => documentos.push({ ...d, periodo }));
        } catch(e) {
          console.log("JSON parse error:", e.message);
        }
      }
    } catch(e) {
      console.log(`Error ${periodo}:`, e.message);
    }
  }

  return documentos;
}

exports.handler = async (event) => {
  const headers = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };

  if (!SII_RUT || !SII_CLAVE) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: "Variables no configuradas" }) };
  }

  try {
    const jar = await loginSII();
    const documentos = await obtenerDocumentos(jar);
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true, total: documentos.length, documentos, cookies: Object.keys(jar) }) };
  } catch(e) {
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: e.message }) };
  }
};
