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
        "Accept": "*/*",
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
      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers,
        location: res.headers.location,
        body: d,
      }));
    });
    r.on("error", reject);
    if (body) r.write(body);
    r.end();
  });
}

function parseCookies(headers, jar = {}) {
  (headers["set-cookie"] || []).forEach(c => {
    const p = c.split(";")[0].trim();
    const i = p.indexOf("=");
    if (i > 0) jar[p.substring(0, i).trim()] = p.substring(i + 1).trim();
  });
  return jar;
}

function cookieStr(jar) {
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");
}

async function loginSII() {
  const { num, dv } = parsearRut(SII_RUT);
  const jar = {};

  // Paso 1: Obtener token CSRF desde la página de login
  const r1 = await req("https://zeusr.sii.cl/AUT2000/InicioAutenticacion/IngresarNormalAuto.html", {
    headers: { Referer: "https://homer.sii.cl/" }
  });
  parseCookies(r1.headers, jar);
  console.log("Step1 status:", r1.status, "cookies:", Object.keys(jar));

  // Extraer token oculto si existe
  let token = "";
  const tokenMatch = r1.body.match(/name="token"\s+value="([^"]+)"/);
  if (tokenMatch) token = tokenMatch[1];
  console.log("Token CSRF:", token ? "found" : "not found");

  // Paso 2: POST con credenciales al endpoint de autenticación
  const params = new URLSearchParams({
    rutcont: num,
    dvcontrib: dv,
    clave: SII_CLAVE,
    referencia: "https://homer.sii.cl/",
    ...(token ? { token } : {}),
  });

  const r2 = await req(
    "https://zeusr.sii.cl/cgi_AUT2000/autInicio.cgi",
    {
      method: "POST",
      headers: {
        Cookie: cookieStr(jar),
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(params.toString()),
        "Referer": "https://zeusr.sii.cl/AUT2000/InicioAutenticacion/IngresarNormalAuto.html",
        "Origin": "https://zeusr.sii.cl",
      },
    },
    params.toString()
  );
  parseCookies(r2.headers, jar);
  console.log("Step2 status:", r2.status, "location:", r2.location, "cookies:", Object.keys(jar));

  // Paso 3: Seguir redirecciones
  let loc = r2.location;
  for (let i = 0; i < 6 && loc; i++) {
    const base = loc.startsWith("http") ? loc : `https://homer.sii.cl${loc}`;
    console.log(`Redir ${i}:`, base.substring(0, 80));
    const rr = await req(base, {
      headers: {
        Cookie: cookieStr(jar),
        Referer: i === 0 ? "https://zeusr.sii.cl/" : loc,
      }
    });
    parseCookies(rr.headers, jar);
    console.log(`Redir ${i} status:`, rr.status, "cookies:", Object.keys(jar));
    if (rr.body && rr.body.includes("errorp")) {
      throw new Error("Credenciales incorrectas — SII devolvió página de error");
    }
    loc = rr.location;
    if (rr.status === 200 && !rr.location) break;
  }

  console.log("Jar final keys:", Object.keys(jar));

  // Necesitamos al menos alguna cookie de sesión
  if (Object.keys(jar).length === 0) {
    throw new Error("No se obtuvieron cookies de sesión");
  }

  return jar;
}

async function obtenerDTERecibidos(jar) {
  const { num, dv } = parsearRut(SII_RUT);
  const hoy = new Date();
  const docs = [];

  for (let i = 0; i < 3; i++) {
    const d = new Date(hoy.getFullYear(), hoy.getMonth() - i, 1);
    const periodo = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}`;

    try {
      // Endpoint interno del portal de consulta DTE
      const url = `https://www4.sii.cl/consdcvinternetui/services/data/facturacion/listadoDTE?rutEmpresa=${num}${dv}&periodo=${periodo}&tipo=COMPRAS`;
      const r = await req(url, {
        headers: {
          Cookie: cookieStr(jar),
          Accept: "application/json, */*",
          Referer: "https://www4.sii.cl/consdcvinternetui/index.html",
          "X-Requested-With": "XMLHttpRequest",
        }
      });
      console.log(`DTE ${periodo}: HTTP ${r.status} body:`, r.body.substring(0, 200));

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

  if (!SII_RUT || !SII_CLAVE) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: "Variables no configuradas" }) };
  }

  try {
    const jar = await loginSII();
    const docs = await obtenerDTERecibidos(jar);
    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ok: true, total: docs.length, documentos: docs, cookieKeys: Object.keys(jar) })
    };
  } catch(e) {
    console.error("Error:", e.message);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: e.message }) };
  }
};
