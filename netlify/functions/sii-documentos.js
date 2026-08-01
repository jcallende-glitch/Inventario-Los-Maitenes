// Netlify Function: sii-documentos.js
const https = require("https");
const { URLSearchParams } = require("url");

const SII_RUT = process.env.SII_RUT;
const SII_CLAVE = process.env.SII_CLAVE;

function parsearRut(rut) {
  const clean = rut.replace(/\./g, "").trim();
  const [num, dv] = clean.split("-");
  return { num, dv: dv.toLowerCase() };
}

function httpsRequest(url, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const reqOptions = {
      hostname: urlObj.hostname,
      port: 443,
      path: urlObj.pathname + urlObj.search,
      method: options.method || "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-CL,es;q=0.9",
        "Accept-Encoding": "identity",
        "Connection": "keep-alive",
        ...options.headers,
      },
      rejectUnauthorized: false,
    };
    const req = https.request(reqOptions, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function extraerCookies(respHeaders, prevCookies = "") {
  const setCookie = respHeaders["set-cookie"] || [];
  const mapa = {};
  if (prevCookies) {
    prevCookies.split(";").forEach(c => {
      const [k, v] = c.trim().split("=");
      if (k) mapa[k.trim()] = v || "";
    });
  }
  setCookie.forEach(c => {
    const parte = c.split(";")[0].trim();
    const eqIdx = parte.indexOf("=");
    if (eqIdx > 0) {
      const k = parte.substring(0, eqIdx).trim();
      const v = parte.substring(eqIdx + 1).trim();
      mapa[k] = v;
    }
  });
  return Object.entries(mapa).map(([k, v]) => `${k}=${v}`).join("; ");
}

async function loginSII() {
  const { num, dv } = parsearRut(SII_RUT);

  // Paso 1: GET homer.sii.cl para obtener cookies iniciales
  const resp1 = await httpsRequest("https://homer.sii.cl/");
  let cookies = extraerCookies(resp1.headers);

  // Paso 2: POST login
  const params = new URLSearchParams({
    rutcont: num,
    dvcontrib: dv,
    clave: SII_CLAVE,
    referencia: "https://homer.sii.cl/",
  });

  const resp2 = await httpsRequest(
    "https://hercules.sii.cl/cgi_AUT2000/autInicio.cgi",
    {
      method: "POST",
      headers: {
        Cookie: cookies,
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(params.toString()),
        "Referer": "https://homer.sii.cl/",
        "Origin": "https://homer.sii.cl",
      },
    },
    params.toString()
  );

  cookies = extraerCookies(resp2.headers, cookies);
  console.log("Login status:", resp2.status);
  console.log("Cookies obtenidas:", cookies.substring(0, 100));

  // Seguir redirección si la hay
  if (resp2.status === 302 && resp2.headers.location) {
    const resp3 = await httpsRequest(resp2.headers.location, {
      headers: { Cookie: cookies, Referer: "https://hercules.sii.cl/" }
    });
    cookies = extraerCookies(resp3.headers, cookies);
  }

  // Verificar que no sea error de clave
  if (resp2.body && (resp2.body.toLowerCase().includes("clave incorrecta") || resp2.body.toLowerCase().includes("rut incorrecto"))) {
    throw new Error("RUT o clave incorrectos");
  }

  return cookies;
}

async function obtenerDocumentos(cookies) {
  const { num, dv } = parsearRut(SII_RUT);
  const hoy = new Date();
  const documentos = [];

  for (let i = 0; i < 3; i++) {
    const fecha = new Date(hoy.getFullYear(), hoy.getMonth() - i, 1);
    const periodo = `${fecha.getFullYear()}${String(fecha.getMonth() + 1).padStart(2, "0")}`;

    try {
      const url = `https://www4.sii.cl/consdcvinternetui/services/data/facturacion/listadoDTE?rutEmpresa=${num}${dv}&periodo=${periodo}&tipo=COMPRAS`;
      const resp = await httpsRequest(url, {
        headers: {
          Cookie: cookies,
          "Accept": "application/json, text/plain, */*",
          "Referer": "https://www4.sii.cl/consdcvinternetui/index.html",
        }
      });

      console.log(`Periodo ${periodo} status:`, resp.status, "body:", resp.body.substring(0, 200));

      if (resp.status === 200 && resp.body) {
        try {
          const data = JSON.parse(resp.body);
          const lista = data.data || data.listado || data.documentos || [];
          if (Array.isArray(lista)) lista.forEach(d => documentos.push({ ...d, periodo }));
        } catch(e) { console.log("Parse error:", e.message); }
      }
    } catch(e) { console.log(`Error ${periodo}:`, e.message); }
  }

  return documentos;
}

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  if (!SII_RUT || !SII_CLAVE) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: "Variables SII_RUT y SII_CLAVE no configuradas" }) };
  }

  try {
    const cookies = await loginSII();
    const documentos = await obtenerDocumentos(cookies);
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true, total: documentos.length, documentos }) };
  } catch(e) {
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: e.message }) };
  }
};
