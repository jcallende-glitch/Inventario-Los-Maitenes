// Netlify Function: sii-documentos.js
// Obtiene facturas y guías de despacho recibidas desde el portal SII
// Las credenciales se leen desde variables de entorno — nunca se exponen al navegador

const https = require("https");
const http = require("http");
const { URLSearchParams } = require("url");

const SII_RUT = process.env.SII_RUT;       // ej: 76123456-7
const SII_CLAVE = process.env.SII_CLAVE;   // clave tributaria

// Parsear RUT en partes (sin puntos, separado por guión)
function parsearRut(rut) {
  const [num, dv] = rut.split("-");
  return { num: num.replace(/\./g, ""), dv };
}

// Función para hacer requests HTTP/HTTPS con soporte de cookies
function request(url, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const lib = urlObj.protocol === "https:" ? https : http;
    const reqOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === "https:" ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: options.method || "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-CL,es;q=0.9",
        ...options.headers,
      },
    };

    const req = lib.request(reqOptions, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data,
          location: res.headers.location,
        });
      });
    });

    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// Login al SII y obtención de token de sesión
async function loginSII() {
  const { num, dv } = parsearRut(SII_RUT);

  // Paso 1: obtener página de login para extraer token CSRF
  const loginPage = await request("https://misiir.sii.cl/cgi_misii/siihome.cgi");
  
  // Paso 2: hacer login con RUT y clave
  const params = new URLSearchParams({
    rutcont: num,
    dvcontrib: dv,
    clave: SII_CLAVE,
    referencia: "https://misiir.sii.cl/cgi_misii/siihome.cgi",
  });

  const loginResp = await request(
    "https://hercules.sii.cl/cgi_AUT2000/autInicio.cgi",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "https://misiir.sii.cl/cgi_misii/siihome.cgi",
      },
    },
    params.toString()
  );

  // Extraer cookies de sesión
  const setCookie = loginResp.headers["set-cookie"] || [];
  const cookies = setCookie.map((c) => c.split(";")[0]).join("; ");

  if (!cookies || loginResp.status >= 400) {
    throw new Error("Login fallido — verificar RUT y clave");
  }

  return cookies;
}

// Obtener documentos del Registro de Compras
async function obtenerDocumentos(cookies, tipo = "33,52") {
  // tipo 33 = Factura electrónica, 52 = Guía de despacho
  const hoy = new Date();
  const mesActual = String(hoy.getMonth() + 1).padStart(2, "0");
  const anio = hoy.getFullYear();
  const mesPrevio = hoy.getMonth() === 0 ? "12" : String(hoy.getMonth()).padStart(2, "0");
  const anioPrevio = hoy.getMonth() === 0 ? anio - 1 : anio;

  const { num, dv } = parsearRut(SII_RUT);

  // Consultar registro de compras del mes actual y el anterior
  const meses = [
    { mes: mesActual, anio },
    { mes: mesPrevio, anio: anioPrevio },
  ];

  let documentos = [];

  for (const { mes, anio: a } of meses) {
    try {
      const url = `https://www4.sii.cl/consdcvinternetui/services/data/facturacion/listadoDTE?rutEmpresa=${num}${dv}&periodo=${a}${mes}&tipo=COMPRAS`;
      
      const resp = await request(url, {
        headers: {
          Cookie: cookies,
          Accept: "application/json",
          Referer: "https://www4.sii.cl/consdcvinternetui/index.html",
        },
      });

      if (resp.status === 200) {
        try {
          const data = JSON.parse(resp.body);
          const docs = data.data || data.listado || data.documentos || [];
          documentos = documentos.concat(docs.map(d => ({
            ...d,
            periodo: `${a}-${mes}`,
          })));
        } catch (e) {
          console.log("No se pudo parsear respuesta:", resp.body.substring(0, 200));
        }
      }
    } catch (e) {
      console.log(`Error consultando periodo ${a}-${mes}:`, e.message);
    }
  }

  return documentos;
}

// Handler principal
exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  if (!SII_RUT || !SII_CLAVE) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: "Variables SII_RUT y SII_CLAVE no configuradas" }),
    };
  }

  try {
    console.log("Iniciando login SII para RUT:", SII_RUT);
    const cookies = await loginSII();
    console.log("Login exitoso, obteniendo documentos...");
    const documentos = await obtenerDocumentos(cookies);
    console.log(`Documentos encontrados: ${documentos.length}`);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        ok: true,
        total: documentos.length,
        documentos,
      }),
    };
  } catch (e) {
    console.error("Error:", e.message);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ ok: false, error: e.message }),
    };
  }
};
