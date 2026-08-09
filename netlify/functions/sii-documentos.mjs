import { withLambda } from "@netlify/aws-lambda-compat";
import https from "https";
import forge from "node-forge";
import { SignedXml } from "xml-crypto";

// El certificado viene dividido en 2 variables de entorno por el límite de 5000
// caracteres de Netlify. Se reconstruye aquí uniendo ambas partes.
// El .trim() elimina espacios/saltos de línea que a veces se cuelan al copiar y pegar.
const PARTE_1 = (process.env.SII_CERT_B64_1 || "").trim();
const PARTE_2 = (process.env.SII_CERT_B64_2 || "").trim();
const CERT_B64 = `${PARTE_1}${PARTE_2}`;
const CERT_PASS = process.env.SII_CERT_PASS;

// ---------------------------------------------------------------------------
// 1. Cargar certificado digital (.pfx) y extraer llave privada + certificado
// ---------------------------------------------------------------------------
function cargarCertificado() {
  if (!CERT_B64 || !CERT_PASS) {
    throw new Error("Faltan variables SII_CERT_B64_1 / SII_CERT_B64_2 / SII_CERT_PASS");
  }

  console.log(
    `Diagnóstico certificado -> parte1: ${PARTE_1.length} chars, parte2: ${PARTE_2.length} chars, total: ${CERT_B64.length} chars`
  );
  // Validar que el string sólo contenga caracteres base64 válidos
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(CERT_B64)) {
    const invalido = CERT_B64.split("").find((c) => !/[A-Za-z0-9+/=]/.test(c));
    throw new Error(
      `El certificado reconstruido contiene caracteres inválidos para base64 (ej: ${JSON.stringify(
        invalido
      )}). Revisa que las variables SII_CERT_B64_1 y SII_CERT_B64_2 no tengan espacios ni saltos de línea extra.`
    );
  }

  let pfxDer;
  try {
    pfxDer = forge.util.decode64(CERT_B64);
  } catch (e) {
    throw new Error(`Error decodificando base64 (largo total: ${CERT_B64.length}): ${e.message}`);
  }

  let p12Asn1;
  try {
    p12Asn1 = forge.asn1.fromDer(pfxDer);
  } catch (e) {
    throw new Error(
      `Error leyendo estructura ASN.1 (bytes decodificados: ${pfxDer.length}). Esto casi siempre significa que el base64 reconstruido está incompleto o corrupto. Detalle: ${e.message}`
    );
  }
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, CERT_PASS);

  let cert, privateKey;
  for (const safeContents of p12.safeContents) {
    for (const safeBag of safeContents.safeBags) {
      if (safeBag.type === forge.pki.oids.certBag) cert = safeBag.cert;
      if (
        safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag ||
        safeBag.type === forge.pki.oids.keyBag
      ) {
        privateKey = safeBag.key;
      }
    }
  }
  if (!cert || !privateKey) {
    throw new Error("No se pudo extraer certificado o llave privada del .pfx (revisar SII_CERT_PASS)");
  }

  const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const certB64 = forge.util.encode64(certDer);

  const bigIntToBytes = (bn) => {
    let hex = bn.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    return forge.util.hexToBytes(hex);
  };
  const modulus = forge.util.encode64(bigIntToBytes(cert.publicKey.n));
  const exponent = forge.util.encode64(bigIntToBytes(cert.publicKey.e));

  const cn = cert.subject.attributes.find((a) => a.name === "commonName");
  console.log("Certificado cargado. Titular:", cn ? cn.value : "(desconocido)");

  return { privateKeyPem, certB64, modulus, exponent };
}

// ---------------------------------------------------------------------------
// Helper genérico para llamadas SOAP / HTTP
// ---------------------------------------------------------------------------
function soapRequest(url, body, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request(
      {
        hostname: u.hostname,
        path: u.pathname + u.search,
        method: "POST",
        headers: {
          "Content-Type": "text/xml; charset=utf-8",
          "Content-Length": Buffer.byteLength(body),
          SOAPAction: "",
          ...extraHeaders,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function decodeXmlEntities(str) {
  return str
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&");
}

// ---------------------------------------------------------------------------
// 2. Obtener semilla (CrSeed.jws)
// ---------------------------------------------------------------------------
async function obtenerSemilla() {
  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body>
<m:getSeed xmlns:m="https://palena.sii.cl/DTEWS/CrSeed.jws"/>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>`;

  const r = await soapRequest("https://palena.sii.cl/DTEWS/CrSeed.jws", soapBody);
  console.log("CrSeed status:", r.status);

  // Tolerante a prefijos de namespace: busca cualquier etiqueta que termine en
  // "getSeedReturn" o "getSeedResponse", con o sin prefijo tipo "ns1:".
  const m = r.body.match(
    /<(?:[\w-]+:)?getSeedReturn[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?getSeedReturn>/
  );
  if (!m) {
    throw new Error(
      "Respuesta inesperada de CrSeed (no se encontró getSeedReturn). Respuesta completa: " +
        r.body.substring(0, 2000)
    );
  }

  const decoded = decodeXmlEntities(m[1]);
  const estadoMatch = decoded.match(/<ESTADO>(-?\d+)<\/ESTADO>/);
  const semillaMatch = decoded.match(/<SEMILLA>(\d+)<\/SEMILLA>/);

  if (!semillaMatch) {
    throw new Error(
      `No se pudo obtener semilla. Estado: ${estadoMatch ? estadoMatch[1] : "?"} — ${decoded}`
    );
  }
  return semillaMatch[1];
}

// ---------------------------------------------------------------------------
// 3. Firmar la semilla con el certificado (formato XML-DSig exigido por el SII)
// ---------------------------------------------------------------------------
function firmarSemilla(semilla, certData) {
  const { privateKeyPem, certB64, modulus, exponent } = certData;
  const xmlSinFirmar = `<getToken><item><Semilla>${semilla}</Semilla></item></getToken>`;

  const sig = new SignedXml({
    privateKey: privateKeyPem,
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  });

  sig.addReference({
    xpath: "//*[local-name(.)='getToken']",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"],
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    isEmptyUri: true,
  });

  sig.getKeyInfoContent = () =>
    `<KeyValue><RSAKeyValue><Modulus>${modulus}</Modulus><Exponent>${exponent}</Exponent></RSAKeyValue></KeyValue><X509Data><X509Certificate>${certB64}</X509Certificate></X509Data>`;

  sig.computeSignature(xmlSinFirmar, {
    location: { reference: "//*[local-name(.)='item']", action: "after" },
  });

  return sig.getSignedXml();
}

// ---------------------------------------------------------------------------
// 4. Canjear la semilla firmada por un Token (GetTokenFromSeed.jws)
// ---------------------------------------------------------------------------
async function obtenerToken(xmlFirmado) {
  const xmlEscapado = xmlFirmado
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<SOAP-ENV:Body>
<m:getToken xmlns:m="https://palena.sii.cl/DTEWS/GetTokenFromSeed.jws">
<pszXml xsi:type="xsd:string">${xmlEscapado}</pszXml>
</m:getToken>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>`;

  const r = await soapRequest("https://palena.sii.cl/DTEWS/GetTokenFromSeed.jws", soapBody);
  console.log("GetTokenFromSeed status:", r.status);

  const m = r.body.match(
    /<(?:[\w-]+:)?getTokenReturn[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?getTokenReturn>/
  );
  if (!m) {
    throw new Error(
      "Respuesta inesperada de GetTokenFromSeed (no se encontró getTokenReturn). Respuesta completa: " +
        r.body.substring(0, 2000)
    );
  }

  const decoded = decodeXmlEntities(m[1]);
  const estadoMatch = decoded.match(/<ESTADO>(-?\d+)<\/ESTADO>/);
  const glosaMatch = decoded.match(/<GLOSA>([^<]*)<\/GLOSA>/);
  const tokenMatch = decoded.match(/<TOKEN>([^<]+)<\/TOKEN>/);

  if (!tokenMatch) {
    throw new Error(
      `No se pudo obtener token. Estado: ${estadoMatch ? estadoMatch[1] : "?"} — ${
        glosaMatch ? glosaMatch[1] : decoded
      }`
    );
  }
  return tokenMatch[1];
}

// ---------------------------------------------------------------------------
// 5. Consultar el detalle de compras de UN proveedor específico en un período.
//    Este es el endpoint real que usa la aplicación "Registro de Compras y Ventas"
//    del SII (confirmado por múltiples desarrolladores externos). Requiere saber
//    de antemano el RUT del proveedor — no existe una versión pública confirmada
//    que liste automáticamente TODOS los proveedores de un período sin conocerlos.
// ---------------------------------------------------------------------------
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
        Accept: "application/json, text/plain, */*",
        "Accept-Language": "es-CL,es;q=0.9",
        ...opts.headers,
      },
    };
    const r = https.request(o, (res) => {
      let d = "";
      res.on("data", (c) => (d += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: d }));
    });
    r.on("error", reject);
    if (body) r.write(body);
    r.end();
  });
}

// rutEmisor/dvEmisor: RUT del PROVEEDOR (no de tu empresa) sin puntos, con dígito
// verificador separado. periodo: "202506" (año+mes). token: el TOKEN ya obtenido.
async function getDetalleCompra(token, rutEmisor, dvEmisor, periodo) {
  const url = "https://www4.sii.cl/consdcvinternetui/services/data/facadeService/getDetalleCompra";
  const body = JSON.stringify({
    metaData: {
      conversationId: token,
      transactionId: "0",
      namespace: "cl.sii.sdi.lob.diii.consdcv.data.api.interfaces.FacadeService/getDetalleCompra",
      page: null,
    },
    data: {
      rutEmisor: String(rutEmisor),
      dvEmisor: String(dvEmisor),
      ptributario: String(periodo),
      operacion: "COMPRA",
      estadoContab: "REGISTRO",
      codTipoDoc: "0", // 0 = todos los tipos de documento
    },
  });

  const r = await req(
    url,
    {
      method: "POST",
      headers: {
        Cookie: `TOKEN=${token}`,
        "Content-Type": "application/json;charset=utf-8",
      },
    },
    body
  );

  console.log(`getDetalleCompra (${rutEmisor}-${dvEmisor}, ${periodo}): status ${r.status} — ${r.body.substring(0, 300)}`);

  if (r.status !== 200) {
    throw new Error(`SII respondió ${r.status} al consultar el proveedor ${rutEmisor}-${dvEmisor}: ${r.body.substring(0, 300)}`);
  }
  return JSON.parse(r.body);
}

// ---------------------------------------------------------------------------
// 5b. AUTENTICACIÓN POR TLS MUTUO (necesaria para las apps web del SII, como
//     el Registro de Compras y Ventas en consdcvinternetui).
//
//     Esto es DISTINTO al flujo de semilla/token de más arriba (ese sirve para
//     Web Services tipo SOAP). Aquí el certificado se presenta directo en la
//     conexión HTTPS (como lo hace un navegador cuando eliges "Certificado
//     Digital" para entrar a sii.cl), y el SII responde con una cookie de
//     sesión (TOKEN o SESSIONID) que se usa después para consultar el RCV.
// ---------------------------------------------------------------------------
function mutualTlsRequest(url, opts = {}, body = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const pfxBuffer = Buffer.from(CERT_B64, "base64");
    const o = {
      hostname: u.hostname,
      port: 443,
      path: u.pathname + u.search,
      method: opts.method || "GET",
      pfx: pfxBuffer,
      passphrase: CERT_PASS,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        ...opts.headers,
      },
    };
    const r = https.request(o, (res) => {
      let d = "";
      res.on("data", (c) => (d += c));
      res.on("end", () =>
        resolve({ status: res.statusCode, headers: res.headers, body: d })
      );
    });
    r.on("error", reject);
    if (body) r.write(body);
    r.end();
  });
}

async function loginConCertificadoTLS() {
  const referencia = "https://palena.sii.cl/cgi_dte/UPL/DTEauth?1";
  const bodyForm = `referencia=${encodeURIComponent(referencia)}`;

  const r = await mutualTlsRequest(
    "https://herculesr.sii.cl/cgi_AUT2000/CAutInicio.cgi",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(bodyForm),
      },
    },
    bodyForm
  );

  console.log(
    `Login TLS mutuo -> status: ${r.status}, set-cookie: ${JSON.stringify(
      r.headers["set-cookie"] || []
    )}`
  );

  const cookies = r.headers["set-cookie"] || [];
  for (const c of cookies) {
    const m = c.match(/^(TOKEN|SESSIONID)=([^;]+)/);
    if (m) return { nombre: m[1], valor: m[2] };
  }

  throw new Error(
    `No se encontró cookie TOKEN/SESSIONID tras el login TLS. Status: ${r.status}. Respuesta (primeros 1000 caracteres): ${r.body.substring(
      0,
      1000
    )}`
  );
}

// rutPropio/dvPropio: el RUT DE TU PROPIA EMPRESA (no de un proveedor externo).
// Con esto el SII devuelve el resumen agrupado por TODOS los proveedores del
// período, tal como se ve en la pantalla de "Registro de Compras y Ventas".
async function getResumenRCV(cookie, rutPropio, dvPropio, periodo, operacion) {
  const estados =
    operacion === "VENTA" ? ["REGISTRO"] : ["REGISTRO", "RECLAMADO", "PENDIENTE"];

  const resultados = {};
  for (const estado of estados) {
    const payload = JSON.stringify({
      metaData: {
        namespace: "cl.sii.sdi.lob.diii.consdcv.data.api.interfaces.FacadeService/getResumen",
        conversationId: `${cookie.nombre}=${cookie.valor}`,
        transactionId: String(Date.now()),
      },
      data: {
        RutEmisor: String(rutPropio),
        DvEmisor: String(dvPropio),
        EstadoContab: estado,
        Ptributario: String(periodo),
        Operacion: operacion.toUpperCase(),
      },
    });

    const r = await mutualTlsRequest(
      "https://www4.sii.cl/consdcvinternetui/services/data/facadeService/getResumen",
      {
        method: "POST",
        headers: {
          Cookie: `${cookie.nombre}=${cookie.valor}`,
          "Content-Type": "application/json;charset=utf-8",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      payload
    );

    console.log(
      `getResumen [${estado}] -> status: ${r.status}, body (primeros 400): ${r.body.substring(0, 400)}`
    );

    if (r.status === 200) {
      try {
        resultados[estado] = JSON.parse(r.body);
      } catch (e) {
        resultados[estado] = { error: "No se pudo parsear JSON", raw: r.body.substring(0, 500) };
      }
    } else {
      resultados[estado] = { error: `Status ${r.status}`, raw: r.body.substring(0, 500) };
    }
  }
  return resultados;
}

// ---------------------------------------------------------------------------
// Handler principal
//
// Modo 1 (por defecto) — Resumen de TODOS los proveedores de un período:
//   /.netlify/functions/sii-documentos?periodo=202506&operacion=COMPRA
//   (usa el RUT de tu propia empresa, tomado de la variable SII_RUT)
//
// Modo 2 — Detalle de UN proveedor específico ya conocido:
//   /.netlify/functions/sii-documentos?rutEmisor=76876772&dvEmisor=6&periodo=202506&detalle=1
// ---------------------------------------------------------------------------
export default withLambda(async (event, context) => {
  const headers = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };
  const params = event.queryStringParameters || {};

  try {
    // Preparamos el RUT propio (de la empresa, desde SII_RUT) sin puntos ni guión
    const rutSii = (process.env.SII_RUT || "").replace(/\./g, "");
    const [rutPropio, dvPropio] = rutSii.split("-");

    const periodo =
      params.periodo ||
      (() => {
        const d = new Date();
        return `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}`;
      })();
    const operacion = (params.operacion || "COMPRA").toUpperCase();

    // Modo 2: detalle de un proveedor puntual (usa el flujo semilla/token, ya probado)
    if (params.rutEmisor && params.dvEmisor && params.detalle) {
      const certData = cargarCertificado();
      const semilla = await obtenerSemilla();
      const xmlFirmado = firmarSemilla(semilla, certData);
      const token = await obtenerToken(xmlFirmado);
      const resultado = await getDetalleCompra(token, params.rutEmisor, params.dvEmisor, periodo);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, modo: "detalle", token, resultado }) };
    }

    // Modo 1 (por defecto): resumen de todos los proveedores del período, vía TLS mutuo
    cargarCertificado(); // valida que el certificado esté bien formado antes de usarlo en TLS
    const cookie = await loginConCertificadoTLS();
    console.log("Login TLS exitoso. Cookie:", cookie.nombre);

    const resumen = await getResumenRCV(cookie, rutPropio, dvPropio, periodo, operacion);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        ok: true,
        modo: "resumen",
        periodo,
        operacion,
        rutConsultado: `${rutPropio}-${dvPropio}`,
        resumen,
      }),
    };
  } catch (e) {
    console.error("Error:", e.message);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: e.message }) };
  }
});
