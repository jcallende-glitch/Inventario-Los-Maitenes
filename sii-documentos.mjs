import { withLambda } from "@netlify/aws-lambda-compat";
import https from "https";
import forge from "node-forge";
import { SignedXml } from "xml-crypto";

// El certificado viene dividido en 2 variables de entorno por el límite de 5000
// caracteres de Netlify. Se reconstruye aquí uniendo ambas partes.
const CERT_B64 = `${process.env.SII_CERT_B64_1 || ""}${process.env.SII_CERT_B64_2 || ""}`;
const CERT_PASS = process.env.SII_CERT_PASS;

// ---------------------------------------------------------------------------
// 1. Cargar certificado digital (.pfx) y extraer llave privada + certificado
// ---------------------------------------------------------------------------
function cargarCertificado() {
  if (!CERT_B64 || !CERT_PASS) {
    throw new Error("Faltan variables SII_CERT_B64_1 / SII_CERT_B64_2 / SII_CERT_PASS");
  }

  const pfxDer = forge.util.decode64(CERT_B64);
  const p12Asn1 = forge.asn1.fromDer(pfxDer);
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

  const m = r.body.match(/<getSeedReturn[^>]*>([\s\S]*?)<\/getSeedReturn>/);
  if (!m) throw new Error("Respuesta inesperada de CrSeed: " + r.body.substring(0, 300));

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

  const m = r.body.match(/<getTokenReturn[^>]*>([\s\S]*?)<\/getTokenReturn>/);
  if (!m) throw new Error("Respuesta inesperada de GetTokenFromSeed: " + r.body.substring(0, 300));

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
// 5. (Experimental) Usar el Token para consultar DTE recibidos en www4.sii.cl
//    NOTA: esta parte no está tan documentada oficialmente como los pasos
//    1-4. Si no devuelve datos, revisar los logs de la función en Netlify.
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
        Accept: "application/json, text/html,*/*;q=0.8",
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

async function obtenerDTERecibidos(token, rutEmpresa) {
  const hoy = new Date();
  const docs = [];

  for (let i = 0; i < 3; i++) {
    const d = new Date(hoy.getFullYear(), hoy.getMonth() - i, 1);
    const periodo = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}`;
    const url = `https://www4.sii.cl/consdcvinternetui/services/data/facturacion/listadoDTE?rutEmpresa=${rutEmpresa}&periodo=${periodo}&tipo=COMPRAS`;

    try {
      const r = await req(url, {
        headers: {
          Cookie: `TOKEN=${token}`,
          "X-Requested-With": "XMLHttpRequest",
          Referer: "https://www4.sii.cl/consdcvinternetui/index.html",
        },
      });
      console.log(`DTE ${periodo}: status ${r.status} — ${r.body.substring(0, 200)}`);

      if (r.status === 200) {
        try {
          const data = JSON.parse(r.body);
          const lista = data.data || data.listado || data.documentos || data || [];
          if (Array.isArray(lista)) lista.forEach((x) => docs.push({ ...x, periodo }));
        } catch (e) {
          console.log("No se pudo parsear JSON:", e.message);
        }
      }
    } catch (e) {
      console.log(`Error consultando ${periodo}:`, e.message);
    }
  }

  return docs;
}

// ---------------------------------------------------------------------------
// Handler principal
// ---------------------------------------------------------------------------
export default withLambda(async (event, context) => {
  const headers = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };

  try {
    const certData = cargarCertificado();

    const semilla = await obtenerSemilla();
    console.log("Semilla obtenida:", semilla);

    const xmlFirmado = firmarSemilla(semilla, certData);
    const token = await obtenerToken(xmlFirmado);
    console.log("Token obtenido:", token);

    const rutEmpresa = (process.env.SII_RUT || "").replace(/\./g, "").replace("-", "");
    const docs = await obtenerDTERecibidos(token, rutEmpresa);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        ok: true,
        token, // útil para depurar en los logs; quitar si se prefiere no exponerlo
        total: docs.length,
        documentos: docs,
      }),
    };
  } catch (e) {
    console.error("Error:", e.message);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: e.message }) };
  }
});
