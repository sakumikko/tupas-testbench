var crypto = require('crypto'),
    config = require('./tupasconfig')
    moment = require('moment');


/*
 Vastaussanoma eli Tupas-tunniste ja sen yksilöintitiedot
 1. Versio 	B02K_VERS 	4	P 	Esim. "0002"
 2. Tunnisteen yksilöinti 	B02K_TIMESTMP 	23	P 	NNNvvvvkkpphhmmssxxxxx x
 3. Tunnisteen numero 	B02K_IDNBR 	10	P 	Pankin tunnisteelle antama numero
 4. Pyynnön yksilöinti 	B02K_STAMP 	20	P 	Kyselyn tietokenttä 7 ( A01Y_STAMP)
 5. Asiakas 	B02K_CUSTNAME 	–40 	P 	Pankin tietokannassa oleva tunnistetun henkilön tai yri- tyksen nimi
 6. Avainversio 	B02K_KEYVERS 	4	P 	Avaimen sukupolvi
 7. Algoritmi 	B02K_ALG 	2	P 	01 = MD5 02 = SHA-1 03 = SHA-256
 8. Yksilöintitieto 	B02K_CUSTID 	-40	P 	ks. liite 2
 9. Yksilöintitiedon tyyppi 	B02K_CUSTTYPE 	2	P 	ks. liite 2
 10. Käyttäjän tunnus 	B02K_USERID 	-40	V 	Yrityskäyttäjän henkilötunnus tai salattu tunnus , ks. liite 2
 11. Käyttäjän nimi 	B02K_USERNAME 	-40	V 	Yrityskäyttäjän nimi ks. liite 2
 12. Tarkiste 	B02K_MAC 	32 - 40 	P 	Vastauksen turvatarkiste
 */


function computeReturnParams(ssn, cn, stamp) {
    var params = {
        B02K_VERS: config.version,
        B02K_TIMESTMP: config.bankNumber + moment().format('YYYYMMDDhhmmss') + '000000',
        B02K_IDNBR: '1234567890',
        B02K_STAMP: stamp,
        B02K_CUSTNAME: cn,
        B02K_KEYVERS: config.keyVersion,
        B02K_ALG: '03', // SHA-256
        B02K_CUSTID: ssn,
        B02K_CUSTTYPE: '01' // 01 = selväkielinen henkilötunnus
    }

    params.B02K_MAC = computeReturnMac(params, config.checksumKey);

    return params;
}

function computeMac(macBase){
    return crypto
        .createHash('sha256')
        .update(macBase)
        .digest('hex')
        .toUpperCase();
}

function computeReturnMac(params, secretKey) {
    return computeMac(respParamsToMacBase(params, secretKey));

};

function computeReqMac(reqBody){
    return computeMac(reqParamsToMacBase(reqBody, config.checksumKey));
}


function respParamsToMacBase(params, secretKey) {
    return [
            params.B02K_VERS,
            params.B02K_TIMESTMP,
            params.B02K_IDNBR,
            params.B02K_STAMP,
            params.B02K_CUSTNAME,
            params.B02K_KEYVERS,
            params.B02K_ALG,
            params.B02K_CUSTID,
            params.B02K_CUSTTYPE,
            secretKey
        ].join("&") + "&";
};


function reqParamsToMacBase(params, secretKey){
  return [
      params.A01Y_ACTION_ID,
      params.A01Y_VERS,
      params.A01Y_RCVID,
      params.A01Y_LANGCODE,
      params.A01Y_STAMP,
      params.A01Y_IDTYPE,
      params.A01Y_RETLINK,
      params.A01Y_CANLINK,
      params.A01Y_REJLINK,
      params.A01Y_KEYVERS,
      params.A01Y_ALG,
      secretKey
  ].join("&") + "&";

};


module.exports = {
    computeReturnParams: computeReturnParams,
    computeReturnMac: computeReturnMac,
    computeReqMac: computeReqMac
}