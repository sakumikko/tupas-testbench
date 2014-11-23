var express = require('express'),
    router = express.Router(),
    tupascrypt = require('../lib/tupascrypt'),
    querystring = require('querystring');


/*
 <FORM METHOD=”POST” ACTION=”pankin Tupas-palvelun URL”>
 <INPUT NAME=”A01Y_ACTION_ID” TYPE=”hidden” VALUE=”701”>
 <INPUT NAME=”A01Y_VERS” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_RCVID” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_LANGCODE” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_STAMP” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_IDTYPE” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_RETLINK” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_CANLINK” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_REJLINK” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_KEYVERS” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_ALG” TYPE="hidden” VALUE=”...”>
 <INPUT NAME=”A01Y_MAC” TYPE="hidden” VALUE=”...”>
 </FORM>

 FORM-TIETORYHMÄ
 Kenttä Tiedon nimi Pituus Huomautus
 1. Sanomatyyppi A01Y_ACTION_ID 3 - 4 Vakio, "701"
 2. Versio A01Y_VERS 4 Esim. "0002"
 3. Palveluntarjoaja A01Y_RCVID 10 -15 Asiakastunnus
 4. Palvelun kieli A01Y_LANGCODE 2 ISO 639:n mukainen tunnus:
 FI = Suomi
 SV = Ruotsi
 EN = Englanti
 5. Pyynnön yksilöinti A01Y_STAMP 20 Vvvvkkpphhmmssxxxxxx
 6. Yksilöintitiedon tyyppi A01Y_IDTYPE 2 ks. liite 1
 7. Paluuosoite A01Y_RETLINK 199 OK paluuosoite tunnisteelle
 8. Peruuta-osoite A01Y_CANLINK 199 Paluuosoite peruutuksessa
 9. Hylätty-osoite A01Y_REJLINK 199 Paluuosoite virhetilanteessa
 10. Avainversio A01Y_KEYVERS 4 Avaimen sukupolvitieto
 11. Algoritmi A01Y_ALG 2 01 = MD5
 02 = SHA-1
 03 = SHA-256
 12. Tarkiste A01Y_MAC 32 - 40 Pyynnön turvatarkiste
 */


router.post("/identify", function (req, res) {

    if (req.body.A01Y_MAC != tupascrypt.computeReqMac(req.body)) {
        res.render('macfailed', {title: 'Mac mismatch'});
    } else {
        console.log(req.body.A01Y_MAC);
        console.log(tupascrypt.computeReqMac(req.body));
        res.render('identify', {
            title: 'Fake tupas',
            tupas: {
                returnUri: req.body.A01Y_RETLINK,
                cancelUri: req.body.A01Y_CANLINK,
                rejectUri: req.body.A01Y_REJLINK,
                stamp: req.body.A01Y_STAMP
            }
        });
    }
});

router.post("/verify", function (req, res) {

    var returnParams = tupascrypt.computeReturnParams(req.body.ssn, req.body.cn, req.body.stamp)
    var queryParams = querystring.stringify(returnParams);
    res.redirect(req.body.returnUri + '?' + queryParams);

});


module.exports = router;