var assert = require('assert'),
    _ = require('underscore'),
    tupascrypt = require('../lib/tupascrypt');


var testdata = {
    B02K_VERS: '0003',
    B02K_TIMESTMP: '50020141123184741267849',
    B02K_IDNBR: '2676202678',
    B02K_STAMP: '20141123064649123456',
    B02K_CUSTNAME: 'TESTI ANNA',
    B02K_KEYVERS: '0001',
    B02K_ALG: '03',
    B02K_CUSTID: '081181-9984',
    B02K_CUSTTYPE: '01',
    B02K_USERID: '',
    B02K_USERNAME: ''
};


var B02K_MAC = 'DFECBA49225E966ECB4885DA40D64CD74B76341712A2A68BDF80307EC6715B42'

var secret = "Esittelykauppiaansalainentunnus"
describe("checksum computation", function () {
    it('should compute correct mac', function () {
        var returnMac = tupascrypt.computeReturnMac(testdata, secret);
        assert.equal(B02K_MAC, returnMac);
    });
});


