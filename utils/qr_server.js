const qrcode = require('qrcode-terminal');
const request = require('request');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const http = require('http');

const iprequest = {
    data: 'foobar',
    timeout: 60,
    request: {
        'credentials': [
            {
                'credential': 'irma-demo.MijnOverheid.ageLower',
                'validity': 1582969600,
                'attributes': {
                    'over12': 'yes',
                    'over16': 'yes',
                    'over18': 'yes',
                    'over21': 'no'
                }
            },
            {
                'credential': 'irma-demo.MijnOverheid.address',
                'validity': 1582969600,
                'attributes': {
                    'country': 'The Netherlands',
                    'city': 'Nijmegen',
                    'street': 'Toernooiveld 212',
                    'zipcode': '6525 EC'
                }
            }
        ]
    }
};

const sprequest = {
    "validity": 60,
    "timeout": 60,
    "request": {
        "content": [
            {
                "label": "Over 21",
                "attributes": ["irma-demo.MijnOverheid.ageLower.over18", "irma-demo.MijnOverheid.ageLower.over21"]
            }
        ]
    }
};

// const serverUri = process.argv[2] + "/irma_api_server/api/v2/issue/";

const serverUri = 'https://demo.irmacard.org/tomcat';

function checkStatus(token, doneCallback) {
    const checkOptions = {
        uri: serverUri + token + '/status',
        method: 'GET'
    };

    request(checkOptions, (error, response, body) => {
        if ( !(body == '"INITIALIZED"' || body == '"CONNECTED"') ) {
            doneCallback(body);
        } else {
            // process.stdout.write(".");
        }
    });
}

function setupSession(endpointUri, jwtMessage, jwtOptions, qrCallback) {
    const token = jwt.sign(jwtMessage, null, jwtOptions);

    const requestOptions = {
        uri: endpointUri,
        method: 'POST',
        body: token
    };

    request(requestOptions, (error, response, body) => {
        if (!error && response.statusCode == 200) {
            const qrcontent = JSON.parse(body);
            const token = qrcontent.u;
            
            qrcontent.u = endpointUri + token;
            qrCallback(JSON.stringify(qrcontent));

            const delayedReportStatus = () => {
                checkStatus(token, () => {
                    console.log('Status report for token', token + ':', status);    
                });
            }

            // Don't check for status for now
            // setTimeout(delayedReportStatus, 30000);
        } else {
            console.log('Error in initial request: ', error);
            console.log(body);
        }
    });
}

function setupIssuanceSession(qrCallback) {
    const endpointUri = serverUri + '/irma_api_server/api/v2/issue/';
    console.log(endpointUri);
    const jwtMessage = {iprequest};
    const jwtOptions = {
        algorithm: 'none',
        issuer: 'testip',
        subject: 'issue_request'
    };

    setupSession(endpointUri, jwtMessage, jwtOptions, qrCallback);
}

function setupDisclosureSession(qrCallback) {
    const endpointUri = serverUri + '/irma_api_server/api/v2/verification/';
    const jwtMessage = {sprequest};
    const jwtOptions = {
        algorithm: 'none',
        issuer: 'testsp',
        subject: 'verification_request'
    };

    setupSession(endpointUri, jwtMessage, jwtOptions, qrCallback);
}

const server = http.createServer( (req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');

    console.log('Got request')
    setupDisclosureSession( qrJSON => {
        console.log('Served up QR:', qrJSON)
        res.end(qrJSON);
    });
});

server.listen('7000', '127.0.0.1', () => {
  console.log('Server running...');
});
