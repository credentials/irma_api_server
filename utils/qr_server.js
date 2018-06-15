const qrcode = require('qrcode-terminal');
const request = require('request');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const http = require('http');
const url = require('url');

// Get a timestamp for a year of validity, but floored to weeks, required by the API server
const boundedTimestamp = () => {
  const epochSeconds = Math.floor((new Date).getTime() / 1000) + (60 * 60 * 24 * 365);
  return epochSeconds - (epochSeconds % (60 * 60 * 24 * 7));
};

const iprequest = {
    data: 'foobar',
    timeout: 60,
    request: {
        'credentials': [
            {
                'credential': 'irma-demo.MijnOverheid.ageLower',
                'validity': boundedTimestamp(),
                'attributes': {
                    'over12': 'yes',
                    'over16': 'yes',
                    'over18': 'yes',
                    'over21': 'no'
                }
            },
            {
                'credential': 'irma-demo.MijnOverheid.address',
                'validity': boundedTimestamp(),
                'attributes': {
                    'country': 'The Netherlands',
                    'city': 'Nijmegen',
                    'street': 'Toernooiveld 212',
                    'zipcode': '6525 EC'
                }
            }
        ],

        // 'disclose': [
        //     {
        //         'label': 'Over 18',
        //         'attributes': ['irma-demo.MijnOverheid.ageLower.over18', 'irma-demo.MijnOverheid.ageLower.over21']
        //     }
        // ]
    }
};

const sprequest = {
    "validity": 60,
    "timeout": 60,
    "request": {
        "content": [
            {
                "label": "Over 18",
                "attributes": ["irma-demo.MijnOverheid.ageLower.over18", "irma-demo.MijnOverheid.ageLower.over21"]
            },
        ]
    }
};

var sigrequest = {
    "data": "foobar",
    "validity": 60,
    "timeout": 60,
    "request": {
        "message" : "Message to be signed",
        "messageType" : "STRING",
        "content": [
            // {
            //     "label": "Name",
            //     "attributes": {"irma-demo.MijnOverheid.fullName.firstname": "Johan" }
            // },
            {
                "label": "Over 21",
                "attributes": ["irma-demo.MijnOverheid.ageLower.over18", "irma-demo.MijnOverheid.ageLower.over21"]
            }
        ]
    }
};

const serverUri = 'https://demo.irmacard.org/tomcat';
const apiUri = serverUri + '/irma_api_server/api/v2';

function checkStatus(url, doneCallback) {
    const checkOptions = {
        uri: url + '/status',
        method: 'GET'
    };

    request(checkOptions, (error, response, body) => {
        if (error != null) {
            console.log();
            doneCallback(error);
        }
        else if ( !(body == '"INITIALIZED"' || body == '"CONNECTED"') ) {
            console.log();
            doneCallback(body);
        } else {
            process.stdout.write(".");
            setTimeout(() => {checkStatus(url, doneCallback)}, 1000);
        }
    });
}

function getProof(url) {
    var proofOptions = {
        uri: url + "/getproof",
        method: 'GET'
    };

    request(proofOptions, (error, response, body) => {
        if (error != null) {
            console.log(response);
            console.log(error);
        } else {
            console.log(jwt.decode(body));
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
            qrcontent.u = endpointUri + '/' + token;
            qrCallback(JSON.stringify(qrcontent));

            const delayedReportStatus = () => {
                checkStatus(qrcontent.u, (status) => {
                    console.log('Status report for token', token + ':', status);    
                    if (status === "\"DONE\"" && jwtOptions.subject != 'issue_request')
                        getProof(qrcontent.u);
                });
            }

            setTimeout(delayedReportStatus, 500);
        } else {
            console.log('Error in initial request: ', error);
            console.log(body);
        }
    });
}

function setupIssuanceSession(qrCallback) {
    const endpointUri = apiUri + '/issue';
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
    const endpointUri = apiUri + '/verification';
    const jwtMessage = {sprequest};
    const jwtOptions = {
        algorithm: 'none',
        issuer: 'testsp',
        subject: 'verification_request'
    };

    setupSession(endpointUri, jwtMessage, jwtOptions, qrCallback);
}

function setupSigningSession(qrCallback) {
    const endpointUri = apiUri + '/signature';
    const jwtMessage = {absrequest: sigrequest}
    var jwtOptions = {
        algorithm: "none",
        issuer: "testsigclient",
        subject: "signature_request"
    };

    setupSession(endpointUri, jwtMessage, jwtOptions, qrCallback);
}

const server = http.createServer( (req, res) => {
    var query = url.parse(req.url, true).query;
    console.log('Got request for type', query.type);

    let fn;
    switch(query.type) {
        case 'issuance':
            fn = setupIssuanceSession; break;
        case 'disclosure':
            fn = setupDisclosureSession; break;
        case 'signing':
            fn = setupSigningSession; break;

        default:
            console.log('Unrecognized session type');

            res.statusCode = 400;
            res.end();
            return;
    }
    
    fn( qrJSON => {
        console.log('Served up QR:', qrJSON)

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(qrJSON);
    });
});

server.listen('7000', '127.0.0.1', () => {
  console.log('Server running...');
});
