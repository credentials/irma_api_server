var qrcode = require('qrcode-terminal');
var request = require('request');
var jwt = require("jsonwebtoken");
var fs = require('fs');

var iprequest = {
    data: "foobar",
    timeout: 60,
    request: {
        "credentials": [
            {
                "credential": "MijnOverheid.ageLower",
                "validity": 1483228800,
                "attributes": {
                    "over12": "yes",
                    "over16": "yes",
                    "over18": "yes",
                    "over21": "no"
                }
            },
            {
                "credential": "MijnOverheid.address",
                "validity": 1483228800,
                "attributes": {
                    "country": "The Netherlands",
                    "city": "Nijmegen",
                    "street": "Toernooiveld 212",
                    "zipcode": "6525 EC"
                }
            }
        ],
        "disclose": [
            {
                "label": "Age (higher)",
                "attributes": {
                    "MijnOverheid.ageHigher": "present"
                }
            }
        ]
    }
};

var jwtOptions = {
    algorithm: "RS256",
    issuer: "testip",
    subject: "issue_request"
};

var token = jwt.sign({iprequest: iprequest}, fs.readFileSync('testip.pem'), jwtOptions);
var server = process.argv[2] + "/irma_api_server/api/v2/issue/";
var result = null;

function poll(token) {
    var pollOptions = {
        uri: server + token + "/getstatus",
        method: 'GET'
    };

    request(pollOptions, function (error, response, body) {
        if (body == "INITIALIZED" || body == "CONNECTED")
            process.stdout.write(".");
        else {
            console.log();
            console.log(body);
            result = body;
        }
    });
}

var options = {
    uri: server,
    method: 'POST',
    body: token
};

request(options, function (error, response, body) {
    if (!error && response.statusCode == 200) {
        var qrcontent = JSON.parse(body);
        var session = qrcontent.u;
        qrcontent.u = server + qrcontent.u;

        console.log(qrcontent);
        qrcode.generate(JSON.stringify(qrcontent));

        var check = function() {
            if (result == null) {
                poll(session);
                setTimeout(check, 1000);
            }
        };

        check();
    } else {
        console.log("Error in initial request: ", error);
        console.log(body);
    }
});