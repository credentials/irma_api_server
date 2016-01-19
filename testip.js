var qrcode = require('qrcode-terminal');
var request = require('request');

var iprequest = {
    data: "foobar",
    timeout: 60,
    request: {
        "credentials": [
            {
                "credential": "MijnOverheid.ageLower",
                "validity": 6,
                "attributes": {
                    "over12": "yes",
                    "over16": "yes",
                    "over18": "yes",
                    "over21": "no"
                }
            },
            {
                "credential": "MijnOverheid.address",
                "validity": 6,
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
    json: iprequest
};

request(options, function (error, response, body) {
    if (!error && response.statusCode == 200) {
        var qrcontent = body;
        var session = body.u;
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