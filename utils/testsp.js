var qrcode = require('qrcode-terminal');
var request = require('request');
var jwt = require('jsonwebtoken');
var fs = require('fs');

var sprequest = {
	"data": "foobar",
	"validity": 60,
	"timeout": 60,
	"request": {
		"content": [
			{
				"label": "Name",
				"attributes": ["irma-demo.MijnOverheid.fullName.firstname"]
			},
			{
				"label": "Over 21",
				"attributes": ["irma-demo.MijnOverheid.ageLower.over18", "irma-demo.MijnOverheid.ageLower.over21"]
			}
		]
	}
};

var jwtOptions = {
	algorithm: "RS256",
	issuer: "testsp",
	subject: "verification_request"
};

var keyfile = "src/main/resources/issuers/testip-sk.pem";
var token = jwt.sign({sprequest: sprequest}, fs.readFileSync(keyfile), jwtOptions);
var server = process.argv[2] + "/irma_api_server/api/v2/verification/";
var publickey = fs.readFileSync('src/main/resources/pk.pem');
var result = null;

var options = {
	uri: server,
	method: 'POST',
	json: sprequest
	//body: token
};

request(options, function (error, response, body) {
	if (!error && response.statusCode == 200) {
		var qrcontent;

		// The request library calls JSON.parse() on the body only if the POST body
		// also was json - if not, we have to do this manually.
		if (Object.prototype.toString.call(body) == '[object String]')
			qrcontent = JSON.parse(body);
		else
			qrcontent = body;
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
		console.log("Error in initial request:");
		console.log(body);
	}
});


function poll(token) {
	var pollOptions = {
		uri: server + token + "/getproof",
		method: 'GET'
	};

	request(pollOptions, function (error, response, body) {
		process.stdout.write(".");

		try {
			var payload = jwt.verify(body, publickey, {algorithms: ["RS256"]});
			if (payload.status != "WAITING") {
				result = payload;
				console.log();
				console.log(body);
				console.log();
				console.log(result);

				if (payload.status != "VALID")
					throw "Proof was invalid";
				if (payload.sub != "disclosure_result")
					throw "Invalid subject";
			}
		} catch(err) {
			result = 1;
			console.log("\nDid not receive a valid token (error: \"" + err.toString() + "\")");
			console.log("Data: " + String(body));
		}
	});
}

