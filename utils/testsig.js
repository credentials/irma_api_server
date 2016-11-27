var qrcode = require('qrcode-terminal');
var request = require('request');
var jwt = require('jsonwebtoken');
var fs = require('fs');

var sigrequest = {
	"data": "foobar",
	"validity": 60,
	"timeout": 60,
	"request": {
		"message" : "Message to be signed",
		"messageType" : "STRING",
		"content": [
			{
				"label": "Name",
				"attributes": {"irma-demo.MijnOverheid.fullName.firstname": "Johan" }
			},
			{
				"label": "Over 21",
				"attributes": ["irma-demo.MijnOverheid.ageLower.over18", "irma-demo.MijnOverheid.ageLower.over21"]
			}
		]
	}
};

var jwtOptions = {
	algorithm: "none",
	issuer: "testsigclient",
	subject: "signature_request"
};
var token = jwt.sign({absrequest: sigrequest}, null, jwtOptions);
var confpath = process.argv[3] != null ? process.argv[3] : 'src/main/resources';
var publickey = fs.readFileSync(confpath + '/pk.pem');

var server = process.argv[2] + "/irma_api_server/api/v2/signature/";
var options = {
	uri: server,
	method: 'POST',
	body: token
};

console.log(options);

var result = null;
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
		uri: server + token + "/getsignature",
		method: 'GET'
	};

	request(pollOptions, function (error, response, body) {
		process.stdout.write(".");

		try {
			var r = jwt.verify(body, publickey, {algorithms: ["RS256"]});
			if (r.status != "WAITING") {
				result = r;
				console.log();
				console.log(r);

				if (r.status != "VALID") {
					throw "Proof was invalid";
				}

				// Base64-decode the middle part of the JWT
				var sigresult = new Buffer(body.split('.')[1], 'base64').toString('ascii');
				var checkoptions = {
					uri: server + "checksignature",
					method: 'POST',
					headers: {'Content-Type': 'application/json'},
					body: sigresult
				};
				request(checkoptions, function (err2, response2, body2) {
					if (err2 || response2.statusCode != 200) {
						console.log("\nError in signature verification: " + response2.statusCode);
						console.log(err2)
					}
				});
			}
		} catch(err) {
			result = 1;
			console.log("\nDid not receive a valid token (error: \"" + err.toString() + "\")");
			console.log("Data: " + String(body));
		}
	});
}
