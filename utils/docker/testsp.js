const qrcode = require('qrcode-terminal');
const request = require('request');
const jwt = require('jsonwebtoken');
const fs = require('fs');

if (process.argv.length !== 3) {
  console.log('Usage: npm testip http://irma_api_ip:port\n\n');
  console.log('IP can be found using \'docker inspect IMAGE\'');
  console.log('Make sure the file irma_api_key.pem is present in this directory, containing the correct IRMA api key');
  process.exit(1);
}

const sprequest = {
	"validity": 60,
	"timeout": 60,
	"request": {
		"content": [
			{
				"label": "Initials",
				"attributes": ["pbdf.pbdf.idin.initials"]
			}
		]
	}
};

const jwtOptions = {
	algorithm: "none",
	issuer: "testsp",
	subject: "verification_request"
};

const server = process.argv[2] + "/api/v2/verification/";
const token = jwt.sign({sprequest: sprequest}, null, jwtOptions);
let result = null;

const options = {
	uri: server,
	method: 'POST',
	body: token
};

const publickey = fs.readFileSync('irma_api_key.pem');

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
    console.log(error);
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
