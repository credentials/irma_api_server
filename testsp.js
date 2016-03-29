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
				"attributes": ["irma-demo.MijnOverheid.fullName.firstname", "irma-demo.IRMAWiki.member.realname"]
			},
			{
				"label": "Over 18",
				"attributes": ["irma-demo.MijnOverheid.ageLower.over18", "irma-demo.MijnOverheid.ageLower.nonexisting"]
			}
		]
	}
};

var server = process.argv[2] + "/irma_api_server/api/v2/verification/";
var publickey = fs.readFileSync('src/main/resources/pk.pem');
var result = null;

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

var options = {
	uri: server,
	method: 'POST',
	json: sprequest
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
		console.log("Error in initial request:");
		console.log(body);
	}
});

