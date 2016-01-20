var qrcode = require('qrcode-terminal');
var request = require('request');
var jwt = require('jsonwebtoken');
var fs = require('fs');

var sprequest = {
	"data": "foobar",
	"validity": 60,
	"request": {
		"content": [
			//{
			//	"label": "Email",
			//	"attributes": ["IRMAWiki.member.email", "Surfnet.root.userID"]
			//},
			{
				"label": "Name",
				"attributes": ["MijnOverheid.fullName.firstname", "IRMAWiki.member.realname"]
			},
			{
				"label": "Over 18",
				"attributes": ["MijnOverheid.ageLower.over18", "MijnOverheid.ageLower.over9000"]
			},
			//{
			//	"label": "Foo",
			//	"attributes": ["MijnOverheid.foobar.baz"]
			//},
			//{
			//	"label": "Bar",
			//	"attributes": ["MijnOverheid.barfoo.baz"]
			//},
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

