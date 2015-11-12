var qrcode = require('qrcode-terminal');
var request = require('request');

var sprequest = {
	"data": "foobar",
	"request": {
		"content": [
			{
				"label": "over12",
				"attributes": ["MijnOverheid.ageLower.over12"]
			},
			{
				"label": "over16",
				"attributes": ["MijnOverheid.ageLower.over16"]
			}
		]
	}
};


var server = process.argv[2] + "/irma_verification_server/api/v1/";

var options = {
	uri: server + 'create',
	method: 'POST',
	json: sprequest
};

var result = null;

function poll(token) {
	var pollOptions = {
		uri: server + token + "/getproof",
		method: 'GET'
	};

	request(pollOptions, function (error, response, body) {
		process.stdout.write(".");
		var json = JSON.parse(body);
		if (json.status != "WAITING") {
			result = json;
		}
	});
}

request(options, function (error, response, body) {
	if (!error && response.statusCode == 200) {
		var url = server + body;

		var qrcontent = JSON.stringify({"v":"1.0", "u": url});
		console.log(qrcontent);
		qrcode.generate(qrcontent);

		var check = function() {
			if (result == null) {
				poll(body);
				setTimeout(check, 1000);
			} else {
				console.log();
				console.log(result);
			}
		};

		check();
	} else {
		console.log(error);
	}
});

