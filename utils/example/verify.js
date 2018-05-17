$(function() {
    var sprequest = {
        "request": {
            "content": [
                {
                    "label": "Over 18",
                    "attributes": ["pbdf.pbdf.ageLimits.over18"]
                },
            ]
        }
    };

    var onSuccess = function(data) {
        $("#result_status").html("Success!");
        $("#token-content").text(JSON.stringify(jwt_decode(data), null, 2));
    }

    var onCancel = function(data) {
        $("#result_status").html("Cancelled!");
    }
    
    var onError = function(data) {
        $("#result_status").html("Failure!");
        console.log("Error data:", data);
    }

    $("#try_irma_btn").click(function() {
        var ip = $("#ip").val();
        if (!ip.startsWith("http://") && !ip.startsWith("https://"))
            ip = "http://" + ip;
        if (!ip.endsWith("/"))
            ip = ip + "/";
        IRMA.init(ip + "api/v2/", ip + "server/");
        var jwt = IRMA.createUnsignedVerificationJWT(sprequest);
        IRMA.verify(jwt, onSuccess, onCancel, onError);
    });
});
