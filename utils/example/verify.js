$(function() {
    var onSuccess = function(data) {
        $("#result_status").html("Success!");
        var jwt = jwt_decode(data);
        var table = $("tbody");
        $.each(jwt.attributes, function(attrid, attrvalue) {
            var tr = $("<tr>").appendTo(table);
            tr.append($("<td>", { text: attrid }));
            tr.append($("<td>", { text: attrvalue }));
        });
        $("#token-content").text(JSON.stringify(jwt, null, 2));
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

        var attr = $("#attribute").val();
        var sprequest = {
            "request": {
                "content": [
                    {
                        "label": "IRMA attribute",
                        "attributes": [attr]
                    },
                ]
            }
        };
        var jwt = IRMA.createUnsignedVerificationJWT(sprequest);

        IRMA.verify(jwt, onSuccess, onCancel, onError);
    });
});
