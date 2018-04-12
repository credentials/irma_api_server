(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
"use strict";

function handleMessage(event) {
    var msg = event.data;
    console.log("Received message: ", msg);

    switch (msg.type) {
        case "tokenData":
            console.log("Got a QR code");
            $("#qrcode").empty().qrcode({
                text: JSON.stringify(msg.message),
                size: 230
            });
            $("#spinner").hide();
            $(".irma_option_container").show();
            break;
        case "clientConnected":
            showMessage("Please follow the instructions on your IRMA token");
            $(".irma_option_container").hide();
            break;
        case "done":
            break;
        default:
            failure("Received unknown message: \"" + msg + "\"");
            break;
    }
}

function sendMessage(data) {
    window.top.postMessage(data, "*");
    console.log("Sent message: " + JSON.stringify(data));
}

function failure() {
    console.log("ERROR: ", arguments);

    if (arguments.length > 0) {
        $(".irma_title").html("ERROR");
        showMessage("<b>Error: <b> " + arguments[0]);
        $("#irma_text").add_class("error");
    }
}

function showMessage(msg) {
    $("#irma_text").html(msg);
}

window.addEventListener("message", handleMessage, false);

sendMessage({
    type: "serverPageReady"
});

$(function () {
    $("#cancel_button").on("click", function () {
        sendMessage({
            type: "userCancelled"
        });
    });
});

console.log("Server module loaded");

},{}]},{},[1]);
