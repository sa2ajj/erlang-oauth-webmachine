-module(eow_db).

-export([
    consumer_lookup/1,
    request_secret_lookup/1,
    access_secret_lookup/1,
    new_request_token/0
]).

consumer_lookup("key") ->
    {"key", "secret", hmac_sha1};
consumer_lookup(_) ->
    none.

request_secret_lookup("requestkey") ->
    "requestsecret";
request_secret_lookup(_) ->
    none.

access_secret_lookup("accesskey") ->
    {"accesssecret", "joe"};
access_secret_lookup(_) ->
    none.

new_request_token() ->
    {"requestkey", "requestsecret"}.
