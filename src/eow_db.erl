-module(eow_db).

-export([
    consumer_lookup/1,
    request_secret_lookup/2,
    access_secret_lookup/1,
    new_request_token/1,
    new_access_token/1
]).

-define(USER, "joe").

consumer_lookup("key") ->
    {"key", "secret", hmac_sha1};
consumer_lookup(_) ->
    none.

request_secret_lookup({"key", _, _}, "requestkey") ->
    {"requestsecret", ?USER};
request_secret_lookup(_, _) ->
    none.

access_secret_lookup("accesskey") ->
    {"accesssecret", ?USER};
access_secret_lookup(_) ->
    none.

new_request_token({"key", _, _}) ->
    {"requestkey", "requestsecret"};
new_request_token(_) ->
    none.

new_access_token(?USER) ->
    {"accesskey", "accesssecret"};
new_access_token(_) ->
    none.
