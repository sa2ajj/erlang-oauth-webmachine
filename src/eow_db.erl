-module(eow_db).

-export([
    consumer_lookup/1,
    request_token_new/1,
    request_token_lookup/2,
    access_token_new/1,
    access_token_lookup/1
]).

-define(USER, "joe").

consumer_lookup("key") ->
    {"key", "secret", hmac_sha1};
consumer_lookup(_) ->
    none.

request_token_new({"key", _, _}) ->
    {"requestkey", "requestsecret"};
request_token_new(_) ->
    none.

request_token_lookup({"key", _, _}, "requestkey") ->
    {"requestsecret", ?USER};
request_token_lookup(_, _) ->
    none.

access_token_new(?USER) ->
    {"accesskey", "accesssecret"};
access_token_new(_) ->
    none.

access_token_lookup("accesskey") ->
    {"accesssecret", ?USER};
access_token_lookup(_) ->
    none.
