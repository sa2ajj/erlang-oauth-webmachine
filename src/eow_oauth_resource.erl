-module(eow_oauth_resource).

-export([
    init/1,
    malformed_request/2,
    is_authorized/2,
    % forbidden/2,
    allowed_methods/2,
    content_types_provided/2,
    to_text/2
]).

-include_lib("webmachine/include/webmachine.hrl").

-record(state, {
    kind,
    params,
    user
}).

-define(REALM, "http://localhost:8000").
-define(TEXT_MT, "text/plain").
-define(HMAC_SHA1, "HMAC-SHA1").

init([Kind]) ->
    {ok, #state{kind=Kind}}.

allowed_methods(ReqData, State) ->
    {if
        State#state.kind == 'authorize' ->
            ['GET', 'POST'];

        true ->
            ['GET']
    end, ReqData, State}.

malformed_request(ReqData, #state{kind=authorize}=State) ->
    {false, ReqData, State};
malformed_request(ReqData, State) ->
    Params = case wrq:get_req_header("authorization", ReqData) of
        undefined ->
            wrq:req_qs(ReqData);

        Value ->
            % values in qs take precedence over what's supplied in
            % Authorization header
            lists:keymerge(1, lists:keysort(1, wrq:req_qs(ReqData)),
                          lists:keysort(1, auth_to_proplist(Value)))
    end,
    case check_params(Params) of
        ok ->
            {false, ReqData, State#state{params=Params}};

        _ ->
            {true, ReqData, State}
    end.

is_authorized(ReqData, #state{kind=authorize}=State) ->
    % put site specific authorization here
    {true, ReqData, State};
is_authorized(ReqData, #state{kind=Kind, params=Params}=State) ->
    Result = case Params of
        [] ->
            false;

        _ ->
            verify(Kind, Params, ReqData)
    end,
    case Result of
        {true, User} ->
            {true, ReqData, State#state{user=User}};

        true ->
            {true, ReqData, State};

        _ ->
            {"OAuth realm=\"" ?REALM "\"", ReqData, State}
    end.

content_types_provided(ReqData, State) ->
    Types = [
        {?TEXT_MT, to_text}
    ],
    {Types, ReqData, State}.

to_text(ReqData, #state{kind=request_token}=State) ->
    {"oauth_token=requestkey&oauth_token_secret=requestsecret", ReqData, State};
to_text(ReqData, #state{kind=access_token}=State) ->
    {"oauth_token=accesskey&oauth_token_secret=accesssecret", ReqData, State};
to_text(ReqData, #state{kind=authorize}=State) ->
    {"AUTH", ReqData, State}.

% helpers
auth_to_proplist("OAuth " ++ Rest) ->
    auth_to_proplist(lists:map(fun string:strip/1, string:tokens(Rest, ",")), []).

auth_to_proplist([Value | Rest], Acc) ->
    case Value of
        "oauth_" ++ _ ->
            [Name, Value] = string:tokens(Value, "="),
            auth_to_proplist(Rest, [{Name, string:strip(Value, both, $")} | Acc]);

        "realm=" ++ _ ->
            auth_to_proplist(Rest, Acc)
    end;
auth_to_proplist([], Acc) ->
    Acc.

check_params([]) ->
    ok;
check_params(Params) ->
    check_params(missing, Params).

check_params(missing, Params) ->
    case check_required_params(Params) of
        ok ->
            check_params(signature, Params);

        _ ->
            nok
    end;
check_params(signature, Params) ->
    case lists:keyfind("oauth_signature_method", 1, Params) of
        {_, ?HMAC_SHA1} ->
            check_params(done, Params);

        _ ->
            nok
    end;
check_params(done, _) ->
    ok.

required_params() ->
    [
        "oauth_consumer_key",
        "oauth_signature_method",
        "oauth_signature",
        "oauth_timestamp",
        "oauth_nonce"
    ].

check_required_params(Params) ->
    check_required_params(Params, required_params()).

check_required_params([], [_ | _]) ->
    nok;
check_required_params(Params, [Key | Rest]) ->
    case lists:keytake(Key, 1, Params) of
        {value, _, NewParams} ->
            check_required_params(NewParams, Rest);

        false ->
            nok
    end;
check_required_params(_, []) ->
    ok.

verify(Kind, Params, ReqData) ->
    {value, {_, Signature}, OtherParams} = lists:keytake("oauth_signature", 1, Params),
    {_, ConsumerKey} = lists:keyfind("oauth_consumer_key", 1, OtherParams),
    URL = string:concat(?REALM, wrq:path(ReqData)),
    io:format("verify: ~p ~s~n", [wrq:method(ReqData), URL]),
    case consumer_lookup(ConsumerKey) of
        none ->
            false;

        Consumer ->
            Result = verify(Kind, atom_to_list(wrq:method(ReqData)), URL, Consumer, Signature, OtherParams),
            io:format("verify result: ~p~n", [Result]),
            Result
    end.

verify(request_token, Method, URL, Consumer, Signature, Params) ->
    io:format("verify(request_token): ~p~n", [[Method, URL, Consumer, Signature, Params]]),
    oauth:verify(Signature, Method, URL, Params, Consumer, "");
verify(access_token, Method, URL, Consumer, Signature, Params) ->
    io:format("verify(access_token): ~p~n", [[Method, URL, Consumer, Signature, Params]]),
    case request_secret_lookup(oauth:token(Params)) of
        none ->
            false;

        Secret ->
            oauth:verify(Signature, Method, URL, Params, Consumer, Secret)
    end;
verify(access, Method, URL, Consumer, Signature, Params) ->
    io:format("verify(access): ~p~n", [[Method, URL, Consumer, Signature, Params]]),
    case access_secret_lookup(oauth:token(Params)) of
        none ->
            false;

        {Secret, User} ->
            {oauth:verify(Signature, Method, URL, Params, Consumer, Secret), User}
    end;
verify(Kind, _, _, _, _, _) ->
    io:format("verify(~p):~n", [Kind]),
    false.

-ifdef(YES).
set_resp(ReqData, ContentType, Body) ->
    wrq:set_resp_header("content-type", ContentType, wrq:set_resp_body(Body, ReqData)).
-endif.

% To be done with a database
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
