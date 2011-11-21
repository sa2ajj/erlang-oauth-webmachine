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
    consumer,
    user
}).

-define(REALM, "http://localhost:8000").
-define(TEXT_MT, "text/plain").
-define(HMAC_SHA1, "HMAC-SHA1").

init([Kind]) ->
    {ok, #state{kind=Kind}}.

allowed_methods(ReqData, #state{kind=authorize}=State) ->
    {['POST'], ReqData, State};
allowed_methods(ReqData, State) ->
    {['GET'], ReqData, State}.

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
    % put site specific authorization here, here's an example of how this can
    % be done
    User = case wrq:get_req_header("Authorization", ReqData) of
        "Basic "++Base64 ->
            case binary:split(base64:mime_decode(Base64), <<":">>) of
                [Username, Password] ->
                    case eow_db:check_user(Username, Password) of
                        true ->
                            Username;

                        false ->
                            unknown
                    end;

                _ ->
                    unknown
            end;

        _ ->
            unknown
    end,
    if
        User =/= unknown ->
            {true, ReqData, State#state{user=User}};

        true ->
            {"Basic realm=\"" ?REALM "\"", ReqData, State}
    end;
is_authorized(ReqData, #state{kind=Kind, params=Params}=State) ->
    Result = case Params of
        [] ->
            false;

        _ ->
            verify(Kind, Params, ReqData, State)
    end,
    case Result of
        {true, NewState} ->
            {true, ReqData, NewState};


        {_, NewState} ->
            {"OAuth realm=\"" ?REALM "\"", ReqData, NewState}
    end.

content_types_provided(ReqData, State) ->
    Types = [
        {?TEXT_MT, to_text}
    ],
    {Types, ReqData, State}.

to_text(ReqData, #state{kind=request_token, consumer=Consumer}=State) ->
    {Token, Secret} = eow_db:request_token_new(Consumer),
    Result = oauth:uri_params_encode([
        {"oauth_token", Token},
        {"oauth_token_secret", Secret}
    ]),
    {Result, ReqData, State};
to_text(ReqData, #state{kind=access_token, user=User}=State) ->
    % at this point, user != 'undefined' (it's handled in is_authorized function)
    {Token, Secret} = eow_db:access_token_new(User),
    Result = oauth:uri_params_encode([
        {"oauth_token", Token},
        {"oauth_token_secret", Secret}
    ]),
    {Result, ReqData, State};
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
            check_params(version, Params);

        _ ->
            nok
    end;
check_params(version, Params) ->
    Version = case lists:keyfind("oauth_version", 1, Params) of
        {_, Value} ->
            Value;

        _ ->
            "1.0"
    end,
    if
        Version == "1.0" ->
            check_params(signature, Params);

        true ->
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

required_params() -> [
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

verify(Kind, Params, ReqData, State) ->
    {value, {_, Signature}, OtherParams} = lists:keytake("oauth_signature", 1, Params),
    {_, ConsumerKey} = lists:keyfind("oauth_consumer_key", 1, OtherParams),
    URL = string:concat(?REALM, wrq:path(ReqData)),
    case eow_db:consumer_lookup(ConsumerKey) of
        none ->
            {false, State};

        Consumer ->
            verify(Kind, atom_to_list(wrq:method(ReqData)), URL, Signature,
                   OtherParams, State#state{consumer=Consumer})
    end.

verify(request_token, Method, URL, Signature, Params, #state{consumer=Consumer}=State) ->
    {oauth:verify(Signature, Method, URL, Params, Consumer, ""), State};
verify(access_token, Method, URL, Signature, Params, #state{consumer=Consumer}=State) ->
    case eow_db:request_token_lookup(Consumer, oauth:token(Params)) of
        none ->
            {false, State};

        {_, undefined} ->
            % the user has not authorized the request token yet (indicated by
            % user value 'undefined')
            {false, State};

        {Secret, User} ->
            {oauth:verify(Signature, Method, URL, Params, Consumer, Secret), State#state{user=User}}
    end;
verify(access, Method, URL, Signature, Params, #state{consumer=Consumer}=State) ->
    % this branch is not used in this module.  it should be used for serving
    % OAuth protected resources
    case eow_db:access_token_lookup(oauth:token(Params)) of
        none ->
            {false, State};

        {Secret, User} ->
            {oauth:verify(Signature, Method, URL, Params, Consumer, Secret), State#state{user=User}}
    end;
verify(_Kind, _, _, _, _, State) ->
    {false, State}.
