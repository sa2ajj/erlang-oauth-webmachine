-module(eow).

-export([
    start/0,
    start_link/0,
    stop/0
]).

ensure_started(App) ->
    case application:start(App) of
        ok ->
            ok;

        {error, {already_started, App}} ->
            ok
    end.

start_link() ->
    ensure_started(inets),
    ensure_started(crypto),
    ensure_started(mochiweb),
    application:set_env(webmachine, webmachine_logger_module, webmachine_logger),
    ensure_started(webmachine),
    eow_sup:start_link().

start() ->
    ensure_started(inets),
    ensure_started(crypto),
    ensure_started(mochiweb),
    application:set_env(webmachine, webmachine_logger_module, webmachine_logger),
    ensure_started(webmachine),
    application:start(eow).

stop() ->
    Res = application:stop(eow),
    application:stop(webmachine),
    application:stop(mochiweb),
    application:stop(crypto),
    application:stop(inets),
    Res.
