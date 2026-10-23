%%%-------------------------------------------------------------------
%%% @author benoitc
%%% @copyright (C) 2018, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 02. Apr 2018 11:42
%%%-------------------------------------------------------------------
-module(hackney_ssl_tests).
-author("benoitc").

-include_lib("eunit/include/eunit.hrl").
-include("hackney_lib.hrl").


setup() -> ok.

teardown(_) -> ok.

empty_clen_test_() ->
  {
    "test SSL",
    {
      setup,
      fun start/0, fun stop/1,
      {
        foreach,
        fun setup/0, fun teardown/1,
        [
          fun wildcard_cert/1,
          fun custom_ssl_opts_hostname_verification/1,
          fun googleapis_ssl_opts_test/1
        ]
      }
    }
  }.

%% The default options take their trust anchors from `cacertfile_path'. Point
%% it at the bundle in the test directory so that these requests do not depend
%% on the trust store of the machine running the tests, which on OTP 24 does
%% not exist as far as `public_key' is concerned.
start() ->
  error_logger:tty(false),
  ok = application:set_env(hackney, cacertfile_path, cacertfile()),
  {ok, _} = application:ensure_all_started(hackney),
  ok.

stop(_) ->
  application:stop(hackney),
  ok = application:unset_env(hackney, cacertfile_path),
  error_logger:tty(true),
  ok.

cacertfile() ->
  filename:join(filename:dirname(code:which(?MODULE)), "cacerts.pem").

wildcard_cert(_) ->
    URL = <<"https://friendpaste.com">>,
    Resp = case hackney:get(URL) of
             {ok, _, _, _} -> valid;
             _ -> error
           end,
    ?_assertEqual(Resp, valid).

custom_ssl_opts_hostname_verification(_) ->
    URL = <<"https://www.googleapis.com">>,
    %% Test with custom ssl_options that should not override hostname verification
    CustomSSLOpts = [{versions, ['tlsv1.2', 'tlsv1.3']}, {ciphers, []}],
    Opts = [{ssl_options, CustomSSLOpts}],
    Resp = case hackney:get(URL, [], <<>>, Opts) of
             {ok, _, _, _} -> valid;
             _ -> error
           end,
    ?_assertEqual(Resp, valid).

googleapis_ssl_opts_test(_) ->
    %% Erlang translation of the Elixir test that failed in 1.22.0
    URL = "https://www.googleapis.com/oauth2/v1/certs",
    SSLOpts = [
        {versions, ['tlsv1.2']},
        {verify, verify_peer},
        {cacertfile, cacertfile()},
        {depth, 10},
        {customize_hostname_check, [
            {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
        ]}
    ],
    Opts = [
        {ssl_options, SSLOpts},
        {recv_timeout, 500},
        {with_body, true}
    ],
    Resp = case hackney:request(get, URL, [], "", Opts) of
             {ok, 200, _Headers, _Body} -> success;
             _ -> error
           end,
    ?_assertEqual(Resp, success).

