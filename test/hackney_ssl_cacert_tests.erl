%%% -*- erlang -*-
%%%
%%% This file is part of hackney released under the Apache 2 license.
%%% See the NOTICE for more information.

-module(hackney_ssl_cacert_tests).

-include_lib("eunit/include/eunit.hrl").

cacert_test_() ->
  {foreach,
   fun setup/0,
   fun teardown/1,
   [fun configured_path_is_passed_as_cacertfile/0,
    fun a_binary_path_is_accepted/0,
    fun the_system_store_is_used_when_unset/0,
    fun peer_verification_stays_on/0]}.

setup() ->
  application:get_env(hackney, cacertfile_path).

teardown({ok, Path}) ->
  application:set_env(hackney, cacertfile_path, Path);
teardown(undefined) ->
  application:unset_env(hackney, cacertfile_path).

%% ssl reads and caches the file itself, so hackney passes the path through and
%% never holds the certificates.
configured_path_is_passed_as_cacertfile() ->
  Path = fixture(),
  ok = application:set_env(hackney, cacertfile_path, Path),
  Opts = hackney_ssl:check_hostname_opts("example.com"),
  ?assertEqual(Path, proplists:get_value(cacertfile, Opts)),
  ?assertEqual(undefined, proplists:get_value(cacerts, Opts)).

a_binary_path_is_accepted() ->
  Path = list_to_binary(fixture()),
  ok = application:set_env(hackney, cacertfile_path, Path),
  Opts = hackney_ssl:check_hostname_opts("example.com"),
  ?assertEqual(Path, proplists:get_value(cacertfile, Opts)).

the_system_store_is_used_when_unset() ->
  ok = application:unset_env(hackney, cacertfile_path),
  Opts = hackney_ssl:check_hostname_opts("example.com"),
  ?assertEqual(undefined, proplists:get_value(cacertfile, Opts)),
  case erlang:function_exported(public_key, cacerts_get, 0) of
    true ->
      ?assert(is_list(proplists:get_value(cacerts, Opts)));
    false ->
      %% Nothing to verify against. ssl rejects the options rather than
      %% accepting any peer.
      ?assertEqual(undefined, proplists:get_value(cacerts, Opts))
  end.

peer_verification_stays_on() ->
  ok = application:set_env(hackney, cacertfile_path, fixture()),
  Opts = hackney_ssl:check_hostname_opts("example.com"),
  ?assertEqual(verify_peer, proplists:get_value(verify, Opts)),
  ?assertMatch({_, _}, proplists:get_value(verify_fun, Opts)).

fixture() ->
  filename:join(filename:dirname(code:which(?MODULE)), "cacerts.pem").
