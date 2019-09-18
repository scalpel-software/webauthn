defmodule Webauthn do

  @auth_challenge Application.get_env(:webauthn, :auth_challenge, Webauthn.Authentication.Challenge)
  @auth_response Application.get_env(:webauthn, :auth_response, Webauthn.Authentication.Response)
  @reg_challenge Application.get_env(:webauthn, :registration_challenge, Webauthn.Registration.Challenge)
  @reg_response Application.get_env(:webauthn, :registration_response, Webauthn.Registration.Response)

  def challenge do
    Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
  end

  def auth_challenge(challenge, options) do
    @auth_challenge.generate(challenge, options)
  end

  def auth_response(request, params) do
    @auth_response.verify(request, params)
  end

  def registration_challenge(challenge, options) do
    @reg_challenge.generate(challenge, options)
  end

  def registration_response(request, att_obj, json) do
    @reg_response.verify(request, att_obj, json)
  end
end
