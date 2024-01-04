defmodule Webauthn.Registration.Challenge do
  @moduledoc """
  This module handles the first step of the Webauthn ceremony, creating a
  challenge so the client can register their device. The generate/1 function
  outputs a map of 'publicKey' options that will be passed into the browser's
  navigator.credentials.create method.

  **Note**
  The 'challenge' value is encoded as a url safe base64 string. In the front end
  you will need to decode this value and convert to a Uint8Array. We will include
  some javascript that will walk you through this process in the demo application.
  """

  # pubKeyCredParams uses algorithm values defined in the following document
  # https://www.iana.org/assignments/cose/cose.xhtml#key-type
  #
  # More information about this can be found here:
  # https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/pubKeyCredParams
  #
  # We default to ECDSA w/ SHA-256 which is represented by '-7'
  # We fallback to the algorithms listed in Google's webauthn demo app
  # https://github.com/google/webauthndemo

  @es256 -7
  @es384 -35
  @es512 -36
  @rs256 -257
  @rs384 -258
  @rs512 -259
  @ps256 -37
  @ps384 -38
  @ps512 -39

  @attestation_error "Attestation must be one of 'none', 'indirect', or 'direct'"
  @rp_error "Missing 'rp' (relying party) Map, configure your application or pass in this option directly"
  @user_error "Missing 'user' Map, expected :id, and :name parameters"

  @attestations ["none", "indirect", "direct"]

  def generate(challenge, options) do
    %{
      "attestation" => attestation_for(options),
      "authenticatorSelection" => authenticator_selection_for(options),
      "challenge" => challenge,
      "excludeCredentials" => exclude_credentials(options),
      "extensions" => extensions_for(options),
      "pubKeyCredParams" => public_key_credential(options),
      "rp" => relying_party(options),
      "timeout" => timeout_for(options),
      "user" => user_details(options)
    }
  end

  defp attestation_for(%{attestation: value}) do
    if value in @attestations do
      value
    else
      raise ArgumentError, @attestation_error
    end
  end

  defp attestation_for(%{"attestation" => value}) do
    if value in @attestations do
      value
    else
      raise ArgumentError, @attestation_error
    end
  end

  defp attestation_for(_options), do: "direct"

  # authenticatorSelection details
  # https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/authenticatorSelection
  defp authenticator_selection_for(%{authenticatorSelection: selection}), do: selection
  defp authenticator_selection_for(%{authenticator_selection: selection}), do: selection
  defp authenticator_selection_for(%{"authenticatorSelection" => selection}), do: selection
  defp authenticator_selection_for(%{"authenticator_selection" => selection}), do: selection
  defp authenticator_selection_for(_), do: %{}

  defp exclude_credentials(%{excludeCredentials: creds}), do: creds
  defp exclude_credentials(%{exclude_credentials: creds}), do: creds
  defp exclude_credentials(%{"excludeCredentials" => creds}), do: creds
  defp exclude_credentials(%{"exclude_credentials" => creds}), do: creds
  defp exclude_credentials(_options), do: []

  defp public_key_credential(%{pubKeyCredParams: params}), do: params
  defp public_key_credential(%{pub_key_cred_params: params}), do: params
  defp public_key_credential(%{"pubKeyCredParams" => params}), do: params
  defp public_key_credential(%{"pub_key_cred_params" => params}), do: params

  defp public_key_credential(_options) do
    Application.get_env(:webauthn, :pub_key_cred_params, [
      %{"type" => "public-key", "alg" => @es256},
      %{"type" => "public-key", "alg" => @es384},
      %{"type" => "public-key", "alg" => @es512},
      %{"type" => "public-key", "alg" => @rs256},
      %{"type" => "public-key", "alg" => @rs384},
      %{"type" => "public-key", "alg" => @rs512},
      %{"type" => "public-key", "alg" => @ps256},
      %{"type" => "public-key", "alg" => @ps384},
      %{"type" => "public-key", "alg" => @ps512}
    ])
  end

  # Relying party is a map containing an id and name, with an optional icon
  # https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/rp
  defp relying_party(%{rp: rp}), do: rp
  defp relying_party(%{"rp" => rp}), do: rp

  defp relying_party(_options) do
    Application.get_env(:webauthn, :relying_party) ||
      raise ArgumentError, @rp_error
  end

  # The time (in milliseconds) that the user has to respond to a prompt for
  # registration before an error is returned
  defp timeout_for(%{timeout: timeout}) when is_integer(timeout), do: timeout
  defp timeout_for(%{"timeout" => timeout}) when is_integer(timeout), do: timeout
  defp timeout_for(_options), do: 60_000

  defp user_details(%{user: user}), do: user
  defp user_details(%{"user" => user}), do: user

  defp user_details(_options) do
    raise ArgumentError, @user_error
  end

  # Extensions are values requesting additional processing by the client
  # https://www.w3.org/TR/webauthn/#sctn-defined-extensions
  # https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/extensions
  # https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#sctn-extensions-reg
  defp extensions_for(%{extensions: ext}) when is_map(ext), do: ext
  defp extensions_for(%{"extensions" => ext}) when is_map(ext), do: ext
  defp extensions_for(_), do: %{}
end
