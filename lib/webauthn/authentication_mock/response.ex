defmodule Webauthn.AuthenticationMock.Response do
  @moduledoc false

  @counter Application.get_env(:webauthn, :counter, :sign_count)

  def verify(%{"challenge" => "missingAuthData"}, _params) do
    {:error, "Missing authenticatorData parameter"}
  end

  def verify(%{"challenge" => "missingClientDataJSON"}, _params) do
    {:error, "Missing clientDataJSON parameter"}
  end

  def verify(%{"challenge" => "missingSignature"}, _params) do
    {:error, "Missing signature parameter"}
  end

  def verify(%{"challenge" => "missingRawId"}, _params) do
    {:error, "Missing rawId parameter"}
  end

  def verify(%{"challenge" => "missingCredential"}, _params) do
    {:error, "Could not find a matching credential"}
  end

  def verify(%{"challenge" => "invalidRequest"}, _params) do
    {:error, "Invalid request type"}
  end

  def verify(%{"challenge" => "missingChallenge"}, _params) do
    {:error, "Missing challenge"}
  end

  def verify(%{"challenge" => "originMismatch"}, _params) do
    {:error, "Origin does not match original request"}
  end

  def verify(%{"challenge" => "relyingPartyMismatch"}, _params) do
    {:error, "Relying party does not match original request"}
  end

  def verify(%{"challenge" => "missingRelyingParty"}, _params) do
    {:error, "Missing relying party"}
  end

  def verify(%{"challenge" => "userNotPresent"}, _params) do
    {:error, "User was not present"}
  end

  def verify(%{"challenge" => "userNotVerified"}, _params) do
    {:error, "User verification is required"}
  end

  def verify(%{"challenge" => "extensionMismatch"}, _params) do
    {:error, "Extensions flag not present, but extensions detected"}
  end

  def verify(%{"challenge" => "invalidSignature"}, _params) do
    {:error, "Invalid signature"}
  end

  def verify(%{"allowCredentials" => creds, "challenge" => "warn"}, _params) when is_list(creds) do
    {:warn, hd(creds), 0, "The device you're using may have been cloned."}
  end

  def verify(%{"allowCredentials" => creds}, _params) when is_list(creds) do
    {:ok, hd(creds), Map.get(hd(creds), @counter, 0) + 1}
  end
end
