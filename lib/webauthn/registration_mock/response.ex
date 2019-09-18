defmodule Webauthn.RegistrationMock.Response do
  @moduledoc false

  def verify(_registration, attestation_obj, _json) do
    with {:ok, attestation_cbor} <- Base.url_decode64(attestation_obj, padding: false),
         {:ok, attestation, _} <- CBOR.decode(attestation_cbor),
         {:ok, auth_data} <- Webauthn.AuthenticatorData.parse(attestation) do
      {:ok, auth_data}
    else
      error -> error
    end
  end
end
