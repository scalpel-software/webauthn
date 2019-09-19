defmodule Webauthn.Authentication.Response do
  alias Webauthn.AuthenticatorData

  @counter Application.get_env(:webauthn, :counter_attr, :sign_count)
  @credential Application.get_env(:webauthn, :credential_id_attr, :credential_id)
  @public_key Application.get_env(:webauthn, :public_key_attr, :credential_public_key)

  # https://www.w3.org/TR/webauthn/#verifying-assertion
  # request expected to look like to have form:
  # %{
  #   "allowCredentials" => [], # array of %{credential_id: id, public_key: key}
  #   "challenge" => challenge,
  #   "origin" => origin,
  #   "rp" => %{"id" => rp_id},
  #   "userHandle" => user,
  #   "userVerification" => "preferred" | "required" | "discouraged",
  # }

  # params structure expected to look like:
  # %{
  #   "id" => id,
  #   "response" => %{
  #     "authenticatorData" => auth_data,
  #     "clientDataJSON" => json,
  #     "signature" => signature,
  #     "userHandle" => handle
  #   }
  # }

  def verify(request, params) do
    with {:ok, {auth_bin, auth_data}} <- decode_auth_data(params),
         {:ok, {cdata, client_json}} <- decode_json(params),
         {:ok, signature} <- decode_signature(params),
         {:ok, public_key_id} <- find_public_key(params),
         {:ok, credential} <- find_credential(request, public_key_id),
         :ok <- type?(client_json),
         :ok <- challenge?(request, client_json),
         :ok <- origin?(request, client_json),
         :ok <- token_binding?(request, client_json),
         :ok <- rp_id_hash?(request, auth_data),
         :ok <- user_present?(auth_data),
         :ok <- user_verified?(request, auth_data),
         :ok <- user_handle?(request["userHandle"], params["userHandle"]),
         :ok <- extensions?(auth_data),
         cdata_hash <- :crypto.hash(:sha256, cdata),
         stored_public_key <- Map.get(credential, @public_key, nil),
         {:ok, public_key} <- Webauthn.Cose.to_public_key(stored_public_key),
         {:ok, digest} <- Webauthn.Cose.digest_for(stored_public_key),
         :ok <- valid_signature?(auth_bin <> cdata_hash, digest, signature, public_key) do
      signature_count(auth_data, credential)
    else
      error -> error
    end
  end

  def decode_auth_data(%{"response" => response}), do: decode_auth_data(response)
  def decode_auth_data(%{"authenticatorData" => auth_data}) do
    case Base.url_decode64(auth_data, padding: false) do
      {:ok, data} -> parse_auth_data(data)
      error -> error
    end
  end

  def decode_auth_data(_params), do: {:error, "Missing authenticatorData parameter"}

  def parse_auth_data(data) do
    case AuthenticatorData.parse(data) do
      {:ok, auth_data} -> {:ok, {data, auth_data}}
      error -> error
    end
  end

  def decode_json(%{"response" => response}), do: decode_json(response)
  def decode_json(%{"clientDataJSON" => raw_json}) do
    case Jason.decode(raw_json) do
      {:ok, json} -> {:ok, {raw_json, json}}
      error -> error
    end
  end

  def decode_json(_params), do: {:error, "Missing clientDataJSON parameter"}

  def decode_signature(%{"response" => response}), do: decode_signature(response)
  def decode_signature(%{"signature" => signature}) do
    Base.url_decode64(signature, padding: false)
  end

  def decode_signature(_params), do: {:error, "Missing signature parameter"}

  def find_public_key(%{"id" => id}), do: Base.url_decode64(id, padding: false)
  def find_public_key(_params), do: {:error, "Missing id parameter"}

  def find_credential(%{"allowCredentials" => credentials}, key_id) do
    find_credential(credentials, key_id)
  end

  def find_credential([], _), do: {:error, "Could not find a matching credential"}
  def find_credential([head | tail], key_id) do
    if Webauthn.Utils.Crypto.secure_compare(Map.get(head, @credential, ""), key_id) do
      {:ok, head}
    else
      find_credential(tail, key_id)
    end
  end

  def type?(%{"type" => "webauthn.get"}), do: :ok
  def type?(_other), do: {:error, "Invalid request type"}

  def challenge?(%{"challenge" => request}, %{"challenge" => response}) do
    if request && response && Webauthn.Utils.Crypto.secure_compare(request, response) do
      :ok
    else
      {:error, "Response challenge does not match original request"}
    end
  end

  def challenge?(_, _), do: {:error, "Missing challenge"}

  def origin?(%{"origin" => request}, %{"origin" => response}) do
    if request && response && Webauthn.Utils.Crypto.secure_compare(request, response) do
      :ok
    else
      {:error, "Origin does not match original request"}
    end
  end

  def origin?(_, _), do: {:error, "Missing origin"}

  # Token Binding is not implemented in any browser so we can skip this step
  def token_binding?(_, _), do: :ok

  def rp_id_hash?(%{"rp" => %{"id" => rp_id}}, %{rp_id_hash: hash}) do
    if Webauthn.Utils.Crypto.secure_compare(:crypto.hash(:sha256, rp_id), hash) do
      :ok
    else
      {:error, "Relying party does not match original request"}
    end
  end

  def rp_id_hash?(_, _), do: {:error, "Missing relying party"}

  def user_present?(%{user_present: 1}), do: :ok
  def user_present?(_other), do: {:error, "User was not present"}

  def user_verified?(%{"userVerification" => "required"}, auth_data) do
    if auth_data.user_verified == 1 do
      :ok
    else
      {:error, "User verification is required"}
    end
  end

  def user_verified?(_, _), do: :ok

  def user_handle?(request, response) when not is_nil(request) and not is_nil(response) do
    if Webauthn.Utils.Crypto.secure_compare(request, response) do
      :ok
    else
      {:error, "User handle does not match value provided by the server"}
    end
  end

  def user_handle?(_, _), do: :ok

  # In the future we will do more extension verification
  def extensions?(%{extension_included: 1, extensions: exts}) do
    if is_nil(exts) || length(exts) == 0 do
      {:error, "Extensions flag not present, but extensions detected"}
    else
      :ok
    end
  end

  def extensions?(%{extension_included: 0, extensions: exts}) do
    if is_nil(exts) do
      :ok
    else
      {:error, "Extensions flag not present, but extensions detected"}
    end
  end

  def valid_signature?(message, digest, signature, key) do
    if :public_key.verify(message, digest, signature, key) do
      :ok
    else
      {:error, "Invalid signature"}
    end
  end

  def signature_count(%{sign_count: response}, credential) do
    if response > Map.get(credential, @counter, 0) do
      {:ok, credential, response}
    else
      {:warn, credential, response, "The device you're using may have been cloned."}
    end
  end
end
