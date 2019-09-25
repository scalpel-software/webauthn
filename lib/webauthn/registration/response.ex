defmodule Webauthn.Registration.Response do
  alias Webauthn.{AuthenticatorData, AttestationStatement}

  # Steps for Relying Party to follow when registering a new credential
  # https://www.w3.org/TR/webauthn/#registering-a-new-credential
  # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#intro

  def verify(registration, attestation_obj, raw_client_json) do
    with {:ok, client_json} <- Jason.decode(raw_client_json),
         :ok <- type?(client_json),
         :ok <- challenge?(registration, client_json),
         :ok <- origin?(registration, client_json),
         :ok <- token_binding?(registration, client_json),
         {:ok, attestation_cbor} <- Base.url_decode64(attestation_obj, padding: false),
         {:ok, attestation, _} <- CBOR.decode(attestation_cbor),
         {:ok, auth_data} <- AuthenticatorData.parse(attestation),
         :ok <- rp_id?(registration, auth_data),
         :ok <- user_present?(auth_data),
         :ok <- user_verified?(registration, auth_data),
         :ok <- client_extension_verified?(auth_data),
         client_hash <- :crypto.hash(:sha256, raw_client_json),
         {:ok, attest_data} <- attestation?(attestation, auth_data, client_hash),
         :ok <- trustworthy?(attest_data, trusted_types()) do
      {:ok, auth_data}
    else
      error -> error
    end
  end

  defp type?(%{"type" => "webauthn.create"}), do: :ok
  defp type?(_other), do: {:error, "Invalid request type"}

  defp challenge?(%{"challenge" => stored}, %{"challenge" => challenge}) do
    if stored == challenge, do: :ok, else: {:error, "Challenge mismatch"}
  end

  defp challenge?(_stored, _json), do: {:error, "Challenge not present"}

  defp origin?(%{"origin" => stored}, %{"origin" => origin}) do
    if stored == origin, do: :ok, else: {:error, "Origin mismatch"}
  end

  defp origin?(_stored, _json), do: {:error, "Origin not present"}

  defp token_binding?(server, %{"tokenBinding" => client}) do
    Webauthn.Utils.TokenBinding.validate(server, client)
  end

  defp token_binding?(_server, _params), do: :ok

  defp rp_id?(%{"rp" => %{"id" => rp_id}}, data) do
    if :crypto.hash(:sha256, rp_id) == data.rp_id_hash do
      :ok
    else
      {:error, "Relying party id mismatch"}
    end
  end

  defp rp_id?(_registration, _data), do: {:error, "Missing rp[id] parameter"}

  defp user_present?(%AuthenticatorData{user_present: 1}), do: :ok
  defp user_present?(_data), do: {:error, "User not present"}

  defp user_verified?(_reg, %AuthenticatorData{user_verified: 1}), do: :ok
  defp user_verified?(registration, _data) do
    registration
    |> Map.get("authenticatorSelection", %{})
    |> Map.get("userVerification", "preferred")
    |> user_verified?()
  end

  # Can be "required", "preferred", or "discouraged"
  defp user_verified?("required"), do: {:error, "User verification is required"}
  defp user_verified?(_other), do: :ok

  # This is the only library I could find that attempts to verify extensions
  # https://github.com/abergs/fido2-net-lib/blob/master/Src/AuthenticatorAssertionResponse.cs
  # Will send an email to the working group to verify that this is what should be done
  defp client_extension_verified?(%AuthenticatorData{extension_included: 1} = ad) do
    if is_nil(ad.extensions) || length(ad.extensions) == 0 do
      {:error, "Extensions flag not present, but extensions detected"}
    else
      :ok
    end
  end

  defp client_extension_verified?(%AuthenticatorData{extension_included: 0} = ad) do
    if is_nil(ad.extensions) do
      :ok
    else
      {:error, "Extensions flag not present, but extensions detected"}
    end
  end

  # https://w3c.github.io/webauthn/#sctn-defined-attestation-formats
  defp attestation?(%{"fmt" => "packed", "attStmt" => att_stmt}, auth_data, client_hash) do
    AttestationStatement.Packed.verify(att_stmt, auth_data, client_hash)
  end

  defp attestation?(%{"fmt" => "tpm", "attStmt" => att_stmt}, auth_data, client_hash) do
    AttestationStatement.TPM.verify(att_stmt, auth_data, client_hash)
  end

  defp attestation?(%{"fmt" => "android-key", "attStmt" => att_stmt}, auth_data, client_hash) do
    AttestationStatement.AndroidKey.verify(att_stmt, auth_data, client_hash)
  end

  defp attestation?(%{"fmt" => "android-safetynet", "attStmt" => att_stmt}, auth_data, client_hash) do
    AttestationStatement.AndroidSafetynet.verify(att_stmt, auth_data, client_hash)
  end

  defp attestation?(%{"fmt" => "fido-u2f", "attStmt" => att_stmt}, auth_data, client_hash) do
    AttestationStatement.FidoU2F.verify(att_stmt, auth_data, client_hash)
  end

  defp attestation?(%{"fmt" => "none"}, _, _) do
    {:ok, {:none, nil}}
  end

  defp attestation?(_, _, _) do
    {:error, "Invalid attestation format"}
  end

  # Provide default attestation types for relying party
  defp trusted_types do
    Application.get_env(
      :webauthn,
      :trusted_attestation_types,
      [:self, :basic, :none, :attca, :unknown]
    )
  end

  defp trustworthy?({:self, nil}, types) do
    if :self in types do
      :ok
    else
      {:error, "Registration: Devices with 'self' attestation are not trustworthy"}
    end
  end

  defp trustworthy?({:none, nil}, types) do
    if :none in types do
      :ok
    else
      {:error, "Registration: Devices without attestation information are not trustworthy"}
    end
  end

  defp trustworthy?({:attca, certs}, types) when is_list(certs) do
    if :attca in types do
      acceptable_root_cert?(certs)
    else
      {:error, "Registration: Attca attestation is not supported"}
    end
  end

  defp trustworthy?({:basic, certs}, types) when is_list(certs) do
    if :basic in types do
      acceptable_root_cert?(certs)
    else
      {:error, "Registration: Basic attestation is not supported"}
    end
  end

  defp trustworthy?({:unknown, certs}, types) when is_list(certs) do
    if :unknown in types do
      acceptable_root_cert?(certs)
    else
      {:error, "Registration: Unknown attestation is not supported"}
    end
  end

  defp trustworthy?(_, _) do
    {:error, "Registration: This device is not trustworthy"}
  end

  defp acceptable_root_cert?(certs) do
    certs
    |> List.last()
    |> X509.Certificate.issuer()
    |> Webauthn.Utils.Crypto.find_root_certificate()
    |> acceptable?()
  end

  defp acceptable?(nil), do: {:error, "Registration: Untrusted Root Certificate"}
  defp acceptable?(_other), do: :ok
end
