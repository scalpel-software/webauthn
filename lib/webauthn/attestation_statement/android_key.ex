defmodule Webauthn.AttestationStatement.AndroidKey do

  # https://w3c.github.io/webauthn/#sctn-android-key-attestation

  # https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h
  @km_origin_generated 0
  @km_purpose_sign 2
  @android_key_oid {1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

  @software_enforced_position 3
  @tee_enforced_position 4
  @all_applications_position 24
  @origin_position 28
  @purpose_position 1

  def verify(%{"alg" => alg, "sig" => sig, "x5c" => x5c}, auth_data, client_hash) do
    with {:ok, [cert | tail]} <- certification_chain_for(x5c),
         {:ok, digest} <- Webauthn.Cose.digest_for(alg),
         public_key <- X509.Certificate.public_key(cert),
         :ok <- valid_signature?(auth_data.raw_data <> client_hash, digest, tag_to_bytes(sig), public_key),
         {:ok, auth_public_key} <- Webauthn.Cose.to_public_key(auth_data),
         :ok <- matching_public_key?(auth_public_key, public_key),
         {:ok, key_description} <- find_key_description(cert),
         :ok <- matching_challenge?(key_description, client_hash),
         :ok <- all_applications_not_present?(key_description),
         :ok <- valid_origin_and_purpose(key_description) do
      {:ok, {:basic, [cert | tail]}}
    else
      error -> error
    end
  end

  defp certification_chain_for(x5c) when is_list(x5c) do
    {:ok, Enum.map(x5c, fn cert -> X509.Certificate.from_der!(cert.value) end)}
  end

  defp certification_chain_for(_x5c) do
    {:error, "Android Key: Certificate chain must return a list"}
  end

  defp valid_signature?(message, digest, signature, public_key) do
    if :public_key.verify(message, digest, signature, public_key) do
      :ok
    else
      {:error, "Android Key: Invalid signature"}
    end
  end

  defp matching_public_key?(auth_public_key, public_key) do
    case auth_public_key do
      ^public_key -> :ok
      _other -> {:error, "Android Key: Public key mismatch"}
    end
  end

  # https://github.com/google/u2f-ref-code/blob/master/u2f-ref-code/java/src/com/google/u2f/server/impl/attestation/android/AndroidKeyStoreAttestation.java#L59
  defp find_key_description(certificate) do
    certificate
    |> X509.Certificate.extension(@android_key_oid)
    |> extension_key_description()
  end

  defp extension_key_description({_ext, _oid, _critical, key_description}) do
    case :android_key_description.decode(:AndroidKeyDescription, key_description) do
      {:ok, response} -> {:ok, response}
      _error -> {:error, "Android Key: Unable to decode description"}
    end
  end

  defp extension_key_description(nil), do: {:error, "Missing Android extension"}

  defp matching_challenge?(key_description, client_hash) do
    if Webauthn.Utils.Crypto.secure_compare(elem(key_description, 2), client_hash) do
      :ok
    else
      {:error, "Android Key: challenge mismatch"}
    end
  end

  defp all_applications_not_present?(kd) do
    all_applications_not_present?(
      kd |> elem(@software_enforced_position) |> elem(@all_applications_position),
      kd |> elem(@tee_enforced_position) |> elem(@all_applications_position)
    )
  end

  defp all_applications_not_present?(:asn1_NOVALUE, :asn1_NOVALUE), do: :ok
  defp all_applications_not_present?(_soft, _tee) do
    {:error, "Android Key: All application was present in description"}
  end

  defp valid_origin_and_purpose(key_description) do
    valid_origin_and_purpose(
      key_description,
      Application.get_env(:webauthn, :tee_enforced)
    )
  end

  defp valid_origin_and_purpose(kd, false) do
    if tee_origin_and_purpose(kd) || software_origin_and_purpose(kd) do
      :ok
    else
      {:error, "Android Key: Invalid origin or purpose in description"}
    end
  end

  defp valid_origin_and_purpose(kd, _other) do
    if tee_origin_and_purpose(kd) do
      :ok
    else
      {:error, "Android Key: Invalid origin or purpose in description"}
    end
  end

  defp tee_origin_and_purpose(kd) do
    origin?(elem(kd, @tee_enforced_position)) &&
    purpose?(elem(kd, @tee_enforced_position))
  end

  defp software_origin_and_purpose(kd) do
    origin?(elem(kd, @software_enforced_position)) &&
    purpose?(elem(kd, @software_enforced_position))
  end

  defp origin?(auth_list) do
    case elem(auth_list, @origin_position) do
      @km_origin_generated -> true
      _other -> false
    end
  end

  defp purpose?(auth_list) do
    @km_purpose_sign in List.wrap(elem(auth_list, @purpose_position))
  end

  defp tag_to_bytes(%CBOR.Tag{tag: :bytes, value: value}), do: value
  defp tag_to_bytes(value), do: value
end
