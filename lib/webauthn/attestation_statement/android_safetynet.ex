defmodule Webauthn.AttestationStatement.AndroidSafetynet do
  # https://w3c.github.io/webauthn/#sctn-android-safetynet-attestation
  @hostname "attest.android.com"
  @required_safetynet_keys [
    "apkPackageName",
    "apkCertificateDigestSha256",
    "basicIntegrity",
    "ctsProfileMatch",
    "nonce",
    "timestampMs"
  ]

  # Time between sending the request and verifying it (2 minutes)
  @window_ms 120_000

  def verify(%{"response" => response}, auth_data, client_hash) do
    with expanded <- expand(response),
         {:ok, [leaf_cert | tail]} <- certification_chain_for(expanded),
         :ok <- check_safetynet_response(expanded),
         :ok <- matching_nonce?(expanded, auth_data.raw_data <> client_hash),
         :ok <- check_timestamp(expanded),
         :ok <- check_validity_period(leaf_cert),
         :ok <- matching_hostname?(leaf_cert),
         :ok <- validate_certificate_chain([leaf_cert | tail]),
         :ok <- verify_signature(leaf_cert, expanded) do
      {:ok, {:basic, [leaf_cert | tail]}}
    else
      error -> error
    end
  end

  defp expand(%CBOR.Tag{tag: :bytes, value: value}), do: expand(String.split(value, "."))
  defp expand([protected, payload, signature]) do
    %{
      "message" => protected <> "." <> payload,
      "protected" => from_base64_json(protected),
      "payload" => from_base64_json(payload),
      "signature" => Base.url_decode64!(signature, padding: false)
    }
  end

  defp from_base64_json(value) do
    value |> Base.url_decode64!(padding: false) |> Jason.decode!()
  end

  defp check_safetynet_response(%{"payload" => payload}) do
    if valid_safetynet_response?(payload) do
      :ok
    else
      {:error, "Invalid android safetynet response"}
    end
  end

  defp valid_safetynet_response?(payload) do
    Enum.all?(@required_safetynet_keys, fn key -> Map.has_key?(payload, key) end) &&
    Map.get(payload, "ctsProfileMatch") == true &&
    !Map.has_key?(payload, "error")
  end

  defp matching_nonce?(%{"payload" => %{"nonce" => nonce}}, bytes) do
    if Webauthn.Utils.Crypto.secure_compare(:crypto.hash(:sha256, bytes), nonce) do
      :ok
    else
      {:error, "Android safetynet nonce mismatch"}
    end
  end

  defp check_timestamp(%{"payload" => %{"timestampMs" => timestamp}}) do
    check_timestamp(timestamp, DateTime.to_unix(DateTime.utc_now(), :millisecond))
  end

  defp check_timestamp(timestamp, now) do
    if timestamp < now && timestamp >= (now - @window_ms) do
      :ok
    else
      {:error, "Request not completed in allotted time"}
    end
  end

  defp certification_chain_for(%{"protected" => %{"x5c" => x5c}}) when is_list(x5c) do
    {:ok, Enum.map(x5c, fn cert -> X509.Certificate.from_der!(Base.decode64!(cert)) end)}
  end

  defp check_validity_period(cert) do
    if in_validity_range?(X509.Certificate.validity(cert), DateTime.utc_now()) do
      :ok
    else
      {:error, "Android safetynet certificate is not valid"}
    end
  end

  defp in_validity_range?({:Validity, from, until}, time) do
    time >= X509.DateTime.to_datetime(from) &&
    time <= X509.DateTime.to_datetime(until)
  end

  defp matching_hostname?(certificate) do
    if Webauthn.Utils.Crypto.secure_compare(find_hostname(certificate), @hostname) do
      :ok
    else
      {:error, "Android safetynet hostname mismatch"}
    end
  end

  defp find_hostname(certificate) do
    certificate
    |> X509.Certificate.subject()
    |> X509.RDNSequence.get_attr("CN")
    |> List.first()
  end

  defp validate_certificate_chain(chain) do
    chain
    |> List.last()
    |> X509.Certificate.issuer()
    |> Webauthn.Utils.Crypto.find_root_certificate()
    |> validate_certificate_chain(chain)
  end

  defp validate_certificate_chain(nil, _) do
    {:error, "Android Safetynet root certificate not found"}
  end

  # TODO_VERIFY: Ensure this works the way you think it does.
  # NOTE: Users must configure the 'crl_check' option on the ssl application
  # to automatically fetch the Certificate Revocation List on all certs
  # we recommend that you set it to ':best_effort' as it defaults to 'false'
  defp validate_certificate_chain(root, chain) do
    case :public_key.pkix_path_validation(root, [root | Enum.reverse(chain)], [{:verify_fun, {&check_revoked/3, {root}}}]) do
      {:ok, _} -> :ok
      {:error, _} -> {:error, "Invalid Android Safetynet certificate"}
    end
  end

  defp check_revoked(_cert, {:bad_cert, _} = reason, _state), do: {:fail, reason}
  defp check_revoked(_cert, {:revoked, _} = reason, _state), do: {:fail, reason}
  defp check_revoked(_cert, {:extension, _}, state), do: {:valid, state}
  defp check_revoked(_cert, _unknown, state), do: {:unknown, state}

  defp verify_signature(cert, expanded) do
    verify_signature(
      Map.get(expanded, "message", nil),
      digest_alg(expanded),
      Map.get(expanded, "signature", nil),
      X509.Certificate.public_key(cert)
    )
  end

  defp verify_signature(message, algorithm, signature, public_key) do
    if :public_key.verify(message, algorithm, signature, public_key) do
      :ok
    else
      {:error, "Android Safetynet: Invalid jws signature"}
    end
  end

  defp digest_alg(%{"protected" => %{"alg" => "RS256"}}), do: :sha256
  defp digest_alg(%{"protected" => %{"alg" => "RS384"}}), do: :sha384
  defp digest_alg(%{"protected" => %{"alg" => "RS512"}}), do: :sha512
  defp digest_alg(%{"protected" => %{"alg" => "ES256"}}), do: :sha256
  defp digest_alg(%{"protected" => %{"alg" => "ES384"}}), do: :sha384
  defp digest_alg(%{"protected" => %{"alg" => "ES512"}}), do: :sha512
  defp digest_alg(_), do: raise "jws unsupported digest alg"
end
