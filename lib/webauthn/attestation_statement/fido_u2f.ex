defmodule Webauthn.AttestationStatement.FidoU2F do
  # https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation
  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}

  def verify(%{"x5c" => x5c, "sig" => sig}, auth_data, client_hash) do
    with :ok <- x5c_size(x5c),
         {:ok, certificate} <- decode_cert(x5c),
         public_key <- X509.Certificate.public_key(certificate),
         :ok <- check_public_key(public_key),
         {:ok, public_key_u2f} <- ansi_x962(auth_data),
         verification_data <- build_verification_data(auth_data, client_hash, public_key_u2f),
         :ok <- check_signature(verification_data, sig, public_key) do
      {:ok, {:unknown, [certificate]}}
    else
      error -> error
    end
  end

  def verify(_, _, _), do: {:error, "FidoU2F: No matching verification function"}

  defp x5c_size(certs) when length(certs) == 1, do: :ok
  defp x5c_size(_), do: {:error, "FidoU2F: incorrect attestation cert length"}

  defp decode_cert(certs) when is_list(certs), do: decode_cert(hd(certs))
  defp decode_cert(%CBOR.Tag{tag: :bytes, value: value}) do
    X509.Certificate.from_der(value)
  end

  defp check_public_key({{:ECPoint, _}, {:namedCurve, @secp256r1_oid}}), do: :ok
  defp check_public_key({{:ECPoint, _}, {:namedCurve, :secp256r1}}), do: :ok
  defp check_public_key(_other), do: {:error, "FidoU2F: Invalid public key"}

  defp ansi_x962(%{attested_credential_data: data}), do: ansi_x962(data)
  defp ansi_x962(%{credential_public_key: pk}), do: ansi_x962(pk)
  defp ansi_x962(%{-2 => %CBOR.Tag{value: x}, -3 => %CBOR.Tag{value: y}}), do: ansi_x962(x, y)

  defp ansi_x962(_) do
    {:error, "FidoU2F: Missing Credential Public Key"}
  end

  defp ansi_x962(x, y) when byte_size(x) == 32 and byte_size(y) == 32 do
    {:ok, <<4>> <> x <> y}
  end

  defp ansi_x962(_, _) do
    {:error, "FidoU2F: Public key incorrectly formatted"}
  end

  defp build_verification_data(auth_data, client_hash, public_key_u2f) do
    <<0>>
    <> auth_data.rp_id_hash
    <> client_hash
    <> auth_data.attested_credential_data.credential_id
    <> public_key_u2f
  end

  # We can hard code sha256 here, see github issue for reference
  # https://github.com/w3c/webauthn/issues/1279
  defp check_signature(msg, %CBOR.Tag{tag: :bytes, value: sig}, public_key) do
    if :public_key.verify(msg, :sha256, sig, public_key) do
      :ok
    else
      {:error, "FidoU2F: Invalid signature"}
    end
  end

  defp check_signature(msg, sig, public_key) when is_binary(sig) do
    if :public_key.verify(msg, :sha256, sig, public_key) do
      :ok
    else
      {:error, "FidoU2F: Invalid signature"}
    end
  end

  defp check_signature(_, _, _), do: {:error, "FidoU2F: Invalid signature"}
end
