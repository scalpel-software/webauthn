defmodule Webauthn.AttestationStatement.Packed do
  # https://www.iso.org/obp/ui/#iso:pub:PUB500001:en
  @iso3166 MapSet.new(~w(AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TLa TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW))
  @basic_constraint {2, 5, 29, 19}
  @fido_gen_ce {1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

  # https://w3c.github.io/webauthn/#sctn-packed-attestation

  # ECDAA verification - Not Implemented
  # As of 2019-08-01, this method is unsupported by most webauthn
  # implementations. Right now it's a bit of a foot gun that still needs to be resolved
  def verify(%{"ecdaaKeyId" => _}, _auth_data, _client_hash) do
    {:error, "Packed: ECDAA attestation not implemented"}
  end

  # attestation type is not ECDAA
  def verify(%{"alg" => alg, "sig" => sig, "x5c" => x5c}, auth_data, client_hash) do
    with {:ok, [leaf_cert | tail]} <- certification_chain_for(x5c),
         public_key <- X509.Certificate.public_key(leaf_cert),
         {:ok, digest} <- Webauthn.Cose.digest_for(alg),
         :ok <- verify_x5c(auth_data.raw_data <> client_hash, digest, tag_to_bytes(sig), public_key),
         :ok <- check_cert_version(leaf_cert),
         :ok <- check_cert_subject_format(leaf_cert),
         :ok <- check_cert_country_code(leaf_cert),
         :ok <- check_cert_extension(leaf_cert, auth_data),
         :ok <- check_basic_constraint(leaf_cert) do
      {:ok, {:unknown, [leaf_cert | tail]}}
    else
      error -> error
    end
  end

  # self attestation
  def verify(%{"alg" => alg, "sig" => sig}, auth_data, client_hash) do
    with :ok <- check_algorithms(alg, auth_data),
         message <- auth_data.raw_data <> client_hash,
         {:ok, public_key} <- Webauthn.Cose.to_public_key(auth_data),
         {:ok, digest} <- Webauthn.Cose.digest_for(alg),
         :ok <- check_self_signature(message, digest, sig, public_key) do
      {:ok, {:self, nil}}
    else
      error -> error
    end
  end

  defp certification_chain_for(x5c) when is_list(x5c) do
    {:ok, Enum.map(x5c, fn cert -> X509.Certificate.from_der!(cert.value) end)}
  end

  defp certification_chain_for(_x5c) do
    {:error, "Packed: Certificate chain must return a list"}
  end

  defp verify_x5c(message, digest, signature, public_key) do
    if :public_key.verify(message, digest, signature, public_key) do
      :ok
    else
      {:error, "Packed: Invalid signature"}
    end
  end

  defp check_cert_version(cert) do
    case X509.Certificate.version(cert) do
      :v3 -> :ok
      _other -> {:error, "Packed: Invalid certificate version"}
    end
  end

  # Format is /C= => /O= => /OU= => /CN=
  defp check_cert_subject_format(cert) do
    if match?({:rdnSequence, [
      [{:AttributeTypeAndValue, {2, 5, 4, 6}, _}],
      [{:AttributeTypeAndValue, {2, 5, 4, 10}, {:utf8String, _}}],
      [{:AttributeTypeAndValue, {2, 5, 4, 11}, {:utf8String, "Authenticator Attestation"}}],
      [{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, _}}]
    ]}, X509.Certificate.subject(cert)) do
      :ok
    else
      {:error, "Packed: Invalid certificate format"}
    end
  end

  defp check_cert_country_code(cert) do
    if valid_country_code?(cert), do: :ok, else: {:error, "Packed: Invalid country code"}
  end

  defp valid_country_code?(cert) do
    cert
    |> X509.Certificate.subject()
    |> X509.RDNSequence.get_attr("C")
    |> MapSet.new()
    |> MapSet.subset?(@iso3166)
  end

  # Structure of aaguid is 4 (Tag: OCTET STRING), 16 (Length), Value
  defp check_cert_extension(cert, %{attested_credential_data: %{aaguid: aaguid}}) do
    case X509.Certificate.extension(cert, @fido_gen_ce) do
      {:Extension, _, false, <<4, 16, result::binary>>} -> compare_aaguid(result, aaguid)
      {:Extension, _, false, result} -> compare_aaguid(result, aaguid)
      {:Extension, _, true, _} -> {:error, "Packed: fido extension listed as critical"}
      _other -> :ok
    end
  end

  defp compare_aaguid(result, aaguid) do
    if Webauthn.Utils.Crypto.secure_compare(result, aaguid) do
      :ok
    else
      {:error, "Packed: certificate extension mismatch"}
    end
  end

  defp check_basic_constraint(cert) do
    case X509.Certificate.extension(cert, @basic_constraint) do
      {:Extension, _, _, {:BasicConstraints, false, _}} -> :ok
      nil -> {:error, "Packed: Missing basic constraint extension"}
      _other -> {:error, "Packed: basic constraint CA is true"}
    end
  end

  # https://www.iana.org/assignments/cose/cose.xhtml#algorithms
  defp check_algorithms(alg, auth_data) do
    if alg == auth_data.attested_credential_data.credential_public_key[3] do
      :ok
    else
      {:error, "Packed: Algorithm mismatch"}
    end
  end

  defp check_self_signature(message, digest, signature, public_key) do
    if :public_key.verify(message, digest, signature, public_key) do
      :ok
    else
      {:error, "Packed: Invalid signature"}
    end
  end

  defp tag_to_bytes(%CBOR.Tag{tag: :bytes, value: value}), do: value
  defp tag_to_bytes(value), do: value
end
