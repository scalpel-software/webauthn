defmodule Webauthn.AttestationStatement.TPM do
  # https://w3c.github.io/webauthn/#sctn-tpm-attestation
  @moduledoc false
  @tpm_alg_rsa 0x0001
  @tpm_alg_sha 0x0004
  @tpm_alg_sha256 0x000B
  @tpm_alg_sha384 0x000C
  @tpm_alg_sha512 0x000D
  @tpm_alg_null 0x0010
  @tpm_alg_ecc 0x0023

  # Values taken from the TCG Vendor ID Registry - Table 2
  # https://trustedcomputinggroup.org/wp-content/uploads/Vendor_ID_Registry_0-8_clean.pdf
  @tcg_vendor_ids MapSet.new([
                    # AMD - AMD
                    "id:414D4400",
                    # ATML - Atmel
                    "id:41544D4C",
                    # BRCM - Broadcom
                    "id:4252434D",
                    # IBM - IBM
                    "id:49424D00",
                    # IFX - Infineon
                    "id:49465800",
                    # INTC - Intel
                    "id:494E5443",
                    # LEN - Lenovo
                    "id:4C454E00",
                    # NSM - National Semiconductor
                    "id:4E534D20",
                    # NTZ - Nationz
                    "id:4E545A00",
                    # NTC - Nuvoton Technology
                    "id:4E544300",
                    # QCOM - Qualcomm
                    "id:51434F4D",
                    # SMSC - SMSC
                    "id:534D5343",
                    # STM - St Microelectronics
                    "id:53544D20",
                    # SMSN - Samsung
                    "id:534D534E",
                    # SNS - Sinosun
                    "id:534E5300",
                    # TXN - Texas Instruments
                    "id:54584E00",
                    # WEC - Winbond
                    "id:57454300",
                    # ROCC - Fuzhou Rockchip
                    "id:524F4343"
                  ])

  @basic {2, 5, 29, 19}
  @ext_key_usage {2, 5, 29, 37}
  @fido_gen_ce {1, 3, 6, 1, 4, 1, 45_724, 1, 1, 4}

  def verify(%{"ecdaaKeyId" => _}, _, _) do
    {:error, "TPM: ECDAA attestation not implemented"}
  end

  def verify(%{"x5c" => x5c} = att_stmt, auth_data, client_hash) do
    att_to_be_signed = auth_data.raw_data <> client_hash

    with {:ok, cert_info} <- parse_cert(att_stmt),
         {:ok, digest} <- Webauthn.Cose.digest_for(att_stmt["alg"]),
         {:ok, auth_public_key} <- Webauthn.Cose.to_public_key(auth_data),
         {:ok, pub_area} <- parse_pub_area(att_stmt),
         attested_name = create_attested_name(att_stmt["pubArea"], pub_area),
         {:ok, [leaf_cert | tail]} <- certification_chain_for(x5c),
         leaf_public_key = X509.Certificate.public_key(leaf_cert),
         :ok <- check_version(att_stmt),
         :ok <- check_magic_field(cert_info),
         :ok <- check_type_field(cert_info),
         :ok <- check_extra_data(cert_info, att_to_be_signed, digest),
         :ok <- check_public_key(auth_public_key, pub_area_to_public_key(pub_area)),
         :ok <- check_attested_name(cert_info, attested_name),
         :ok <-
           check_signature(
             tag_to_bytes(att_stmt["certInfo"]),
             digest,
             tag_to_bytes(att_stmt["sig"]),
             leaf_public_key
           ),
         :ok <- check_aik_version(leaf_cert),
         :ok <- check_aik_subject_sequence(leaf_cert),
         :ok <- check_aik_validity(leaf_cert),
         :ok <- check_aik_subject_alt_name(leaf_cert),
         :ok <- check_aik_ext_key_usage(leaf_cert),
         :ok <- check_aik_basic_constraints(leaf_cert),
         :ok <- check_aik_aaguid(leaf_cert, auth_data) do
      {:ok, {:basic, [leaf_cert | tail]}}
    end
  end

  def verify(_, _, _) do
    {:error, "TPM: No matching verification function"}
  end

  defp certification_chain_for(x5c) when is_list(x5c) do
    {:ok, Enum.map(x5c, fn cert -> X509.Certificate.from_der!(cert.value) end)}
  end

  defp certification_chain_for(_x5c) do
    {:error, "TPM: Certificate chain must return a list"}
  end

  defp parse_cert(%{"certInfo" => value}), do: parse_cert(value)
  defp parse_cert(%CBOR.Tag{tag: :bytes, value: value}), do: parse_cert(value)

  defp parse_cert(
         <<magic::integer-size(32), type::integer-size(16),
           qualified_signer_length::integer-size(16),
           _qualified_signer::binary-size(qualified_signer_length),
           extra_data_length::integer-size(16), extra_data::binary-size(extra_data_length),
           _clock_info::binary-size(17), _firmware_version::integer-size(64),
           attested_name_length::integer-size(16), attested_name::binary-size(attested_name_length),
           qualified_name_length::integer-size(16),
           qualified_name::binary-size(qualified_name_length)>>
       ) do
    {:ok,
     %{
       magic: magic,
       type: type,
       extra_data: extra_data,
       attested_name: attested_name,
       qualified_name: qualified_name
     }}
  end

  defp parse_cert(_other), do: {:error, "TPM: Invalid certificate format"}

  # Section 12.2.4
  # https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
  defp parse_pub_area(%{"pubArea" => value}), do: parse_pub_area(value)
  defp parse_pub_area(%CBOR.Tag{tag: :bytes, value: value}), do: parse_pub_area(value)

  # Parsing RSA Pub Area - TPM2B_PUBLIC_KEY_RSA
  # Found in Section 11.2.4.5 of TPM-Rev-2.0 Part 2
  defp parse_pub_area(
         <<@tpm_alg_rsa::integer-size(16), name_alg::integer-size(16),
           object_attributes::integer-size(32), auth_policy_length::integer-size(16),
           auth_policy::binary-size(auth_policy_length), @tpm_alg_null::integer-size(16),
           scheme::integer-size(16), key_bits::integer-size(16), exponent::integer-size(32),
           unique_length::integer-size(16), unique::integer-unit(8)-size(unique_length)>>
       ) do
    {:ok,
     %{
       type: :rsa,
       name_alg: name_alg,
       object_attributes: object_attributes,
       auth_policy: auth_policy,
       scheme: scheme,
       key_bits: key_bits,
       exponent: if(exponent == 0, do: 65_537, else: exponent),
       unique: unique
     }}
  end

  # Parsing ECC Pub Area - Unique is a TPMS_ECC_POINT - 2 TPM2B_ECC_PARAMETER(s)
  # Found in Section 11.2.5.1 of TPM-Rev-2.0 Part 2
  defp parse_pub_area(
         <<@tpm_alg_ecc::integer-size(16), name_alg::integer-size(16),
           object_attributes::binary-size(4), auth_policy_length::integer-size(16),
           auth_policy::binary-size(auth_policy_length), @tpm_alg_null::integer-size(16),
           scheme::integer-size(16), curve_id::integer-size(16), @tpm_alg_null::integer-size(16),
           _unique_length::integer-size(16), x_length::integer-size(16), x::binary-size(x_length),
           y_length::integer-size(16), y::binary-size(y_length)>>
       ) do
    {:ok,
     %{
       type: :ecc,
       name_alg: name_alg,
       object_attributes: object_attributes,
       auth_policy: auth_policy,
       scheme: scheme,
       curve_id: translate_curve(curve_id),
       x: x,
       y: y
     }}
  end

  defp parse_pub_area(_other), do: {:error, "TPM: Invalid pub area"}

  defp create_attested_name(%CBOR.Tag{value: raw_pub_area}, pub_area) do
    pub_area.name_alg
    |> name_alg_digest()
    |> :crypto.hash(raw_pub_area)
    |> then(fn hash -> <<pub_area.name_alg::integer-size(16)>> <> hash end)
  end

  defp check_version(%{"ver" => "2.0"}), do: :ok
  defp check_version(_other), do: {:error, "TPM: Invalid version"}

  # Located in table 7: TPM_GENERATED_VALUE
  # https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
  defp check_magic_field(%{magic: 0xFF544347}), do: :ok
  defp check_magic_field(_other), do: {:error, "TPM: Incorrect 'magic' field"}

  # Located in table 19: TPM_ST_ATTEST_CERTIFY
  # https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
  defp check_type_field(%{type: 0x8017}), do: :ok
  defp check_type_field(_other), do: {:error, "TPM: Incorrect 'type' field"}

  defp check_extra_data(%{extra_data: data}, message, digest) do
    if Webauthn.Utils.Crypto.secure_compare(:crypto.hash(digest, message), data) do
      :ok
    else
      {:error, "TPM: Extra data hash mismatch"}
    end
  end

  defp check_public_key(public_key, pub_area_public_key) do
    case public_key do
      ^pub_area_public_key -> :ok
      _other -> {:error, "TPM: Auth data public key does not match pub area"}
    end
  end

  defp check_attested_name(cert_info, attested_name) do
    if Webauthn.Utils.Crypto.secure_compare(cert_info.attested_name, attested_name) do
      :ok
    else
      {:error, "TPM: Attested name mismatch"}
    end
  end

  defp check_signature(message, digest, sig, public_key) do
    if :public_key.verify(message, digest, sig, public_key) do
      :ok
    else
      {:error, "TPM: Invalid signature"}
    end
  end

  defp check_aik_version(cert) do
    if X509.Certificate.version(cert) == :v3 do
      :ok
    else
      {:error, "TPM: Invalid aik certificate version"}
    end
  end

  defp check_aik_subject_sequence(cert) do
    if X509.Certificate.subject(cert) == {:rdnSequence, []} do
      :ok
    else
      {:error, "TPM: Invalid aik subject sequence"}
    end
  end

  defp check_aik_validity(cert) do
    if in_validity_range?(X509.Certificate.validity(cert), DateTime.utc_now()) do
      :ok
    else
      {:error, "TPM: certificate is not valid"}
    end
  end

  defp in_validity_range?({:Validity, from, until}, time) do
    time >= X509.DateTime.to_datetime(from) &&
      time <= X509.DateTime.to_datetime(until)
  end

  defp check_aik_subject_alt_name(cert) do
    case X509.Certificate.extension(cert, :subject_alt_name) do
      {:Extension, _oid, true, [directoryName: rdnTuple]} ->
        if valid_aik_manufacturer?(rdnTuple), do: :ok, else: {:error, "TPM: Invalid manufacturer"}

      {:Extension, _oid, false, _data} ->
        {:error, "TPM: subject alt name marked non-critical"}

      nil ->
        {:error, "TPM: Missing subject alt name"}
    end
  end

  defp valid_aik_manufacturer?({:rdnSequence, list}) do
    list
    |> List.flatten()
    |> Enum.find({nil, nil, "na"}, fn tuple -> elem(tuple, 1) == {2, 23, 133, 2, 1} end)
    |> elem(2)
    |> String.slice(2..-1//-1)
    |> then(fn id -> MapSet.member?(@tcg_vendor_ids, id) end)
  end

  defp valid_aik_manufacturer?(_other), do: false

  defp check_aik_ext_key_usage(cert) do
    case X509.Certificate.extension(cert, @ext_key_usage) do
      {:Extension, _oid, _critical, {2, 23, 133, 8, 3}} -> :ok
      _other -> {:error, "TPM: ext key usage extension missing OID"}
    end
  end

  defp check_aik_basic_constraints(cert) do
    case X509.Certificate.extension(cert, @basic) do
      {:Extension, _, _, {:BasicConstraints, false, _}} -> :ok
      nil -> {:error, "TPM: Missing basic constraint extension"}
      _other -> {:error, "TPM: basic constraint CA is true"}
    end
  end

  # Structure of aaguid is 4 (Tag: OCTET STRING), 16 (Length), Value
  defp check_aik_aaguid(cert, auth_data) do
    case X509.Certificate.extension(cert, @fido_gen_ce) do
      {:Extension, _, _, <<4, 16, aaguid::binary>>} ->
        check_matching_aaguid(auth_data, aaguid)

      nil ->
        :ok
    end
  end

  defp check_matching_aaguid(%{attested_credential_data: %{aaguid: auth_aaguid}}, aaguid) do
    if Webauthn.Utils.Crypto.secure_compare(auth_aaguid, aaguid) do
      :ok
    else
      {:error, "TPM: fido-gen-ce-aaguid mismatch"}
    end
  end

  defp check_matching_aaguid(_, _) do
    {:error, "TPM: fido-gen-ce-aaguid mismatch"}
  end

  defp pub_area_to_public_key(%{type: :rsa} = pub_area) do
    {:RSAPublicKey, pub_area.unique, pub_area.exponent}
  end

  defp pub_area_to_public_key(%{type: :ecc} = pub_area) do
    {
      {:ECPoint, <<4>> <> pub_area.x <> pub_area.y},
      {:namedCurve, pub_area.curve_id}
    }
  end

  # Section 6.4 - TPM_ECC_CURVE of Rev-2.0-Part-2
  # Some curves are not supported in Erlang, since we delegate to openssl
  # Run > "openssl ecparam -list_curves" to find all supported curves
  defp translate_curve(0x0001), do: :secp192r1
  defp translate_curve(0x0002), do: :secp224r1
  defp translate_curve(0x0003), do: :secp256r1
  defp translate_curve(0x0004), do: :secp384r1
  defp translate_curve(0x0005), do: :secp521r1
  defp translate_curve(_other), do: :__unsupported__

  defp name_alg_digest(@tpm_alg_sha), do: :sha
  defp name_alg_digest(@tpm_alg_sha256), do: :sha256
  defp name_alg_digest(@tpm_alg_sha384), do: :sha384
  defp name_alg_digest(@tpm_alg_sha512), do: :sha512
  defp name_alg_digest(_other), do: :__unknown__

  defp tag_to_bytes(%CBOR.Tag{tag: :bytes, value: value}), do: value
  defp tag_to_bytes(value), do: value
end
