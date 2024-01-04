defmodule Webauthn.AuthenticatorData do
  @moduledoc """
  Information about the authenticator data can be found at the link below
  https://www.w3.org/TR/webauthn/#authenticator-data
  """

  alias Webauthn.AuthenticatorData

  defstruct [
    :acd_included,
    :attested_credential_data,
    :extension_included,
    :extensions,
    :raw_data,
    :rp_id_hash,
    :user_present,
    :user_verified,
    :sign_count
  ]

  def parse(%{"authData" => auth_data}), do: parse(auth_data)

  def parse(%CBOR.Tag{tag: :bytes, value: value}) do
    parse_rp_id(value, %AuthenticatorData{raw_data: value})
  end

  def parse(value) when is_binary(value) do
    parse_rp_id(value, %AuthenticatorData{raw_data: value})
  end

  def parse(_other), do: {:error, "Invalid authenticator data format"}

  def parse_rp_id(<<rp_id_hash::binary-size(32), rest::binary>>, ad) do
    parse_flags(rest, Map.put(ad, :rp_id_hash, rp_id_hash))
  end

  defp parse_flags(
         <<ed::size(1), at::size(1), _rfu2::size(3), uv::size(1), _rfu1::size(1), up::size(1),
           rest::binary>>,
         ad
       ) do
    parse_sign_count(
      rest,
      Map.merge(ad, %{
        acd_included: at,
        extension_included: ed,
        user_present: up,
        user_verified: uv
      })
    )
  end

  defp parse_sign_count(<<sign_count::integer-size(32), rest::binary>>, ad) do
    parse_acd(rest, Map.put(ad, :sign_count, sign_count))
  end

  # https://www.w3.org/TR/webauthn/#sec-attested-credential-data
  defp parse_acd(
         <<aaguid::binary-size(16), cred_len::integer-size(16), cred_id::binary-size(cred_len),
           pk_bin::binary>>,
         %AuthenticatorData{acd_included: 1} = ad
       ) do
    case CBOR.decode(pk_bin) do
      {:ok, public_key, rest} ->
        parse_extensions(
          rest,
          Map.put(ad, :attested_credential_data, %{
            aaguid: aaguid,
            credential_id: cred_id,
            credential_public_key: public_key
          })
        )

      error ->
        error
    end
  end

  defp parse_acd(binary, ad), do: parse_extensions(binary, ad)

  # https://www.w3.org/TR/webauthn/#extensions
  defp parse_extensions(binary, %AuthenticatorData{extension_included: 1} = ad) do
    case CBOR.decode(binary) do
      {:ok, extensions, _rest} -> {:ok, Map.put(ad, :extensions, extensions)}
      error -> error
    end
  end

  defp parse_extensions(_binary, ad), do: {:ok, ad}
end
