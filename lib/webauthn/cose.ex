defmodule Webauthn.Cose do

  @okp 1
  @ec2 2
  @rsa 3
  @symmetric 4

  @okp_curves [4, 5]
  @ec2_curves [1, 2, 3]

  @sha_digests [-65535, -40]
  @sha256_digests [-257, -41, -37, -10, -7, 4, 5]
  @sha384_digests [-258, -38, -35, 6]
  @sha512_digests [-259, -42, -39, -36, -11, 7]

  def digest_for(%{3 => number}), do: digest_for(number)
  def digest_for(number) when number in @sha_digests, do: {:ok, :sha}
  def digest_for(number) when number in @sha256_digests, do: {:ok, :sha256}
  def digest_for(number) when number in @sha384_digests, do: {:ok, :sha384}
  def digest_for(number) when number in @sha512_digests, do: {:ok, :sha512}
  def digest_for(number), do: {:error, "Unknown digest: #{number}"}

  # http://erlang.org/doc/apps/public_key/public_key_records.html
  # https://www.iana.org/assignments/cose/cose.xhtml#key-type

  def to_public_key(%{attested_credential_data: data}), do: to_public_key(data)
  def to_public_key(%{credential_public_key: key}), do: to_public_key(key)

  # okp - Octet Ket Pair
  # https://tools.ietf.org/html/rfc8152#section-13.2
  def to_public_key(%{1 => @okp, -2 => x, -1 => crv}) when crv in @okp_curves do
    {:ok, {:ed_pub, crv, tag_to_bytes(x)}}
  end

  # ec2 - Elliptic Curve Keys w/ x- and y-coordinate pair
  # https://www.ietf.org/rfc/rfc5480.txt
  #
  # The first octet of the OCTET STRING indicates whether the key is
  # compressed or uncompressed.  The uncompressed form is indicated by 0x04
  def to_public_key(%{1 => @ec2, -2 => x, -3 => y, -1 => crv}) when crv in @ec2_curves do
    {:ok, {
      {:ECPoint, <<4>> <> tag_to_bytes(x) <> tag_to_bytes(y)},
      {:namedCurve, named_curve(crv)}
    }}
  end

  # rsa - Rivest-Shamir-Adleman cryptosystem (RSA) keys
  def to_public_key(%{1 => @rsa, -1 => modulus, -2 => exponent}) do
    {:ok, {:RSAPublicKey, rsa_int(modulus), rsa_int(exponent)}}
  end

  # Symmetric - Just return the key that was given
  def to_public_key(%{1 => @symmetric, 4 => key}), do: {:ok, tag_to_bytes(key)}
  def to_public_key(_other), do: {:error, "Invalid public key format"}

  # https://tools.ietf.org/html/rfc8152#section-13.1
  defp named_curve(1), do: :secp256r1
  defp named_curve(2), do: :secp384r1
  defp named_curve(3), do: :secp521r1
  defp named_curve(4), do: :x25519
  defp named_curve(5), do: :x448
  defp named_curve(6), do: :ed25519
  defp named_curve(7), do: :ed448
  defp named_curve(number), do: {:error, "Unknown curve for: #{number}"}

  defp tag_to_bytes(%CBOR.Tag{tag: :bytes, value: value}), do: value
  defp tag_to_bytes(value), do: value

  defp rsa_int(%CBOR.Tag{tag: :bytes, value: value}), do: rsa_int(value)
  defp rsa_int(value) do
    size = byte_size(value)
    <<result::integer-size(size)-unit(8)>> = value

    result
  end
end
