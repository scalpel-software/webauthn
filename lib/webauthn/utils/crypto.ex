defmodule Webauthn.Utils.Crypto do
  use Bitwise

  @certifi_certs Enum.map(:certifi.cacerts(), fn cert ->
    X509.Certificate.from_der!(cert)
  end)

  # https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
  @yubico_cert X509.Certificate.from_pem!("""
  -----BEGIN CERTIFICATE-----
  MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
  dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
  MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
  IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
  AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
  5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
  8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
  nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
  9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
  LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
  hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
  BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
  MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
  hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
  LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
  sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
  U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
  -----END CERTIFICATE-----
  """)

  # https://developers.yubico.com/U2F/fido-preview-ca-cert.pem
  @yubico_preview X509.Certificate.from_pem!("""
  -----BEGIN CERTIFICATE-----
  MIIDGDCCAgCgAwIBAgIJAOklWRaQTVDkMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
  BAMMFll1YmljbyBGSURPIFByZXZpZXcgQ0EwHhcNMTkwMjE4MTIxMzA4WhcNMjAw
  MjE4MTIxMzA4WjAhMR8wHQYDVQQDDBZZdWJpY28gRklETyBQcmV2aWV3IENBMIIB
  IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnvKl/0EJyrD0nmaiU2VZrJl1
  EcJgBUrmzD4htni4ndcMJ4kXd0YMVoXZfBb684yghChJMTyJECcSE2qcdH1qZ8Cb
  +yGDpxUtghzHWCQ63I1/Q3MeX1GmF6YhqxL5cVeY93a0EbXU8S7HU5ttzKVc+wh0
  ufx6KqmwYUWOV38E28GQyWSKimdB15XG6ASen5GRa5opPdg+NORORuC7tVL80TbV
  KvQs2yYKJt0Pp5ZB2hEBS9QS0AuJgitQtEA96yzUSAib0unMRXhvK7reMTA+dVFZ
  e5is2HaKe55OQY+TlEkfUJF697HAT4oUFfyyG9uebi4WWqdFtfijaeyu1Mi3OwID
  AQABo1MwUTAdBgNVHQ4EFgQUEigaujrPSYpIIPDJc/HrqhEpG0swHwYDVR0jBBgw
  FoAUEigaujrPSYpIIPDJc/HrqhEpG0swDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
  9w0BAQsFAAOCAQEAYKOQsm46ysWVP/iv4Xj5EnHuQizOhPgmp9REoKVg/i4lhaqY
  293WzUsyRIdWVEFCpNWT3dTeaWm99n62bUSb0JtqU4+SGeMau3B7GiShmRbN7lLx
  z/By7KPqICYncLrKLukUCu6S6g4U6sPbDZRcxm8LYhR9DTxHuSxyb3gthFhxptBj
  Riceh8yGw4Ic649quLwqZ6dzgcEe9YqiWkLtAhrNWjxGRIayi3fuMGewCRfnHb0K
  bdRpjYMJSczrN5Wu5Dx+HIagOHLXsY6xbyh8bOimeoeQDbOpsUffILTXKs57QoHF
  tuCnuu0rEp9SIguG51IrUokbMFnUxMdfEkXrgA==
  -----END CERTIFICATE-----
  """)

  # https://www.hypersecu.com/support/downloads/attestation
  @hyperfido_cert X509.Certificate.from_pem!("""
  -----BEGIN CERTIFICATE-----
  MIIBjTCCATOgAwIBAgIBATAKBggqhkjOPQQDAjAXMRUwEwYDVQQDEwxGVCBGSURP
  IDAxMDAwHhcNMTQwNzAxMTUzNjI2WhcNNDQwNzAzMTUzNjI2WjAXMRUwEwYDVQQD
  EwxGVCBGSURPIDAxMDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxdLxJx8ol
  S3DS5cIHzunPF0gg69d+o8ZVCMJtpRtlfBzGuVL4YhaXk2SC2gptPTgmpZCV2vbN
  fAPi5gOF0vbZo3AwbjAdBgNVHQ4EFgQUXt4jWlYDgwhaPU+EqLmeM9LoPRMwPwYD
  VR0jBDgwNoAUXt4jWlYDgwhaPU+EqLmeM9LoPROhG6QZMBcxFTATBgNVBAMTDEZU
  IEZJRE8gMDEwMIIBATAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQC2
  D9o9cconKTo8+4GZPyZBJ3amc8F0/kzyidX9dhrAIAIgM9ocs5BW/JfmshVP9Mb+
  Joa/kgX4dWbZxrk0ioTfJZg=
  -----END CERTIFICATE-----
  """)

  # https://docs.solokeys.io/solo/metadata-statements/
  # Converted from base64 encoded string to pem certificate
  @solo_cert X509.Certificate.from_pem!("""
  -----BEGIN CERTIFICATE-----
  MIIB9DCCAZoCCQDER2OSj/S+jDAKBggqhkjOPQQDAjCBgDELMAkGA1UEBhMCVVMx
  ETAPBgNVBAgMCE1hcnlsYW5kMRIwEAYDVQQKDAlTb2xvIEtleXMxEDAOBgNVBAsM
  B1Jvb3QgQ0ExFTATBgNVBAMMDHNvbG9rZXlzLmNvbTEhMB8GCSqGSIb3DQEJARYS
  aGVsbG9Ac29sb2tleXMuY29tMCAXDTE4MTExMTEyNTE0MloYDzIwNjgxMDI5MTI1
  MTQyWjCBgDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1hcnlsYW5kMRIwEAYDVQQK
  DAlTb2xvIEtleXMxEDAOBgNVBAsMB1Jvb3QgQ0ExFTATBgNVBAMMDHNvbG9rZXlz
  LmNvbTEhMB8GCSqGSIb3DQEJARYSaGVsbG9Ac29sb2tleXMuY29tMFkwEwYHKoZI
  zj0CAQYIKoZIzj0DAQcDQgAEWHAN0CCJVZdMs0oktZ5m93uxmB1iyq8ELRLtqVFL
  SOiHQEab56qRTB/QzrpGAY++Y2mw+vRuQMNhBiU0KzwjBjAKBggqhkjOPQQDAgNI
  ADBFAiEAz9SlrAXIlEu87vra54rICPs+4b0qhp3PdzcTg7rvnP0CIGjxzlteQQx+
  jQGd7rwSZuE5RWUPVygYhUstQO9zNUOs
  -----END CERTIFICATE-----
  """)

  @doc """
  Compares the two binaries in constant-time to avoid timing attacks.
  """
  def secure_compare(left, right) do
    if byte_size(left) == byte_size(right) do
      secure_compare(left, right, 0) == 0
    else
      false
    end
  end

  defp secure_compare(<<x, left :: binary>>, <<y, right :: binary>>, acc) do
    secure_compare(left, right, acc ||| (x ^^^ y))
  end

  defp secure_compare(<<>>, <<>>, acc), do: acc

  def certificates do
    [@yubico_cert, @yubico_preview, @solo_cert, @hyperfido_cert] ++ @certifi_certs
  end

  def find_root_certificate(issuer) do
    Enum.find(certificates(), fn cert ->
      X509.Certificate.subject(cert) == issuer
    end)
  end
end
