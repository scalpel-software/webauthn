defmodule Webauthn.Authentication.Challenge do
  @rp_error "Webauthn: Please set a relying party"

  def generate(challenge, options) do
    %{
      "allowCredentials" => credentials_for(options),
      "challenge" => challenge,
      "extensions" => extensions_for(options),
      "rp" => relying_party(options),
      "timeout" => timeout_for(options),
      "userVerification" => user_verification(options)
    }
  end

  defp credentials_for(%{"allowCredentials" => creds}), do: creds
  defp credentials_for(%{allowCredentials: creds}), do: creds
  defp credentials_for(%{"allow_credentials" => creds}), do: creds
  defp credentials_for(%{allow_credentials: creds}), do: creds
  defp credentials_for(_), do: []

  # Extensions are values requesting additional processing by the client
  # https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/extensions
  # https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#sctn-extensions-reg
  defp extensions_for(%{extensions: ext}) when is_map(ext), do: ext
  defp extensions_for(%{"extensions" => ext}) when is_map(ext), do: ext
  defp extensions_for(_), do: %{}

  # Relying party is a map containing an id and name, with an optional icon
  # https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/rp
  defp relying_party(%{rp: rp}), do: rp
  defp relying_party(%{"rp" => rp}), do: rp
  defp relying_party(_options) do
    Application.get_env(:webauthn, :relying_party) ||
    raise ArgumentError, @rp_error
  end

  # The time (in milliseconds) that the user has to respond to a prompt for
  # registration before an error is returned
  defp timeout_for(%{timeout: timeout}) when is_integer(timeout), do: timeout
  defp timeout_for(%{"timeout" => timeout}) when is_integer(timeout), do: timeout
  defp timeout_for(_options), do: 60000

  defp user_verification(%{user_verification: "discouraged"}), do: "discouraged"
  defp user_verification(%{"user_verification" => "discouraged"}), do: "discouraged"
  defp user_verification(%{user_verification: "required"}), do: "required"
  defp user_verification(%{"user_verification" => "required"}), do: "required"
  defp user_verification(_other), do: "preferred"
end
