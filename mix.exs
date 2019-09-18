defmodule Webauthn.MixProject do
  use Mix.Project

  # If we need to compile asn schema to erlang module add following below
  # asn1_paths: ["/asn1"],
  # compilers: [:asn1] ++ Mix.compilers,
  def project do
    [
      app: :webauthn,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  # Only require below lib when we need to transform asn1 schema to modules
  # {:asn1ex, git: "git://github.com/vicentfg/asn1ex.git"}
  defp deps do
    [
      {:jason, "~> 1.1"},
      {:x509, "~> 0.7.0"},
      {:certifi, "~> 2.5.1"},
      {:cbor, "~> 1.0.0"},
      {:ex_doc, "~> 0.21", only: :dev, runtime: false}
    ]
  end
end
