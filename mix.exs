defmodule Attesto.MixProject do
  @moduledoc false
  use Mix.Project

  alias Attesto.AuthorizationCode.Grant
  alias Attesto.CodeStore.ETS
  alias Attesto.DPoP.NonceStore
  alias Attesto.DPoP.ReplayCache
  alias Attesto.Keystore.Static
  alias Attesto.Plug.Authenticate
  alias Attesto.Plug.OAuthError
  alias Attesto.Plug.RequireScopes
  alias Attesto.Test.DPoP, as: TestDPoP
  alias Attesto.Test.DPoPVerifier, as: TestDPoPVerifier

  @version "0.12.0"
  @url "https://github.com/XukuLLC/attesto"
  @maintainers ["Neil Berkman"]

  def project do
    [
      name: "Attesto",
      app: :attesto,
      version: @version,
      elixir: "~> 1.18",
      package: package(),
      source_url: @url,
      homepage_url: @url,
      maintainers: @maintainers,
      description:
        "Vendor-neutral OAuth2/OIDC engine for Elixir with DPoP, mTLS, and PKCE " <>
          "sender-constraint support.",
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: docs(),
      aliases: aliases(),
      dialyzer: [
        ignore_warnings: ".dialyzer_ignore.exs",
        plt_add_apps: [:mix]
      ]
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test, check: :test]]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:jose, "~> 1.11"},
      # Optional: the Attesto.Plug.* integration layer. Hosts that use the
      # plugs already have Plug; the core library does not require it.
      {:plug, "~> 1.16", optional: true},

      # test - cross-language parity / contract tests drive a reference
      # joserfc/cryptography stack in-process via the erlang_python `:py`
      # NIF (see Attesto.Test.PythonBridge). Never shipped.
      {:erlang_python, "~> 3.0", only: :test},
      # test - property-based and mutation-fuzz testing.
      {:stream_data, "~> 1.1", only: :test},

      # dev / quality
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:mix_test_watch, "~> 1.4", only: :dev, runtime: false},
      {:quokka, "~> 2.12", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        "test"
      ],
      # Developer-facing local gate. Runs the full suite -- including the
      # ExUnitProperties `property` cases in test/attesto/property_test.exs,
      # which run as part of `mix test` because they are not behind a
      # `:property` tag/filter. Mirrors `precommit` but is named for the
      # day-to-day "did I break anything?" loop rather than CI.
      check: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "test",
        "credo --strict"
      ]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @url,
      extras: ["README.md", "CHANGELOG.md", "LICENSE"],
      groups_for_extras: [
        Changelog: ~r/CHANGELOG\.md/,
        License: ~r/LICENSE/
      ],
      groups_for_modules: [
        Core: [Attesto.Token, Attesto.IDToken, Attesto.Config, Attesto.PrincipalKind],
        Grants: [
          Attesto.PKCE,
          Attesto.AuthorizationCode,
          Grant,
          Attesto.RefreshToken,
          Attesto.Revocation,
          Attesto.IdentityAssertion
        ],
        Plugs: [
          Authenticate,
          RequireScopes,
          OAuthError
        ],
        Stores: [
          Attesto.CodeStore,
          ETS,
          Attesto.RefreshStore,
          Attesto.RefreshStore.ETS,
          NonceStore,
          Attesto.DPoP.NonceStore.ETS
        ],
        "Sender-constraint": [Attesto.DPoP, ReplayCache, Attesto.MTLS],
        Scopes: [Attesto.Scope],
        Metadata: [Attesto.JWKS, Attesto.Discovery],
        Keys: [Attesto.Keystore, Static, Attesto.Key],
        Shared: [
          Attesto.Thumbprint,
          Attesto.SecureCompare,
          Attesto.Secret,
          Attesto.ClusterGuard
        ],
        Testing: [TestDPoP, TestDPoPVerifier]
      ]
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{
        "Changelog" => "https://hexdocs.pm/attesto/changelog.html",
        "GitHub" => @url
      },
      files: ~w(lib LICENSE mix.exs README.md CHANGELOG.md)
    ]
  end
end
