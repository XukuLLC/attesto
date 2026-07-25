defmodule Attesto.RequestObject.Policy do
  @moduledoc """
  Verification policy for signed authorization request objects (JAR, RFC 9101).

  Policy expressed as data the caller passes to
  `Attesto.AuthorizationRequest.validate/2`, which threads it into
  `Attesto.RequestObject.verify/3`. The default `%Policy{}` is the generic
  OpenID Connect §6.1 / RFC 9101 baseline (a signed request object is verified,
  but `nbf`/`exp`/`typ` are not required). The FAPI 2.0 Message Signing §5.3.1
  profile is the named `fapi_message_signing/0` constructor - profile data, not
  a feature flag and not a backwards-compatibility shim.
  """

  alias Attesto.SigningAlg

  @type t :: %__MODULE__{
          accepted_algs: [SigningAlg.alg()] | nil,
          enforce_fapi_alg_policy: boolean() | nil,
          require_nbf: boolean(),
          max_nbf_age_seconds: pos_integer() | nil,
          require_exp: boolean(),
          max_lifetime_seconds: pos_integer() | nil,
          accepted_typ: [String.t() | nil] | nil,
          require_request_object: boolean()
        }

  defstruct accepted_algs: nil,
            enforce_fapi_alg_policy: nil,
            require_nbf: false,
            max_nbf_age_seconds: nil,
            require_exp: false,
            max_lifetime_seconds: nil,
            accepted_typ: nil,
            require_request_object: false

  # Struct fields that express presence / server-behaviour policy rather than
  # a per-object verification rule, so they are excluded from `to_verify_opts/1`
  # (which feeds `Attesto.RequestObject.verify/3`, a single-object verifier that
  # never sees whether an object was required in the first place).
  @non_verify_keys [:require_request_object]

  @doc """
  The generic OpenID Connect §6.1 / RFC 9101 baseline: a signed request object
  is verified, but `nbf`/`exp`/`typ` are not required. Equivalent to `%Policy{}`.
  """
  @spec generic() :: t()
  def generic, do: %__MODULE__{}

  @doc """
  The FAPI 2.0 Message Signing §5.3.1 profile for signed request objects:

    * a signed request object is REQUIRED - an authorization request that
      carries none is rejected (FAPI 2.0 Message Signing §5.3.1, which mandates
      that clients send the request as a signed JWT);
    * `nbf` REQUIRED, no more than 60 minutes in the past;
    * `exp` REQUIRED, no more than 60 minutes after `nbf`;
    * JOSE header `typ`, when present, must be `"oauth-authz-req+jwt"`, but is
      NOT required.

  `accepted_algs` is left `nil` to inherit `Attesto.RequestObject.verify/3`'s
  default (`Attesto.SigningAlg.fapi_algs/0`: PS256, ES256, legacy EdDSA over
  Ed25519, and explicit Ed25519). `enforce_fapi_alg_policy` is set explicitly
  so a caller can narrow `accepted_algs` without disabling the profile's RSA
  modulus and Edwards-curve checks.

  Note on `typ`: §5.3.1's "shall accept that typ" requires an OP to *accept* the
  `oauth-authz-req+jwt` type when a client sends it - it does not license
  *requiring* it, and RFC 9101 §4 makes `typ` only RECOMMENDED. The FAPI 2.0
  Message Signing conformance suite signs its request objects with no `typ`
  header at all, so an OP that mandates `typ` rejects every conformant request
  and fails certification. `accepted_typ: ["oauth-authz-req+jwt", nil]` therefore
  keeps the RFC 9101 §10.8 explicit-typing defence *when a `typ` is present*
  (a wrong type is still rejected) while accepting its absence.
  """
  @spec fapi_message_signing() :: t()
  def fapi_message_signing do
    %__MODULE__{
      enforce_fapi_alg_policy: true,
      require_nbf: true,
      max_nbf_age_seconds: 3600,
      require_exp: true,
      max_lifetime_seconds: 3600,
      accepted_typ: ["oauth-authz-req+jwt", nil],
      require_request_object: true
    }
  end

  @doc """
  Whether this policy requires the authorization request to carry a signed
  request object (FAPI 2.0 Message Signing §5.3.1). When `true`, a request that
  presents no `request` object is rejected rather than processed from its plain
  parameters.
  """
  @spec require_request_object?(t()) :: boolean()
  def require_request_object?(%__MODULE__{require_request_object: required}), do: required == true

  @doc """
  Flatten the policy to `Attesto.RequestObject.verify/3` options, dropping
  `nil` values so `verify/3` keeps its own defaults (notably `accepted_algs`,
  which defaults to `Attesto.SigningAlg.fapi_algs/0`) and the non-verification
  presence fields (`#{inspect(@non_verify_keys)}`). Boolean `false` remains
  present, allowing a generic non-FAPI policy to opt out of the FAPI key gate
  explicitly.
  """
  @spec to_verify_opts(t()) :: keyword()
  def to_verify_opts(%__MODULE__{} = policy) do
    policy
    |> Map.from_struct()
    |> Map.drop(@non_verify_keys)
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Keyword.new()
  end
end
