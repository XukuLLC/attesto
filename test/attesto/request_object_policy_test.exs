defmodule Attesto.RequestObject.PolicyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.RequestObject.Policy

  describe "to_verify_opts/1" do
    test "generic/0 materializes no strict opts (only the false require flags)" do
      opts = Policy.to_verify_opts(Policy.generic())

      # nils are dropped so RequestObject.verify/3 keeps its own defaults
      # (notably :accepted_algs -> SigningAlg.fapi_algs()).
      refute Keyword.has_key?(opts, :accepted_algs)
      refute Keyword.has_key?(opts, :max_nbf_age_seconds)
      refute Keyword.has_key?(opts, :max_lifetime_seconds)
      refute Keyword.has_key?(opts, :accepted_typ)
      refute Keyword.has_key?(opts, :enforce_fapi_alg_policy)
      assert Keyword.get(opts, :require_nbf) == false
      assert Keyword.get(opts, :require_exp) == false
    end

    test "fapi_message_signing/0 materializes the FAPI 2.0 §5.3.1 opts" do
      opts = Policy.to_verify_opts(Policy.fapi_message_signing())

      assert Keyword.get(opts, :require_nbf) == true
      assert Keyword.get(opts, :max_nbf_age_seconds) == 3600
      assert Keyword.get(opts, :require_exp) == true
      assert Keyword.get(opts, :max_lifetime_seconds) == 3600
      # `typ` is validated when present but not required: the FAPI Message
      # Signing conformance suite signs request objects without a `typ` header,
      # and §5.3.1 only requires the OP to ACCEPT the type, not mandate it.
      assert Keyword.get(opts, :accepted_typ) == ["oauth-authz-req+jwt", nil]
      # accepted_algs is left nil so verify/3's fapi_algs() default applies.
      refute Keyword.has_key?(opts, :accepted_algs)
      assert Keyword.get(opts, :enforce_fapi_alg_policy) == true
    end

    test "algorithm-policy intent survives a narrowed allowlist" do
      fapi_policy = %{Policy.fapi_message_signing() | accepted_algs: ["PS256"]}
      assert Keyword.get(Policy.to_verify_opts(fapi_policy), :enforce_fapi_alg_policy) == true

      non_fapi_policy = %Policy{accepted_algs: ["PS256"], enforce_fapi_alg_policy: false}
      assert Keyword.get(Policy.to_verify_opts(non_fapi_policy), :enforce_fapi_alg_policy) == false
    end

    test "the presence flag is never leaked into the per-object verify opts" do
      # require_request_object governs whether an object must be present, not how
      # a present object is verified, so RequestObject.verify/3 must never see it.
      refute Keyword.has_key?(Policy.to_verify_opts(Policy.generic()), :require_request_object)

      refute Keyword.has_key?(
               Policy.to_verify_opts(Policy.fapi_message_signing()),
               :require_request_object
             )
    end

    test "generic/0 equals the struct default" do
      assert Policy.generic() == %Policy{}
    end
  end

  describe "require_request_object?/1" do
    test "generic/0 does not require a request object" do
      refute Policy.require_request_object?(Policy.generic())
      refute Policy.require_request_object?(%Policy{})
    end

    test "fapi_message_signing/0 requires a request object (§5.3.1)" do
      assert Policy.require_request_object?(Policy.fapi_message_signing())
    end
  end
end
