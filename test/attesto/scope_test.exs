defmodule Attesto.ScopeTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Scope

  # An explicit, application-supplied catalog. Attesto does not ship one;
  # the consuming app builds it once via new_catalog/1.
  @scopes ~w(
    documents.read
    objects.read
    groups.read
    positions.read
    readings.read
    incidents.read
    events.read
    webhooks.read
    webhooks.write
  )

  @resources ~w(documents objects groups positions readings incidents events webhooks)

  setup do
    %{catalog: Scope.new_catalog(@scopes)}
  end

  describe "entries/1" do
    test "returns the concrete catalog entries, sorted", %{catalog: catalog} do
      assert Scope.entries(catalog) == Enum.sort(@scopes)
    end

    test "deduplicates entries supplied more than once" do
      catalog = Scope.new_catalog(["documents.read", "documents.read", "objects.read"])
      assert Scope.entries(catalog) == ["documents.read", "objects.read"]
    end

    test "contains no wildcard forms", %{catalog: catalog} do
      refute Enum.any?(Scope.entries(catalog), &String.contains?(&1, "*"))
    end

    test "every entry is a dotted resource.action string", %{catalog: catalog} do
      for scope <- Scope.entries(catalog) do
        assert [resource, action] = String.split(scope, ".", parts: 2)
        assert resource != ""
        assert action != ""
        refute String.contains?(action, ".")
      end
    end
  end

  describe "resources/1" do
    test "returns the distinct left-of-dot resources, sorted", %{catalog: catalog} do
      assert Scope.resources(catalog) == Enum.sort(@resources)
    end

    test "deduplicates resources shared across multiple entries", %{catalog: catalog} do
      assert Enum.count(Scope.resources(catalog), &(&1 == "webhooks")) == 1
    end
  end

  describe "known?/2" do
    test "true for every concrete catalog entry", %{catalog: catalog} do
      for scope <- @scopes do
        assert Scope.known?(catalog, scope), "expected #{inspect(scope)} to be known"
      end
    end

    test "false for the full wildcard", %{catalog: catalog} do
      refute Scope.known?(catalog, "*")
    end

    test "false for resource-level wildcard grant forms", %{catalog: catalog} do
      refute Scope.known?(catalog, "documents.*")
      refute Scope.known?(catalog, "webhooks.*")
    end

    test "false for unknown concrete strings", %{catalog: catalog} do
      refute Scope.known?(catalog, "totally.fake")
      refute Scope.known?(catalog, "documents.write")
      refute Scope.known?(catalog, "")
    end

    test "false for non-strings", %{catalog: catalog} do
      refute Scope.known?(catalog, nil)
      refute Scope.known?(catalog, :documents_read)
      refute Scope.known?(catalog, 123)
    end
  end

  describe "valid_grant_form?/2 (system-issued credentials)" do
    test "true for concrete catalog entries", %{catalog: catalog} do
      for scope <- @scopes do
        assert Scope.valid_grant_form?(catalog, scope)
      end
    end

    test "true for the full wildcard (system-only form)", %{catalog: catalog} do
      assert Scope.valid_grant_form?(catalog, "*")
    end

    test "true for resource-level wildcards whose resource is in the catalog", %{catalog: catalog} do
      for resource <- Scope.resources(catalog) do
        assert Scope.valid_grant_form?(catalog, "#{resource}.*"),
               "expected #{resource}.* to be a valid grant form"
      end
    end

    test "false for resource-level wildcards whose resource is not in the catalog", %{
      catalog: catalog
    } do
      refute Scope.valid_grant_form?(catalog, "fleet.*")
      refute Scope.valid_grant_form?(catalog, "vehicles.*")
    end

    test "false for deep wildcards like a.b.*", %{catalog: catalog} do
      refute Scope.valid_grant_form?(catalog, "documents.read.*")
      refute Scope.valid_grant_form?(catalog, "webhooks.read.*")
    end

    test "false for degenerate wildcard-looking strings", %{catalog: catalog} do
      refute Scope.valid_grant_form?(catalog, ".*")
      refute Scope.valid_grant_form?(catalog, "*.read")
      refute Scope.valid_grant_form?(catalog, "documents.")
      refute Scope.valid_grant_form?(catalog, "documents")
    end

    test "false for non-strings", %{catalog: catalog} do
      refute Scope.valid_grant_form?(catalog, nil)
      refute Scope.valid_grant_form?(catalog, :"documents.read")
      refute Scope.valid_grant_form?(catalog, [])
    end
  end

  describe "customer_grant_form?/2 (customer-facing issuance)" do
    test "true for concrete catalog entries", %{catalog: catalog} do
      for scope <- @scopes do
        assert Scope.customer_grant_form?(catalog, scope)
      end
    end

    test "rejects the full wildcard (system-only form)", %{catalog: catalog} do
      refute Scope.customer_grant_form?(catalog, "*")
    end

    test "true for resource-level wildcards whose resource is in the catalog", %{catalog: catalog} do
      for resource <- Scope.resources(catalog) do
        assert Scope.customer_grant_form?(catalog, "#{resource}.*")
      end
    end

    test "false for resource-level wildcards whose resource is not in the catalog", %{
      catalog: catalog
    } do
      refute Scope.customer_grant_form?(catalog, "fleet.*")
      refute Scope.customer_grant_form?(catalog, "vehicles.*")
    end

    test "false for deep wildcards like a.b.*", %{catalog: catalog} do
      refute Scope.customer_grant_form?(catalog, "documents.read.*")
      refute Scope.customer_grant_form?(catalog, "webhooks.read.*")
    end

    test "false for degenerate wildcard-looking strings", %{catalog: catalog} do
      refute Scope.customer_grant_form?(catalog, ".*")
      refute Scope.customer_grant_form?(catalog, "*.read")
      refute Scope.customer_grant_form?(catalog, "documents.")
      refute Scope.customer_grant_form?(catalog, "documents")
    end

    test "false for non-strings", %{catalog: catalog} do
      refute Scope.customer_grant_form?(catalog, nil)
      refute Scope.customer_grant_form?(catalog, :"documents.read")
      refute Scope.customer_grant_form?(catalog, [])
    end
  end

  describe "grants?/3 - concrete matches" do
    test "exact match grants", %{catalog: catalog} do
      assert Scope.grants?(catalog, ["documents.read"], "documents.read")
    end

    test "different concrete scopes do not grant each other", %{catalog: catalog} do
      refute Scope.grants?(catalog, ["documents.read"], "positions.read")
      refute Scope.grants?(catalog, ["webhooks.read"], "webhooks.write")
    end

    test "grant list mixed with unrelated scopes still grants the matching one", %{catalog: catalog} do
      assert Scope.grants?(catalog, ["groups.read", "documents.read"], "documents.read")
    end
  end

  describe "grants?/3 - wildcard grants" do
    test "resource-level wildcard covers every catalog action under that resource", %{
      catalog: catalog
    } do
      assert Scope.grants?(catalog, ["webhooks.*"], "webhooks.read")
      assert Scope.grants?(catalog, ["webhooks.*"], "webhooks.write")
    end

    test "resource-level wildcard does not cross resources", %{catalog: catalog} do
      refute Scope.grants?(catalog, ["documents.*"], "positions.read")
      refute Scope.grants?(catalog, ["webhooks.*"], "documents.read")
    end

    test "full wildcard grants every concrete catalog entry", %{catalog: catalog} do
      for scope <- Scope.entries(catalog) do
        assert Scope.grants?(catalog, ["*"], scope), "expected * to cover #{inspect(scope)}"
      end
    end

    test "full wildcard does NOT grant an uncatalogued required scope", %{catalog: catalog} do
      # A required scope that is not in the catalog (a typo, or an endpoint
      # declaring a scope nobody catalogued) must never be authorized, even
      # by a *-granted system credential. The catalog is the authority.
      refute Scope.grants?(catalog, ["*"], "totally.fake")
      refute Scope.grants?(catalog, ["*"], "documents.write")
      refute Scope.grants?(catalog, ["*"], "")
    end

    test "resource-level wildcard for an unknown resource grants nothing", %{catalog: catalog} do
      refute Scope.grants?(catalog, ["fleet.*"], "documents.read")
    end

    test "resource-level wildcard does not grant an uncatalogued concrete scope", %{
      catalog: catalog
    } do
      # documents.* is a valid grant form, but "documents.write" is not in
      # the catalog and so must not be grantable via the wildcard.
      refute Scope.grants?(catalog, ["documents.*"], "documents.write")
    end

    test "deep-wildcard grant entries grant nothing", %{catalog: catalog} do
      refute Scope.grants?(catalog, ["documents.read.*"], "documents.read")
      refute Scope.grants?(catalog, ["webhooks.read.*"], "webhooks.read")
    end
  end

  describe "grants?/3 - input edges" do
    test "nil grant list grants nothing", %{catalog: catalog} do
      refute Scope.grants?(catalog, nil, "documents.read")
    end

    test "empty grant list grants nothing", %{catalog: catalog} do
      refute Scope.grants?(catalog, [], "documents.read")
    end

    test "required wildcards are always rejected", %{catalog: catalog} do
      refute Scope.grants?(catalog, ["*"], "*")
      refute Scope.grants?(catalog, ["documents.*"], "documents.*")
      refute Scope.grants?(catalog, ["*"], "documents.*")
    end

    test "non-string required scope returns false", %{catalog: catalog} do
      refute Scope.grants?(catalog, ["documents.read"], nil)
      refute Scope.grants?(catalog, ["documents.read"], :documents_read)
    end

    test "garbage entries in the grant list are ignored, not crashing", %{catalog: catalog} do
      assert Scope.grants?(catalog, ["nope", nil, :documents_read, "documents.read"], "documents.read")
      refute Scope.grants?(catalog, ["nope", nil, :documents_read], "documents.read")
    end
  end

  describe "grants_all?/3" do
    test "true when every required scope is granted", %{catalog: catalog} do
      assert Scope.grants_all?(
               catalog,
               ["documents.read", "positions.read"],
               ["documents.read", "positions.read"]
             )
    end

    test "false when any required scope is missing", %{catalog: catalog} do
      refute Scope.grants_all?(catalog, ["documents.read"], ["documents.read", "positions.read"])
    end

    test "wildcard grant covers multiple required scopes", %{catalog: catalog} do
      assert Scope.grants_all?(catalog, ["webhooks.*"], ["webhooks.read", "webhooks.write"])
    end

    test "raises on a nil required list (fail-loud against a misconfigured endpoint)", %{
      catalog: catalog
    } do
      assert_raise ArgumentError, ~r/requires at least one required scope/, fn ->
        Scope.grants_all?(catalog, ["documents.read"], nil)
      end
    end

    test "raises on an empty required list (fail-loud against a misconfigured endpoint)", %{
      catalog: catalog
    } do
      assert_raise ArgumentError, ~r/requires at least one required scope/, fn ->
        Scope.grants_all?(catalog, ["documents.read"], [])
      end

      assert_raise ArgumentError, ~r/requires at least one required scope/, fn ->
        Scope.grants_all?(catalog, [], [])
      end

      assert_raise ArgumentError, ~r/requires at least one required scope/, fn ->
        Scope.grants_all?(catalog, nil, [])
      end
    end
  end

  describe "unknown/2" do
    test "returns scopes that are not valid customer-facing grant forms", %{catalog: catalog} do
      assert Scope.unknown(catalog, ["documents.read", "fleet.*", "totally.fake"]) ==
               ["fleet.*", "totally.fake"]
    end

    test "the full wildcard is reported as unknown (customer-facing rejects it)", %{
      catalog: catalog
    } do
      assert Scope.unknown(catalog, ["*"]) == ["*"]
      assert Scope.unknown(catalog, ["documents.read", "*"]) == ["*"]
    end

    test "valid resource-level wildcards are NOT reported as unknown", %{catalog: catalog} do
      assert Scope.unknown(catalog, ["webhooks.*"]) == []
    end

    test "deep wildcards are reported as unknown", %{catalog: catalog} do
      assert Scope.unknown(catalog, ["documents.read.*"]) == ["documents.read.*"]
    end

    test "empty list is empty", %{catalog: catalog} do
      assert Scope.unknown(catalog, []) == []
    end

    test "nil is empty", %{catalog: catalog} do
      assert Scope.unknown(catalog, nil) == []
    end

    test "preserves the order of the input", %{catalog: catalog} do
      assert Scope.unknown(catalog, ["bad1", "documents.read", "bad2"]) == ["bad1", "bad2"]
    end
  end

  describe "grants_all?/3 — indexed form equivalence and complexity" do
    setup do
      %{catalog: Scope.new_catalog(Enum.map(1..200, &"res#{&1}.read") ++ Enum.map(1..200, &"res#{&1}.write"))}
    end

    # The indexed grants_all?/3 must agree with the naive per-required
    # Enum.all?(grants?/3) form on every input. Cover exact, resource-wildcard,
    # full-wildcard, unknown, and mixed granted sets.
    test "agrees with the naive Enum.all?(grants?) form", %{catalog: catalog} do
      naive = fn granted, required -> Enum.all?(required, &Scope.grants?(catalog, granted, &1)) end

      granted_sets = [
        ["res1.read", "res2.read"],
        ["res1.*"],
        ["*"],
        ["res1.*", "res2.write", "res3.read"],
        ["res1.read", "nonsense", "res5.*", "*"],
        [],
        ["res1.read", 123, nil, "res2.*"]
      ]

      required_sets = [
        ["res1.read"],
        ["res1.read", "res1.write"],
        ["res2.read", "res3.read"],
        ["res1.read", "res200.write"],
        ["uncatalogued.read"],
        ["res1.*"],
        ["res1.read", "res2.read", "res5.write"]
      ]

      for granted <- granted_sets, required <- required_sets, required != [] do
        assert Scope.grants_all?(catalog, granted, required) == naive.(granted, required),
               "mismatch: granted=#{inspect(granted)} required=#{inspect(required)}"
      end
    end

    # The bug this replaced: a large caller-supplied required list is a DoS
    # lever. Indexed form is O(|granted| + |required|), so 500k required
    # scopes must stay well under a second - and 10x the input stays ~10x the
    # time, not ~100x.
    @tag :timing
    test "stays linear as the required list grows", %{catalog: catalog} do
      granted = Enum.map(1..200, &"res#{&1}.read")
      # Build the inputs OUTSIDE the timer: constructing a 500k-element list of
      # interpolated strings is itself superlinear in wall-clock (GC), and timing
      # it alongside the call is what made an earlier measurement look
      # superlinear when the function is not.
      r_50k = Enum.map(1..50_000, fn i -> "res#{rem(i, 200) + 1}.read" end)
      r_500k = Enum.map(1..500_000, fn i -> "res#{rem(i, 200) + 1}.read" end)

      # Warm the module so the first call does not pay load cost.
      Scope.grants_all?(catalog, granted, r_50k)

      {us_50k, true} = :timer.tc(fn -> Scope.grants_all?(catalog, granted, r_50k) end)
      {us_500k, true} = :timer.tc(fn -> Scope.grants_all?(catalog, granted, r_500k) end)

      # Absolute bound: the pre-fix code took ~20s at 500k; linear is ~40ms.
      # 500ms is a wide margin that still catches a regression to superlinear.
      assert us_500k < 500_000, "500k scopes took #{Float.round(us_500k / 1000, 1)}ms; expected < 500ms"

      # 10x the input must give ~10x the time, not the ~20x the superlinear
      # scan showed. 15x leaves headroom for noise while still failing on a
      # return to quadratic-ish behaviour.
      ratio = us_500k / max(us_50k, 1)
      assert ratio < 15, "10x input gave #{Float.round(ratio, 1)}x time; expected ~linear (<15x)"
    end
  end
end
