defmodule Attesto.StepUpTest do
  use ExUnit.Case, async: true

  alias Attesto.StepUp
  alias Attesto.StepUp.Requirement

  @now 1_700_000_000

  describe "Requirement.parse/1" do
    test "builds from a keyword list" do
      assert %Requirement{acr_values: ["phr"], max_age: 300} =
               Requirement.parse(acr_values: ["phr"], max_age: 300)
    end

    test "accepts acr-only and max_age-only" do
      assert %Requirement{acr_values: ["phr"], max_age: nil} = Requirement.parse(acr_values: ["phr"])
      assert %Requirement{acr_values: [], max_age: 0} = Requirement.parse(max_age: 0)
    end

    test "raises when neither dimension is constrained" do
      assert_raise ArgumentError, ~r/must constrain/, fn -> Requirement.parse([]) end
    end

    test "raises on a malformed max_age" do
      assert_raise ArgumentError, ~r/max_age/, fn -> Requirement.parse(max_age: -1) end
      assert_raise ArgumentError, ~r/max_age/, fn -> Requirement.parse(max_age: "5") end
    end

    test "raises on an acr value that could break out of the challenge quoted-string" do
      for bad <- ["", "a b", ~s(a"b), "a,b", "a\\b"] do
        assert_raise ArgumentError, ~r/acr_values/, fn -> Requirement.parse(acr_values: [bad]) end
      end
    end
  end

  describe "satisfied?/3 — acr set membership" do
    test "token acr in the accepted set passes; absent/other fails closed" do
      req = Requirement.parse(acr_values: ["phr", "phrh"])
      assert StepUp.satisfied?(req, %{"acr" => "phr"}, @now)
      refute StepUp.satisfied?(req, %{"acr" => "pwd"}, @now)
      refute StepUp.satisfied?(req, %{}, @now)
      refute StepUp.satisfied?(req, %{"acr" => 1}, @now)
    end
  end

  describe "satisfied?/3 — auth_time freshness" do
    test "auth_time within max_age passes; stale/absent fails closed" do
      req = Requirement.parse(max_age: 300)
      assert StepUp.satisfied?(req, %{"auth_time" => @now - 100}, @now)
      assert StepUp.satisfied?(req, %{"auth_time" => @now}, @now)
      refute StepUp.satisfied?(req, %{"auth_time" => @now - 301}, @now)
      refute StepUp.satisfied?(req, %{}, @now)
      refute StepUp.satisfied?(req, %{"auth_time" => "old"}, @now)
    end

    test "max_age: 0 forces a just-now authentication" do
      req = Requirement.parse(max_age: 0)
      assert StepUp.satisfied?(req, %{"auth_time" => @now}, @now)
      refute StepUp.satisfied?(req, %{"auth_time" => @now - 1}, @now)
    end
  end

  describe "satisfied?/3 — conjunction (RFC 9470 §4)" do
    test "both acr AND auth_time must hold" do
      req = Requirement.parse(acr_values: ["phr"], max_age: 300)
      assert StepUp.satisfied?(req, %{"acr" => "phr", "auth_time" => @now - 100}, @now)
      # acr ok but stale
      refute StepUp.satisfied?(req, %{"acr" => "phr", "auth_time" => @now - 999}, @now)
      # fresh but wrong acr
      refute StepUp.satisfied?(req, %{"acr" => "pwd", "auth_time" => @now}, @now)
    end
  end

  describe "evaluate/3" do
    test "ok when satisfied" do
      req = Requirement.parse(acr_values: ["phr"], max_age: 300)
      assert :ok = StepUp.evaluate(req, %{"acr" => "phr", "auth_time" => @now}, @now)
    end

    test "returns the challenge params naming what to re-request" do
      req = Requirement.parse(acr_values: ["phr", "phrh"], max_age: 300)

      assert {:error, :insufficient_user_authentication, %{acr_values: "phr phrh", max_age: 300}} =
               StepUp.evaluate(req, %{"acr" => "pwd"}, @now)
    end

    test "an acr-only requirement omits max_age from the challenge" do
      req = Requirement.parse(acr_values: ["phr"])
      assert {:error, :insufficient_user_authentication, challenge} = StepUp.evaluate(req, %{}, @now)
      assert challenge == %{acr_values: "phr"}
    end
  end
end
