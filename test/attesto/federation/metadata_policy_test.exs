defmodule Attesto.Federation.MetadataPolicyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Federation.MetadataPolicy

  test "value assigns a value or removes the parameter" do
    assert {:ok, %{"subject_type" => "pairwise"}} =
             MetadataPolicy.apply(
               %{"subject_type" => %{"value" => "pairwise"}},
               %{"subject_type" => "public"}
             )

    assert {:ok, %{}} =
             MetadataPolicy.apply(
               %{"subject_type" => %{"value" => nil}},
               %{"subject_type" => "public"}
             )
  end

  test "add unions array values without duplicates" do
    assert {:ok, %{"contacts" => ["leaf@example", "superior@example"]}} =
             MetadataPolicy.apply(
               %{"contacts" => %{"add" => ["leaf@example", "superior@example"]}},
               %{"contacts" => ["leaf@example"]}
             )
  end

  test "default only initializes an absent parameter" do
    policy = %{"grant_types" => %{"default" => ["authorization_code"]}}

    assert {:ok, %{"grant_types" => ["authorization_code"]}} = MetadataPolicy.apply(policy, %{})

    assert {:ok, %{"grant_types" => ["refresh_token"]}} =
             MetadataPolicy.apply(policy, %{"grant_types" => ["refresh_token"]})
  end

  test "one_of checks a present scalar" do
    policy = %{"token_endpoint_auth_method" => %{"one_of" => ["private_key_jwt", "tls_client_auth"]}}

    assert {:ok, %{"token_endpoint_auth_method" => "private_key_jwt"}} =
             MetadataPolicy.apply(policy, %{"token_endpoint_auth_method" => "private_key_jwt"})

    assert {:error, :policy_error} =
             MetadataPolicy.apply(policy, %{"token_endpoint_auth_method" => "client_secret_basic"})
  end

  test "subset_of intersects array values, including to an empty array" do
    policy = %{"response_types" => %{"subset_of" => ["code", "id_token"]}}

    assert {:ok, %{"response_types" => ["code"]}} =
             MetadataPolicy.apply(policy, %{"response_types" => ["code", "token"]})

    assert {:ok, %{"response_types" => []}} =
             MetadataPolicy.apply(policy, %{"response_types" => ["token"]})
  end

  test "superset_of requires all configured values" do
    policy = %{"grant_types" => %{"superset_of" => ["authorization_code"]}}

    assert {:ok, %{"grant_types" => ["authorization_code", "refresh_token"]}} =
             MetadataPolicy.apply(policy, %{"grant_types" => ["authorization_code", "refresh_token"]})

    assert {:error, :policy_error} = MetadataPolicy.apply(policy, %{"grant_types" => ["refresh_token"]})
  end

  test "essential requires the metadata parameter to be present" do
    policy = %{"jwks_uri" => %{"essential" => true}}

    assert {:ok, %{"jwks_uri" => "https://rp.example/jwks"}} =
             MetadataPolicy.apply(policy, %{"jwks_uri" => "https://rp.example/jwks"})

    assert {:error, :policy_error} = MetadataPolicy.apply(policy, %{})
  end

  test "rejects disallowed and conditionally conflicting operator combinations" do
    assert {:error, :policy_error} =
             MetadataPolicy.apply(
               %{"method" => %{"add" => ["a"], "one_of" => ["a"]}},
               %{"method" => ["a"]}
             )

    assert {:error, :policy_error} =
             MetadataPolicy.apply(
               %{"method" => %{"value" => "a", "one_of" => ["b"]}},
               %{}
             )
  end

  test "merges compatible superior and lower policies by each operator's rule" do
    higher = %{
      "contacts" => %{"add" => ["anchor@example"], "subset_of" => ["anchor@example", "leaf@example"]},
      "method" => %{"one_of" => ["a", "b"]},
      "jwks_uri" => %{"essential" => false}
    }

    lower = %{
      "contacts" => %{"add" => ["anchor@example"], "subset_of" => ["anchor@example"]},
      "method" => %{"one_of" => ["b", "c"]},
      "jwks_uri" => %{"essential" => true}
    }

    assert {:ok, merged} = MetadataPolicy.merge(higher, lower)
    assert merged["contacts"]["add"] == ["anchor@example"]
    assert merged["contacts"]["subset_of"] == ["anchor@example"]
    assert merged["method"]["one_of"] == ["b"]
    assert merged["jwks_uri"]["essential"]
  end

  test "fails an incompatible policy merge" do
    assert {:error, :policy_error} =
             MetadataPolicy.merge(
               %{"subject_type" => %{"value" => "pairwise"}},
               %{"subject_type" => %{"value" => "public"}}
             )

    assert {:error, :policy_error} =
             MetadataPolicy.merge(
               %{"method" => %{"one_of" => ["a"]}},
               %{"method" => %{"one_of" => ["b"]}}
             )
  end

  test "ignores an unknown non-critical extension operator" do
    higher = %{"client_name" => %{"regexp" => "^example"}}
    lower = %{"client_name" => %{"essential" => true}}

    assert {:ok, %{"client_name" => %{"essential" => true}}} =
             MetadataPolicy.merge(higher, lower)

    assert {:ok, %{"client_name" => "other"}} =
             MetadataPolicy.apply(higher, %{"client_name" => "other"})
  end
end
