defmodule Attesto.PairwiseSubjectTest do
  use ExUnit.Case, async: true

  alias Attesto.PairwiseSubject

  @salt String.duplicate("s", 32)

  describe "sector_identifier/1" do
    test "is the lowercased host every redirect URI shares" do
      assert {:ok, "rp.example"} =
               PairwiseSubject.sector_identifier(["https://RP.example/cb", "https://rp.example:8443/other"])
    end

    test "refuses redirect URIs that span hosts, have no host, or are absent" do
      assert {:error, :multiple_hosts} =
               PairwiseSubject.sector_identifier(["https://a.example/cb", "https://b.example/cb"])

      assert {:error, :invalid_redirect_uri} = PairwiseSubject.sector_identifier(["https://a.example/cb", "urn:x"])
      assert {:error, :no_redirect_uris} = PairwiseSubject.sector_identifier([])
      assert {:error, :no_redirect_uris} = PairwiseSubject.sector_identifier(nil)
    end
  end

  describe "derive/3" do
    test "is deterministic and differs by sector, subject and salt" do
      sub = PairwiseSubject.derive("rp.example", "usr_1", @salt)

      assert sub == PairwiseSubject.derive("rp.example", "usr_1", @salt)
      assert sub =~ ~r/\A[A-Za-z0-9_-]{43}\z/
      refute sub == PairwiseSubject.derive("other.example", "usr_1", @salt)
      refute sub == PairwiseSubject.derive("rp.example", "usr_2", @salt)
      refute sub == PairwiseSubject.derive("rp.example", "usr_1", String.duplicate("t", 32))
      refute sub =~ "usr_1"
    end

    test "sector and subject cannot be shifted into one another" do
      refute PairwiseSubject.derive("rp.example", "x-usr", @salt) ==
               PairwiseSubject.derive("rp.examplex", "-usr", @salt)
    end

    test "refuses a short salt or empty inputs" do
      assert PairwiseSubject.valid_salt?(@salt)
      refute PairwiseSubject.valid_salt?(String.duplicate("s", 31))
      refute PairwiseSubject.valid_salt?(nil)

      for {sector, subject, salt} <- [{"rp.example", "usr_1", "short"}, {"", "usr_1", @salt}, {"rp.example", "", @salt}] do
        assert_raise ArgumentError, fn -> PairwiseSubject.derive(sector, subject, salt) end
      end
    end
  end
end
