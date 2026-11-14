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

      assert {:error, :invalid_redirect_uri} =
               PairwiseSubject.sector_identifier(["com.evil.app://victim-rp.example/cb"])

      assert {:error, :invalid_redirect_uri} = PairwiseSubject.sector_identifier(["http://rp.example/cb"])
      assert {:error, :invalid_redirect_uri} = PairwiseSubject.sector_identifier(["https://localhost/cb"])
      assert {:error, :invalid_redirect_uri} = PairwiseSubject.sector_identifier(["https://127.0.0.1/cb"])
      assert {:error, :invalid_redirect_uri} = PairwiseSubject.sector_identifier(["https://[::1]/cb"])
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

  describe "seal_subject/3 and unseal_subject/3" do
    test "round-trips with a matching pairwise_sub and salt, using distinct nonces" do
      pairwise = PairwiseSubject.derive("rp.example", "usr_1", @salt)
      sealed_a = PairwiseSubject.seal_subject("usr_1", pairwise, @salt)
      sealed_b = PairwiseSubject.seal_subject("usr_1", pairwise, @salt)

      refute sealed_a == sealed_b
      assert {:ok, "usr_1"} = PairwiseSubject.unseal_subject(sealed_a, pairwise, @salt)
      assert {:ok, "usr_1"} = PairwiseSubject.unseal_subject(sealed_b, pairwise, @salt)
      assert :error = PairwiseSubject.unseal_subject(sealed_a, "other_sub", @salt)
      assert :error = PairwiseSubject.unseal_subject(sealed_a, pairwise, String.duplicate("t", 32))
      assert :error = PairwiseSubject.unseal_subject("not-valid-base64!", pairwise, @salt)
    end

    test "pads short subjects to uniform blocks so ciphertexts do not leak subject length" do
      pairwise = PairwiseSubject.derive("rp.example", "usr_1", @salt)

      lengths =
        for n <- [1, 5, 17, 49, 62] do
          subject = String.duplicate("a", n)
          sealed = PairwiseSubject.seal_subject(subject, pairwise, @salt)
          assert {:ok, ^subject} = PairwiseSubject.unseal_subject(sealed, pairwise, @salt)
          byte_size(sealed)
        end

      assert length(Enum.uniq(lengths)) == 1

      for n <- [63, 64, 128] do
        subject = String.duplicate("b", n)
        sealed = PairwiseSubject.seal_subject(subject, pairwise, @salt)
        assert {:ok, ^subject} = PairwiseSubject.unseal_subject(sealed, pairwise, @salt)
      end
    end
  end
end
