defmodule Attesto.ClientIdMetadata do
  @moduledoc """
  Client ID Metadata Documents - CIMD
  (`draft-ietf-oauth-client-id-metadata-document-01`, IETF OAuth WG).

  CIMD lets a client identify itself with no prior registration by using an
  HTTPS URL as its `client_id`. The authorization server dereferences that URL
  to fetch a JSON client metadata document - the RFC 7591 Dynamic Client
  Registration metadata field set - and uses it as the client.

  This module is the *pure*, conn-free, HTTP-free half of that feature: it
  decides whether a `client_id` is a CIMD URL (`client_id_url?/1`), validates
  the URL against the draft §2 grammar (`validate_client_id/1`), and validates a
  fetched document against the draft §2 content rules, normalizing it into the
  client shape attesto's resolution expects (`validate_document/2`). The
  load-bearing network half - the SSRF-guarded GET, redirect refusal, size cap,
  and caching - lives in the Phoenix layer; this module never touches a socket
  and pulls in no dependencies, the same discipline as
  `Attesto.AuthorizationRequest`.

  ## URL grammar (draft §2)

  A CIMD `client_id` MUST:

    * use the `https` scheme;
    * have a path component;
    * NOT contain a fragment;
    * NOT contain userinfo (a `user:password@` component);
    * NOT contain single-dot (`.`) or double-dot (`..`) path segments.

  Ports are allowed; a query is discouraged but allowed. A `client_id` that is
  not a binary, or does not parse as a URL, is not a CIMD client_id - it is an
  opaque identifier the host resolves through its own registry.

  ## Document content (draft §2)

  The fetched document's fields are the OAuth Dynamic Client Registration
  Metadata registry values (RFC 7591 §2). On top of that field set the draft
  requires:

    * a `client_id` member equal to the URL by simple string comparison
      (mismatch -> `{:error, :client_id_mismatch}`);
    * NO shared symmetric secret: `client_secret` / `client_secret_expires_at`
      MUST NOT be present (`{:error, :symmetric_secret}`), and
      `token_endpoint_auth_method` MUST NOT be one of `client_secret_basic`,
      `client_secret_post`, or `client_secret_jwt`
      (`{:error, :symmetric_auth_method}`) - a CIMD client authenticates as a
      public client (`none` + PKCE) or with `private_key_jwt`.

  RFC 9700 requires registered redirect URIs, so a CIMD document MUST carry a
  non-empty `redirect_uris` array of strings
  (`{:error, :invalid_redirect_uris}` otherwise).

  ## Normalized client shape

  `validate_document/2` returns a string-keyed map carrying the RFC 7591 §2
  client-metadata members the document supplied (`client_id`, `redirect_uris`,
  and any of `grant_types`, `response_types`, `scope`, `jwks`, `jwks_uri`,
  `client_name`, `client_uri`, `logo_uri`, `token_endpoint_auth_method`,
  `contacts`). The shape matches the validated metadata the RFC 7591
  registration path persists, so a CIMD client is consumed downstream (scope
  resolution, redirect match, JARM, DPoP) exactly like a registered one. Absent
  members are omitted rather than rendered as `nil`; an out-of-shape member
  (e.g. a `redirect_uris` that is not a list of strings) is a validation error,
  never silently dropped.
  """

  @https_scheme "https"

  # draft §2: a shared symmetric secret is incompatible with a public
  # `client_id` URL anyone may dereference, so these RFC 7591 §3.2.1 members
  # MUST NOT appear in the document.
  @symmetric_secret_members ~w(client_secret client_secret_expires_at)

  # draft §2 / RFC 7591 §2: the token-endpoint auth methods that rely on a
  # shared symmetric secret. A CIMD client MUST NOT use any of them; it
  # authenticates as a public client (`none`) or with `private_key_jwt`.
  @symmetric_auth_methods ~w(client_secret_basic client_secret_post client_secret_jwt)

  # RFC 7591 §2 client-metadata members carried through, with the shape each
  # must satisfy when present. `redirect_uris` is validated and required
  # separately (RFC 9700), so it is not in this passthrough table.
  @passthrough_members [
    {"grant_types", :string_array},
    {"response_types", :string_array},
    {"contacts", :string_array},
    {"scope", :string},
    {"client_name", :string},
    {"client_uri", :string},
    {"logo_uri", :string},
    {"jwks_uri", :string},
    {"token_endpoint_auth_method", :string},
    {"jwks", :map}
  ]

  @typedoc """
  A reason a `client_id` URL fails the draft §2 grammar.
  """
  @type url_error ::
          :not_a_url
          | :not_https
          | :no_path
          | :has_fragment
          | :has_userinfo
          | :dot_segments

  @typedoc """
  A reason a fetched document fails the draft §2 content rules.
  """
  @type document_error ::
          :client_id_mismatch
          | :symmetric_secret
          | :symmetric_auth_method
          | :invalid_redirect_uris
          | :invalid_metadata

  @doc """
  Returns `true` iff `value` is a CIMD `client_id`: a binary that parses as an
  HTTPS URL satisfying the draft §2 grammar (a path, and no fragment, userinfo,
  or single-/double-dot path segments).

  This is the fast, allocation-light predicate the resolver uses to decide
  whether a `client_id` is a CIMD URL before any network work; a `client_id`
  that is not a binary, or fails the grammar, returns `false`. For the specific
  failure reason use `validate_client_id/1`.
  """
  @spec client_id_url?(term()) :: boolean()
  def client_id_url?(value) when is_binary(value) do
    match?({:ok, _uri}, validate_client_id(value))
  end

  def client_id_url?(_value), do: false

  @doc """
  Validate a `client_id` against the CIMD URL grammar
  (`draft-ietf-oauth-client-id-metadata-document-01` §2).

  Returns `{:ok, %URI{}}` for a well-formed CIMD `client_id`, or
  `{:error, reason}` for the first rule it violates:

    * `:not_a_url` - not parseable as a URL with a host;
    * `:not_https` - the scheme is not `https`;
    * `:no_path` - no path component (or a bare `/` with nothing after it);
    * `:has_fragment` - a fragment is present;
    * `:has_userinfo` - a `user:password@` userinfo component is present;
    * `:dot_segments` - the path contains a single-dot (`.`) or double-dot
      (`..`) segment.

  The checks run in that order, so the returned reason is the first the URL
  fails. A query is permitted (discouraged by the draft, not rejected here).
  """
  @spec validate_client_id(String.t()) :: {:ok, URI.t()} | {:error, url_error()}
  def validate_client_id(client_id) when is_binary(client_id) do
    case URI.new(client_id) do
      {:ok, %URI{host: host} = uri} when is_binary(host) and host != "" ->
        validate_uri_grammar(uri)

      _ ->
        {:error, :not_a_url}
    end
  end

  # draft §2: the grammar checks, ordered so the returned reason is the first
  # rule the URL fails (scheme, then path, then fragment, then userinfo, then
  # the dot-segment ban).
  defp validate_uri_grammar(%URI{} = uri) do
    cond do
      uri.scheme != @https_scheme -> {:error, :not_https}
      not has_path?(uri.path) -> {:error, :no_path}
      not is_nil(uri.fragment) -> {:error, :has_fragment}
      not is_nil(uri.userinfo) -> {:error, :has_userinfo}
      has_dot_segment?(uri.path) -> {:error, :dot_segments}
      true -> {:ok, uri}
    end
  end

  # draft §2: a path component is REQUIRED. `URI.new/1` yields `nil` for an
  # absent path and `"/"` for a bare authority-only URL; neither carries a path
  # segment, so both fail the requirement.
  defp has_path?(path) when is_binary(path), do: path != "" and path != "/"
  defp has_path?(_path), do: false

  # draft §2: the path MUST NOT contain single-dot (`.`) or double-dot (`..`)
  # path segments. Splitting on "/" surfaces every segment, including the empty
  # strings a leading/trailing slash or "//" produces; only the exact "." and
  # ".." segments are forbidden.
  defp has_dot_segment?(path) do
    path
    |> String.split("/")
    |> Enum.any?(&(&1 in [".", ".."]))
  end

  @doc """
  Validate a fetched client metadata document against the draft §2 content
  rules and normalize it into attesto's client shape.

  `client_id` is the URL the document was fetched from (already validated by
  `validate_client_id/1`); `doc` is the decoded JSON object. Returns
  `{:ok, metadata}` - a string-keyed map carrying the validated, normalized
  RFC 7591 §2 metadata members - or `{:error, reason}`:

    * `:client_id_mismatch` - `doc["client_id"]` is not equal to `client_id` by
      simple string comparison (draft §2);
    * `:symmetric_secret` - `client_secret` or `client_secret_expires_at` is
      present (draft §2: no shared symmetric secret);
    * `:symmetric_auth_method` - `token_endpoint_auth_method` is one of
      `client_secret_basic`, `client_secret_post`, or `client_secret_jwt`
      (draft §2);
    * `:invalid_redirect_uris` - `redirect_uris` is absent, empty, or not a list
      of strings (RFC 9700 requires registered redirect URIs);
    * `:invalid_metadata` - a carried-through member is present with the wrong
      shape (e.g. a non-string `scope`, or a `grant_types` that is not a list of
      strings).

  The returned map always carries `client_id` and `redirect_uris`; any of the
  other RFC 7591 §2 members the document supplied
  (`grant_types`, `response_types`, `scope`, `jwks`, `jwks_uri`, `client_name`,
  `client_uri`, `logo_uri`, `token_endpoint_auth_method`, `contacts`) are
  carried through, and absent members are omitted.
  """
  @spec validate_document(String.t(), map()) ::
          {:ok, map()} | {:error, document_error()}
  def validate_document(client_id, doc) when is_binary(client_id) and is_map(doc) do
    with :ok <- validate_document_client_id(client_id, doc),
         :ok <- reject_symmetric_secret(doc),
         :ok <- reject_symmetric_auth_method(doc),
         {:ok, redirect_uris} <- validate_redirect_uris(doc),
         {:ok, passthrough} <- normalize_passthrough(doc) do
      metadata =
        passthrough
        |> Map.put("client_id", client_id)
        |> Map.put("redirect_uris", redirect_uris)

      {:ok, metadata}
    end
  end

  # draft §2: the document MUST contain a `client_id` equal to the URL it was
  # fetched from, by simple string comparison.
  defp validate_document_client_id(client_id, doc) do
    if Map.get(doc, "client_id") == client_id do
      :ok
    else
      {:error, :client_id_mismatch}
    end
  end

  # draft §2: a CIMD client holds no shared symmetric secret, so neither
  # `client_secret` nor `client_secret_expires_at` may appear in the document.
  defp reject_symmetric_secret(doc) do
    if Enum.any?(@symmetric_secret_members, &Map.has_key?(doc, &1)) do
      {:error, :symmetric_secret}
    else
      :ok
    end
  end

  # draft §2: `token_endpoint_auth_method` MUST NOT designate a shared-secret
  # method; a CIMD client is public (`none`) or uses `private_key_jwt`.
  defp reject_symmetric_auth_method(doc) do
    if Map.get(doc, "token_endpoint_auth_method") in @symmetric_auth_methods do
      {:error, :symmetric_auth_method}
    else
      :ok
    end
  end

  # RFC 9700: the AS MUST require registered redirect URIs and exact-match the
  # request's, so a CIMD document MUST carry a non-empty `redirect_uris` array
  # of strings. An absent, empty, or non-string-list value is rejected.
  #
  # Each URI must also be one every URL parser reads the same way
  # (`Attesto.RedirectURI.unambiguous?/1`). A CIMD document is fetched from a
  # URL the client chose, so its `redirect_uris` are attacker-supplied in a way
  # a host-registered set is not, and any origin-level policy applied to them
  # later - the draft's same-origin tightening, a deployment's allow-list - is
  # decided with an RFC 3986 parser but enforced by a browser using WHATWG
  # rules. Rejecting the ambiguity here means no such URI is ever in the set
  # those checks run against, which is the one place the two parsers cannot
  # already have diverged.
  defp validate_redirect_uris(doc) do
    case Map.get(doc, "redirect_uris") do
      [_ | _] = uris ->
        if Enum.all?(uris, &Attesto.RedirectURI.unambiguous?/1) do
          {:ok, uris}
        else
          {:error, :invalid_redirect_uris}
        end

      _ ->
        {:error, :invalid_redirect_uris}
    end
  end

  # RFC 7591 §2: carry through the KNOWN client-metadata members the document
  # supplied, each validated against the shape it must satisfy. An absent member
  # is omitted; a present member of the wrong shape stops normalization with
  # `:invalid_metadata`. Unknown members are dropped (never promoted to trusted
  # policy), matching the registration passthrough discipline.
  defp normalize_passthrough(doc) do
    Enum.reduce_while(@passthrough_members, {:ok, %{}}, fn {key, kind}, {:ok, acc} ->
      case normalize_member(doc, key, kind) do
        :absent -> {:cont, {:ok, acc}}
        {:ok, value} -> {:cont, {:ok, Map.put(acc, key, value)}}
        :error -> {:halt, {:error, :invalid_metadata}}
      end
    end)
  end

  defp normalize_member(doc, key, kind) do
    case Map.get(doc, key) do
      nil -> :absent
      value -> normalize_value(kind, value)
    end
  end

  defp normalize_value(:string, value) when is_binary(value), do: {:ok, value}

  defp normalize_value(:map, value) when is_map(value), do: {:ok, value}

  defp normalize_value(:string_array, value) when is_list(value) do
    if Enum.all?(value, &is_binary/1), do: {:ok, value}, else: :error
  end

  defp normalize_value(_kind, _value), do: :error
end
