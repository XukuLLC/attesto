defmodule Attesto.ResourceRoutes do
  @moduledoc "Root ownership policy for RFC 9728 resource metadata routes."

  @doc "Advance root ownership, raising if declarations leave an ambiguous root."
  def mount(root_choice, state \\ %{count: 0, mounted?: false, explicit?: false}) do
    count = state.count + 1
    mount? = decide_root(root_choice, count, state.mounted?, state.explicit?)

    {mount?,
     %{count: count, mounted?: state.mounted? or mount?, explicit?: state.explicit? or root_choice in [true, false]}}
  end

  defp decide_root(true, _count, true = _mounted?, _explicit?) do
    raise ArgumentError,
          "protected_resource_metadata: root: true was given for more than one resource, " <>
            "but only one resource may answer GET /.well-known/oauth-protected-resource."
  end

  defp decide_root(true, _count, _mounted?, _explicit?), do: true

  defp decide_root(false, count, true = _mounted?, false = _explicit?) when count > 1 do
    raise ArgumentError,
          "protected_resource_metadata: the root " <>
            "GET /.well-known/oauth-protected-resource document was auto-mounted for an earlier " <>
            "resource, so adding another resource with root: false would leave root ownership " <>
            "dependent on declaration order. Set root: true or root: false explicitly on the " <>
            "earlier resource before adding this declaration."
  end

  defp decide_root(false, _count, _mounted?, _explicit?), do: false

  # Single-resource convenience: auto-mount the root for the sole resource.
  defp decide_root(:auto, 1, _mounted?, _explicit?), do: true

  # A second-or-later resource with no explicit :root. If the root was
  # auto-mounted to the first resource it is now ambiguous - refuse rather than
  # silently publish an order-dependent root. If the host already chose the root
  # explicitly (root: true/false somewhere), this extra resource mounts nothing.
  defp decide_root(:auto, _count, true = _mounted?, false = _explicit?) do
    raise ArgumentError,
          "protected_resource_metadata: more than one protected resource is declared, so " <>
            "the root GET /.well-known/oauth-protected-resource document's resource is ambiguous. Pass " <>
            "root: true on the resource that should answer it (or root: false on each to serve no root)."
  end

  defp decide_root(:auto, _count, _mounted?, _explicit?), do: false
end
