# Start the Node.js worker pool ONCE, owned by this process, before ExUnit runs.
#
# `NodeJS.start_link/1` links the pool to whichever process calls it. Started
# lazily from inside a test, the pool is therefore linked to that test's
# process and dies with it, leaving the registered name briefly pointing at a
# dead pid - so the next test's `ensure_started!/0` sees `{:error,
# {:already_started, pid}}`, treats it as success, and then crashes on
# `:gen_server.call` with "no process". Owning it here instead means it is
# alive for the whole run, and every later `ensure_started!/0` is a genuine
# no-op.
#
# Guarded on availability so a machine without Node (or without the JS deps
# installed) still runs the rest of the suite; the parity modules self-skip.
case Attesto.Test.NodeBridge.availability() do
  :ok -> Attesto.Test.NodeBridge.ensure_started!()
  {:skip, _reason} -> :ok
end

ExUnit.start()
