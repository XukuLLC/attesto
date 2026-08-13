# Dialyzer warning suppressions. Attesto is hand-written with no generated
# code, so the only entries here are deliberate fail-closed default clauses
# on the JOSE boundary. JOSE's types declare its verification result exhaustive,
# but malformed input can escape as a different term at runtime. These clauses
# convert that gap to an opaque verification error instead of crashing.
[
  {"lib/attesto/request_object.ex", :pattern_match_cov},
  {"lib/attesto/jws.ex", :pattern_match_cov, {275, 7}}
]
