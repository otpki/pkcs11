# vendors/all

`vendors/all` returns every public vendor module compiled into this repository.
It is convenient for diagnostics, examples, and broad conformance runs.

Production services should usually pass only the vendor modules they expect to
use. A smaller list keeps module matching and native discovery more explicit.
