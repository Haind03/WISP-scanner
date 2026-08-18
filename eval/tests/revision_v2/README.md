# revision-v2 regression tests

Seven tests that **reproduce** the current methodological and data bugs of the WISP
Computers & Security submission. Each test asserts the *desired* (post-fix) invariant, so it
**fails while the bug is present**. Do not weaken an assertion to make it green — the fix belongs in
the production code, and these tests should flip to PASS once it lands.

## Run

```
cd /mnt/d/System-ScanInfosec/wisp-artifact
python3 -m eval.tests.revision_v2.run_all      # reporter; exit 0 == all bugs reproduced (pre-fix baseline)
# or, if pytest is installed:
python3 -m pytest eval/tests/revision_v2 -q     # expect 7 FAILED at the pre-fix baseline
```

The reproduction data (`filled_A.csv`, `filled_B.csv`, `matched_100_baselines_final.json`) is read
from `final/supplementary-data/reproduce/data/`; override with `WISP_REVISION_DATA`.

## The bugs

| Test | Bug | Fails because |
|---|---|---|
| A `test_a_patch_truncation` | `_patch_hunk(..., limit=28)` truncates silently | reviewers' patch hunk omits the finding's changed line for 4 real findings, no truncated flag |
| B `test_b_identifier_collision` | `finding_id = sha1(slug\|tool\|file\|line)` | 200 rows collapse to 191 unique ids (9 collisions) |
| C `test_c_construct_contamination` | bottom rung not class-agnostic | 165/200 cross-class rows, all auto-UR by both reviewers |
| D `test_d_timeout_provenance` | Progpilot cap mismatch | scored run used 60 s, manuscript claims 25 s |
| E `test_e_sanitizer_default` | `WISP_SANI_CLASS` default `"1"` | propagation ON by default, prose says off |
| F `test_f_fixpoint_completion` | non-convergence dropped | `_stabilize_summaries` bool discarded; `summaries_complete=True` hard-coded |
| G `test_g_bundle_provenance` | provenance rewritten post-hoc | `update-final.sh` sec 6e `sed -i` edits commit/hash in shipped JSON |

No production code is modified by these tests.
