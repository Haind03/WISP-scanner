# Defect-level study: the labels behind the one human number in the paper

Every geometric rate in the paper is computed from the vendor diff and needs no human judgment.
One number does need it: the rate at which a finding names the defect the vendor actually fixed.
This directory carries the labels that number is computed from, so it can be checked rather than
taken on trust.

## Files

| File | What it is |
|---|---|
| `defect_study_labels.csv` | 200 sampled findings, both annotators' five axes each, plus the geometry of the same finding |
| `DEFECT_STUDY_SAMPLE_V3.json` | the stratified draw: seed, strata, per-stratum counts, the sampled finding ids |
| `ANNOTATOR_METADATA.json` | each annotator's pseudonymous declaration of expertise, independence and conflict |
| `LOCKED-SHA256.txt` | the content hashes of the two returned workbooks, taken before anything was scored |
| `reconciliation_returned_excluded.xlsx` | the joint reconciliation of the 55 disputed findings, which is **excluded** from the result and ships so the exclusion can be checked |
| `reconciliation_working_note_excluded.txt` | the working note from that session, which is the evidence for excluding it |

## Recompute the paper's numbers

    python3 -m eval.defect_study_result_v3

reads these labels and writes `DEFECT_STUDY_RESULT_V3.json`, from which the manuscript's macros are
built. `python3 -m eval.reproduce_all_v3` runs it as the `defect_study` target and compares the
result against the shipped one.

## What the columns mean

`A_*` and `B_*` are the two annotators. They labelled independently, from packets carrying neither
the producing tool nor any geometric field, after each had first written their own description of
the vendor's defect from the advisory and the uncut diff.

`in_patched_file`, `same_callable_as_change` and `on_exact_changed_line` are the geometry of the same
finding. They are included here so a reader can compare the two measures directly. They were **not**
shown to the annotators, and that withholding is the point: the study exists to test whether patch
geometry overstates defect identification, so a label derived from the geometry could not be
evidence about the geometry.

## Two things this directory does not contain

The tool identity per packet stays sealed outside this directory, except as the `tool` column here,
which is published only now that labelling is closed.

The joint reconciliation of the 55 root-cause disagreements is not applied. It was held, and it was
excluded: it returned one value on all 41 it resolved, adopted one annotator on all 41, and its
working note shows the rows were pre-sorted by patch geometry computed outside the blinded packets.
The disagreements are reported as unresolved instead. Including the reconciliation moves the pooled
rate by 0.005. The supplement gives the full reasoning.

Excluded is not the same as hidden. Both files ship here, so the counts the supplement prints about
that session (41 of 55 resolved, one value on all 41, one annotator adopted on all 41, and the 0.005
the exclusion costs) are recomputed by the scorer rather than restated, and a reader can open the
workbook and disagree with us. Until this revision the workbook sat outside the bundle, the scorer
found nothing where it looked, and those four numbers were the one part of the study a reader could
not check. The working note is in Vietnamese, the language the session was held in. Its content is
checkable without reading it: for each row it records whether the finding's file carried a patched
line, which is `in_patched_file` in `defect_study_labels.csv`, and that is the field the blinded
packets withhold.

## Pseudonyms

Annotators are `A` and `B` throughout. No real name, affiliation or contact appears in any file here.
Annotator A declared knowledge of the study's objective and annotator B did not, which is why the
paper reports B as the primary reading and places A beside it.
