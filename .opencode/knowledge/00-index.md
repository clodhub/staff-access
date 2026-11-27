# staff-access ownership

Repository: https://github.com/clodhub/staff-access.git.
Current code: `implementation/server/access.ts`, `implementation/server/cookies.ts`, `implementation/server/index.ts`, `implementation/server/settings.ts`.
`component.json`, `tools.lock.json` and `visual/` are generated from `authoring/spec.json`. Licence documents belong to their respective authors and are included as supplied. `CONTRACT.md`, `INSTRUCTIONS.md` and `SOURCE.md` are hand-written and kept on regeneration.
Every artefact installs under `components/staff-access/`, which clod places at `components/<slot id>/` of the application; other code reaches this component only through the entry modules in each interface document's `x-clodhub-modules` (paths relative to the component root; set by the scaffolder from `spec.modules`, or from `implementation/<platform>/index.ts` and the native source folders).
