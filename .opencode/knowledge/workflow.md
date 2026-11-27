# Local workflow

Repository: `clodhub/staff-access`. Licence: `Apache-2.0` (`LICENCE`, `NOTICE`).
Suite commands from the package root: `node --test tests/web.test.ts`.
Pack: `python3 -B -m clod pack . --store STORE`. Review: `python3 -B -m clod review DIGEST --store STORE --policy POLICY --trusted --allow-network`.
Always run Python with `-B`; never write bytecode into the repository.
Rebuild from the workspace root: `python3.12 -B recipes/webshop/authoring/build_shared.py staff-access` (scaffold, ClodHub's generate.py, required-interface sync, scaffolder and component checks, class suites, known vulnerabilities). Spec: `authoring/spec.json`; contract for every web shop component: `recipes/webshop/authoring/DESIGN.md`.
