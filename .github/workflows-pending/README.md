# Pending CI workflow

`ci.yml` here is the GitHub Actions CI workflow (install, typecheck, lint,
format check, test, build on Node 22 and 24 for every push and PR).

It couldn't be pushed to `.github/workflows/` because the automation token
lacks the `workflow` scope. To activate it:

```sh
git mv .github/workflows-pending/ci.yml .github/workflows/ci.yml
git rm .github/workflows-pending/README.md
git commit -m "ci: enable GitHub Actions" && git push
```
