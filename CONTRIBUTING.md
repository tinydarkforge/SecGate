# Contributing to SecGate

Thanks for your interest. SecGate is a security engine; contributions that improve detection fidelity, reduce false positives, or extend CI integration are especially welcome.

## Ground rules

- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Report security issues privately — see [SECURITY.md](SECURITY.md). Never open a public issue for a vulnerability.
- Open an issue before large changes so we can align on scope.

## Development setup

```bash
git clone https://github.com/tinydarkforge/SecGate.git
cd SecGate
npm install
node secgate.js --help
```

## Pull request checklist

- [ ] Branch name describes the change (`feat/<slug>`, `fix/<slug>`, `docs/<slug>`)
- [ ] Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`)
- [ ] New detectors or remediations include a short test fixture
- [ ] No secrets, tokens, or real scan artifacts committed
- [ ] README updated if CLI flags or output shape changed

## Commit message format

```
<type>(<scope>): <short description>

<optional body explaining why, not what>
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `security`, `perf`.

## Questions

Open a [discussion](https://github.com/tinydarkforge/SecGate/discussions) or a regular issue. Security matters go through private advisory only.
