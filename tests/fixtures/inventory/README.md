# Forge inventory answers

- `github-org-repos.jsonl`: `gh api --paginate "orgs/<org>/repos?type=sources&per_page=100" --jq '.[] | {url: .html_url, archived, visibility, fork}'` over a public org, recorded 2026-10-24; org and repo names replaced.
- `OWNERS.fixture`, `github-contributors.txt`: a public repository's OWNERS file (renamed so prow never reads it as a real OWNERS file) and `contributors?per_page=10` logins, recorded 2026-10-24; handles replaced (the two bot accounts keep their `-bot` / `-robot` suffixes).
- `gitlab-group-projects.json`: two `glab api --paginate` pages of `groups/<group>/projects`, written from the GitLab API's documented shape (no GitLab credentials when recorded); names are placeholders.
