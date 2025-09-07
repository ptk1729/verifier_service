# Verifier Service

This tool checks a Go project for lint, formatting, vulnerabilities, and more, then generates a JSON report.

in the below format:

<!-- josn format in markdown -->
```json
{
  "metadata": {
    "project_name": "go_proj",
    "repo_url": "/home/prateek/go_proj",
    "commit_hash": "3ac4624edbfe92303809956e8cd3f0368d56730d",
    "commit_message": "add verifier report as artifact",
    "checked_at": "2025-08-04T01:09:52Z",
    "verifier_version": "1.0.0",
    "run_id": "73d12923-e616-4235-bfdc-3941a053c190",
    "verification_status": "FAILED",
    "report_sha256": "03aaefde9a9b657de35755961060854c4a427b2cbdd3abf4f105e9479c165222"
  },
  "report": {
    "linting": {
      "status": "PASSED",
      "errors": null,
      "warnings": null,
      "tool": "go vet"
    },
    "formatting": {
      "status": "PASSED",
      "tool": "gofmt",
      "files_changed": null
    },
    "vulnerability_check": {
      "status": "PASSED",
      "tool": "osv-scanner",
      "vulnerabilities": null
    },
    "commit_verification": {
      "status": "FAILED",
      "commits_checked": [
        {
          "commit": "3ac4624edbfe92303809956e8cd3f0368d56730d",
          "author": "prateekrohilla4.pr@gmail.com",
          "key_id": "49D9F27E562A5A49",
          "verified": true
        },
        {
          "commit": "d71a4551d7ba63c4399d02cc0d94ddf14ad3bc4a",
          "author": "prateekrohilla4.pr@gmail.com",
          "key_id": "49D9F27E562A5A49",
          "verified": true
        },
        {
          "commit": "ba733188b4542eedb6269214b5e0ed60fec63781",
          "author": "prateekrohilla4.pr@gmail.com",
          "key_id": "49D9F27E562A5A49",
          "verified": true
        },
        {
          "commit": "79722c49a6fe0eef824b0205569ae518c20de27e",
          "author": "prateekrohilla4.pr@gmail.com",
          "key_id": "49D9F27E562A5A49",
          "verified": true
        },
        {
          "commit": "8f5429169bebda7074a36c3a709206ab53f1d828",
          "author": "prateekrohilla4.pr@gmail.com",
          "key_id": "49D9F27E562A5A49",
          "verified": true
        },
        {
          "commit": "c3649c404177717164f2d5ec9e740394e73638dc",
          "author": "prateekrohilla4.pr@gmail.com",
          "key_id": "49D9F27E562A5A49",
          "verified": true
        },
        {
          "commit": "8490ddddc80e8baa009c782fc34997da4d780f9e",
          "author": "prateekrohilla4.pr@gmail.com",
          "key_id": "49D9F27E562A5A49",
          "verified": true
        },
        {
          "commit": "1321fccb80ae933f08c2e901d5d61f7d81a903ce",
          "author": "prateekrohilla4.pr@gmail.com",
          "key_id": "49D9F27E562A5A49",
          "verified": true
        }
      ],
      "no_verified_commits": 31,
      "no_unverified_commits": 3
    },
    "env_variables_check": {
      "status": "PASSED",
      "issues": null
    },
    "custom_checks": [
      {
        "name": "Dockerfile Best Practices",
        "status": "SKIPPED",
        "details": []
      }
    ],
    "slsa_check": {
      "status": "FAILED",
      "binary_path": "~/go_proj/binary-linux-amd64/binary-linux-amd64",
      "provenance_path": "~/go_proj/binary-linux-amd64.intoto.jsonl/binary-linux-amd64.intoto.jsonl",
      "source_uri": "git+https://github.com/ptk1729/go_proj",
      "slsa_level": "",
      "missing_provenance": false,
      "error_message": "binary not found: stat ~/go_proj/binary-linux-amd64/binary-linux-amd64: no such file or directory",
      "verified_requirements": [
        {
          "name": "binary_exists",
          "status": "FAILED"
        }
      ]
    }
  }
}
```

## How to Run

1. **Build the program:**
   ```sh
   go build -o verifier main.go
   ```

2. **Run the verifier with your repo URL:**
   ```sh
   ./verifier https://github.com/yourusername/your-repo
   ```
   Or, if you want to run without building:
   ```sh
   go run main.go https://github.com/yourusername/your-repo
   ```

3. **Find your report:**
   - The report will be saved as a JSON file in the `/tmp` directory (e.g., `/tmp/report_20240510123456.json`).

## Individual Check Flags

You can run individual checks instead of the full report generation:

- **Linting check only:**
  ```sh
  ./verifier -lint https://github.com/yourusername/your-repo
  ```

- **Vulnerability check only:**
  ```sh
  ./verifier -vuln https://github.com/yourusername/your-repo
  ```

- **Formatting check only:**
  ```sh
  ./verifier -format https://github.com/yourusername/your-repo
  ```

- **Environment variables check only:**
  ```sh
  ./verifier -env https://github.com/yourusername/your-repo
  ```

- **Reviews check only:**
  ```sh
  ./verifier -reviews https://github.com/yourusername/your-repo
  ```

- **Custom checks only:**
  ```sh
  ./verifier -custom https://github.com/yourusername/your-repo
  ```

- **Commit verification check only:**
  ```sh
  ./verifier -commit -allowed-keys=KEY1,KEY2 https://github.com/yourusername/your-repo
  ```

## Additional Options

- **Print full report to console:**
  ```sh
  ./verifier -print-report https://github.com/yourusername/your-repo
  ```

- **Set required number of reviews:**
  ```sh
  ./verifier -required-reviews 3 https://github.com/yourusername/your-repo
  ```

- **Specify allowed GPG keys for commit verification:**
  ```sh
  ./verifier -allowed-keys=ABC123,DEF456 https://github.com/yourusername/your-repo
  ```

- **View all available flags:**
  ```sh
  ./verifier -h
  ```

## Docker Usage

For example, to run this on caddy server:
```sh
docker build -t verifier:01 .  
docker run verifier:01 https://github.com/caddyserver/caddy --print-report
```

Open the JSON file to see the results! 
