# Verifier Service

This tool checks a Go project for lint, formatting, vulnerabilities, and more, then generates a JSON report.

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
