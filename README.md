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
4. **Find your report:**
   - To print the report in the console, include the flag `--print-report`
   - For example, to run this on caddy server:
     ```sh
     docker build -t verifier:01 .  
     docker run verifier:01 https://github.com/caddyserver/caddy --print-report
     ```
     
Open the JSON file to see the results! 
