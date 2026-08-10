# UrlCrawler

UrlCrawler is a Go-based security scanning web application designed to run reconnaissance and analysis for a given target URL. It integrates and automates the execution of several popular security tools:

- **Nmap**: Active port scanning to discover exposed services.
- **Assetfinder**: Passive DNS subdomain enumeration for mapping target assets.
- **Nuclei**: Active vulnerability scanning using customizable templates.

---

## Project Background

This project was developed during the author's internship period (prior to the widespread adoption of AI coding assistants) through entirely manual research and implementation. Providing a simple web dashboard to trigger security tools (Nmap, Nuclei, Assetfinder), this project served as the initial inspiration and laid the groundwork for the more advanced **Mangudai ASM (Attack Surface Management)** platform.

---

## Requirements

To run this application locally, you must have the following tools installed and added to your system's environment variables (PATH):

- Go compiler (1.18+)
- **Nmap**: For port scanning.
- **Assetfinder**: For subdomain discovery.
- **Nuclei**: For vulnerability scanning.

---

## Installation & Running

1. Clone the repository and build the binary:
   ```bash
   go build -o UrlCrawler
   ```

2. Start the web server:
   ```bash
   ./UrlCrawler
   ```

3. Open your browser and navigate to **`http://localhost:8000`** to access the web panel and start scanning targets.

---

## Contributing

If you would like to contribute to this project, please open an Issue or submit a Pull Request. All contributions are welcome!

---

## Contact

For questions and feedback:
- **Email**: bilge.oktay.944@gmail.com
- **GitHub**: [@oktaybilge1](https://github.com/oktaybilge1)
