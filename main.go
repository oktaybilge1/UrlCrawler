package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const dbFile = "tarama_sonuclari.db"

func main() {
	if err := createDatabase(); err != nil {
		log.Fatalf("Veritabanı oluşturulamadı: %s", err)
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/teknoloji-tarama", teknolojiTaramaHandler) // Yeni teknoloji tarama handler'ı
	http.HandleFunc("/process", processURLHandler)
	http.HandleFunc("/view", viewResultsHandler)

	fmt.Println("Web sunucusu başlatıldı. http://localhost:8000 adresinden erişebilirsiniz...")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func createDatabase() error {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return err
	}
	defer db.Close()

	createTableSQL := `
		CREATE TABLE IF NOT EXISTS tarama_sonuclari (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT NOT NULL,
			nmap TEXT,
			assetfinder TEXT,
			nuclei TEXT
		);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Println("Veritabanı tablosu oluşturulamadı:", err)
		return err
	}
	return nil
}

func teknolojiTaramaHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Sadece POST istekleri desteklenmektedir.", http.StatusMethodNotAllowed)
		return
	}

	url := r.FormValue("url")
	if url == "" {
		http.Error(w, "Geçerli bir URL girin.", http.StatusBadRequest)
		return
	}

	if !strings.HasPrefix(url, "www.") {
		http.Error(w, "URL, www ile başlamalıdır.", http.StatusBadRequest)
		return
	}

	// whatweb aracı ile teknoloji taraması yapma
	whatwebKomut := fmt.Sprintf("whatweb %s", url)
	teknolojiSonucu := runCommand(whatwebKomut)

	// Sonuçları yeni bir sayfada gösterme
	fmt.Fprintf(w, `
	<html>
	<head>
	<title>Teknoloji Tarama Sonuçları</title>
	</head>
	<body>
	<h1>Teknoloji Tarama Sonuçları</h1>
	<pre>%s</pre>
	<form action="/process" method="post">
		<input type="hidden" name="url" value="%s">
		<label for="scanType">Tarama Türleri:</label>
		<input type="checkbox" name="scanType" value="nmap">Nmap
		<input type="checkbox" name="scanType" value="assetfinder">Assetfinder
		<input type="checkbox" name="scanType" value="nuclei">Nuclei
		<br>
		<label for="selectedTemplates">Nuclei için seçilecek templateler:</label>
		<input type="checkbox" name="selectedTemplates" value="cves">CVE
		<input type="checkbox" name="selectedTemplates" value="dns">DNS
		<input type="checkbox" name="selectedTemplates" value="files">Files
		<input type="checkbox" name="selectedTemplates" value="generic-detections">Generic-detections
		<input type="checkbox" name="selectedTemplates" value="panels">Panels
		<input type="checkbox" name="selectedTemplates" value="subdomain-takeover">Subdomain-takeover
		<input type="checkbox" name="selectedTemplates" value="technologies">Technologies
		<input type="checkbox" name="selectedTemplates" value="tokens">Tokens
		<input type="checkbox" name="selectedTemplates" value="vulnerable">Vulnerable
		<br>
		<input type="submit" value="Taramayı Başlat">
	</form>
	</body>
	</html>
	`, teknolojiSonucu, url)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
	<html>
	<head>
	<title>URL Tarayıcı</title>
	</head>
	<body>
	<h1>URL Tarayıcı</h1>
	<form action="/teknoloji-tarama" method="post">
		<label for="url">URL:</label>
		<input type="text" name="url" id="url">
		<input type="submit" value="Teknoloji Taraması Yap">
	</form>
	</body>
	</html>
	`)
}

func processURLHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Sadece POST istekleri desteklenmektedir.", http.StatusMethodNotAllowed)
		return
	}

	url := r.FormValue("url")
	if url == "" {
		http.Error(w, "Geçerli bir URL girin.", http.StatusBadRequest)
		return
	}

	if !strings.HasPrefix(url, "www.") {
		http.Error(w, "URL, www ile başlamalıdır.", http.StatusBadRequest)
		return
	}

	r.ParseForm()
	scanTypes := r.Form["scanType"]
	selectedTemplates := r.Form["selectedTemplates"]

	if len(scanTypes) == 0 {
		http.Error(w, "En az bir tarama türü seçin.", http.StatusBadRequest)
		return
	}

	var output string
	var nmapDuration, assetfinderDuration, nucleiDuration time.Duration

	startTime := time.Now()

	for _, scanType := range scanTypes {
		switch scanType {
		case "nmap":
			nmapOutput := processNmap(url)
			output += nmapOutput + "\n\n"
			if nmapOutput != "" {
				nmapEndTime := time.Now()
				nmapDuration = nmapEndTime.Sub(startTime)
			}
		case "assetfinder":
			assetOutput := processAssetfinder(url)
			output += assetOutput + "\n\n"
			if assetOutput != "Tarama Sonuçları (Assetfinder):\nTarama sonucu bulunamadı.\n" {
				assetEndTime := time.Now()
				assetfinderDuration = assetEndTime.Sub(startTime)
			}
		case "nuclei":
			nucleiOutput := processNucleiWithSelectedTemplates(url, selectedTemplates)
			output += nucleiOutput + "\n\n"
			if nucleiOutput != "Tarama Sonuçları (Nuclei):\nZafiyet bulunamadı.\n" {
				nucleiEndTime := time.Now()
				nucleiDuration = nucleiEndTime.Sub(startTime)
			}
		}
	}

	endTime := time.Now()
	totalDuration := endTime.Sub(startTime)

	fmt.Fprintf(w, `
	<html>
	<head>
	<title>Tarama Sonuçları</title>
	</head>
	<body>
	<h1>Tarama Sonuçları</h1>
	<pre>%s</pre>
	<p>Nmap Tarama Süresi: %s</p>
	<p>Assetfinder Tarama Süresi: %s</p>
	<p>Nuclei Tarama Süresi: %s</p>
	<p>Toplam Tarama Süresi: %s</p>
	</body>
	</html>
	`, output, nmapDuration.String(), assetfinderDuration.String(), nucleiDuration.String(), totalDuration.String())

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Println("Veritabanına bağlanılamadı:", err)
		http.Error(w, "Veritabanına bağlanılamadı.", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	insertSQL := `
	INSERT INTO tarama_sonuclari (url, nmap, assetfinder, nuclei)
	VALUES (?, ?, ?, ?)
	`
	_, err = db.Exec(insertSQL, url, processNmap(url), processAssetfinder(url), processNucleiWithSelectedTemplates(url, selectedTemplates))

	if err != nil {
		log.Println("Sonuçlar kaydedilemedi:", err)
		return
	}

}

func processNucleiWithSelectedTemplates(url string, selectedTemplates []string) string {
	url = strings.TrimSpace(url)
	selectedTemplateFlags := strings.ToLower(strings.Join(selectedTemplates, ","))

	nucleiCommand := fmt.Sprintf("nuclei -t %s -u %s -c 10 --rate-limit 200 --timeout 300 --silent", selectedTemplateFlags, url)

	nucleiStartTime := time.Now()

	cmd := exec.Command("bash", "-c", nucleiCommand)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Hata: %s", err)
	}

	nucleiEndTime := time.Now()
	nucleiDuration := nucleiEndTime.Sub(nucleiStartTime)

	cleanedOutput := strings.ReplaceAll(string(output), "[", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "]", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "[\x1b[92m", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "\x1b[0m", "")

	re := regexp.MustCompile(`\[(.*?)\]`)
	zafiyetler := re.FindAllString(cleanedOutput, -1)

	result := "Tarama Sonuçları (Nuclei):\n"
	if len(zafiyetler) > 0 {
		for _, zafiyet := range zafiyetler {
			result += "- " + zafiyet + "\n"
		}
	} else {
		result += "Zafiyet bulunamadı.\n"
	}

	return fmt.Sprintf("%s\n\nNuclei Tarama Süresi: %s", result, nucleiDuration)
}

func hasNmapResult(output string) string {
	scanResultStart := "Nmap Sonucu:"
	startIndex := strings.Index(output, scanResultStart)
	if startIndex == -1 {
		return "Sonuç bulunamadı: Nmap"
	}
	endIndex := len(output)
	return output[startIndex:endIndex]
}

func hasAssetfinderResult(output string) string {
	scanResultStart := "Assetfinder Sonucu:"
	startIndex := strings.Index(output, scanResultStart)
	if startIndex == -1 {
		return "Sonuç bulunamadı: Assetfinder"
	}
	endIndex := strings.Index(output[startIndex:], "Nmap Sonucu:")
	if endIndex == -1 {
		return output[startIndex:]
	}
	return output[startIndex : startIndex+endIndex]
}

func hasNucleiResult(output string) string {
	scanResultStart := "Nuclei Sonucu:"
	startIndex := strings.Index(output, scanResultStart)
	if startIndex == -1 {
		return "Sonuç bulunamadı: Nuclei"
	}
	endIndex := strings.Index(output[startIndex:], "Assetfinder Sonucu:")
	if endIndex == -1 {
		return output[startIndex:]
	}
	return output[startIndex : startIndex+endIndex]
}

func viewResultsHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		http.Error(w, "Veritabanına bağlanılamadı.", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, url, nmap, assetfinder, nuclei FROM tarama_sonuclari")
	if err != nil {
		http.Error(w, "Sonuçlar alınamadı.", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	fmt.Fprint(w, `
	<html>
	<head>
	<title>Tarama Sonuçları</title>
	</head>
	<body>
	<h1>Tarama Sonuçları</h1>
	<table border="1">
		<tr>
			<th>ID</th>
			<th>URL</th>
			<th>Nmap</th>
			<th>Assetfinder</th>
			<th>Nuclei</th>
		</tr>
	`)
	for rows.Next() {
		var id int
		var url, nmap, assetfinder, nuclei string
		err := rows.Scan(&id, &url, &nmap, &assetfinder, &nuclei)
		if err != nil {
			http.Error(w, "Sonuçlar alınamadı.", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `
		<tr>
			<td>%d</td>
			<td>%s</td>
			<td><pre>%s</pre></td>
			<td><pre>%s</pre></td>
			<td><pre>%s</pre></td>
		</tr>
		`, id, url, nmap, assetfinder, nuclei)
	}
	fmt.Fprint(w, `
	</table>
	</body>
	</html>
	`)
}

func processNmap(url string) string {
	url = strings.TrimSpace(url)
	nmapCommand := fmt.Sprintf("nmap -Pn -p 80,443,22,21 %s -T3", url)
	output := runCommand(nmapCommand)

	cleanedOutput := strings.ReplaceAll(output, "[", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "]", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "\x1b[92m", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "\x1b[0m", "")

	return strings.TrimSpace(cleanedOutput)
}

func processAssetfinder(url string) string {
	url = strings.TrimSpace(url)
	assetfinderCommand := fmt.Sprintf("assetfinder %s", url)
	output := runCommand(assetfinderCommand)

	cleanedOutput := strings.ReplaceAll(output, "[", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "]", "")

	result := "Tarama Sonuçları (Assetfinder):\n"
	if cleanedOutput != "" {
		lines := strings.Split(cleanedOutput, "\n")
		for _, line := range lines {
			if line != "" {
				result += "- " + line + "\n"
			}
		}
	} else {
		result += "Tarama sonucu bulunamadı.\n"
	}

	return result
}

func processNuclei(url string) string {
	url = strings.TrimSpace(url)
	nucleiCommand := fmt.Sprintf("nuclei -t cves/ -t files/ -u %s -c 10 --rate-limit 200 --timeout 300 --silent", url)

	nucleiStartTime := time.Now()

	cmd := exec.Command("bash", "-c", nucleiCommand)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Hata: %s", err)
	}

	nucleiEndTime := time.Now()
	nucleiDuration := nucleiEndTime.Sub(nucleiStartTime)

	cleanedOutput := strings.ReplaceAll(string(output), "[", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "]", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "[\x1b[92m", "")
	cleanedOutput = strings.ReplaceAll(cleanedOutput, "\x1b[0m", "")

	re := regexp.MustCompile(`\[(.*?)\]`)
	zafiyetler := re.FindAllString(cleanedOutput, -1)

	result := "Tarama Sonuçları (Nuclei):\n"
	if len(zafiyetler) > 0 {
		for _, zafiyet := range zafiyetler {
			result += "- " + zafiyet + "\n"
		}
	} else {
		result += "Zafiyet bulunamadı.\n"
	}

	return fmt.Sprintf("%s\n\nNuclei Tarama Süresi: %s", result, nucleiDuration)
}

func runCommand(command string) string {
	cmd := exec.Command("bash", "-c", command)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Hata: %s", err)
	}

	return strings.TrimSpace(string(output))
}
