package main

import (
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const dbFile = "tarama_sonuclari.db"

//go:embed web
var webFS embed.FS

var (
	tmpl = template.Must(template.ParseFS(webFS, "web/templates/*.html"))
	db   *sql.DB

	// Yalnızca www. ile başlayan, geçerli alan adları kabul edilir (komut enjeksiyonunu da engeller).
	hostRe  = regexp.MustCompile(`^www\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	ansiRe  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	scanSet = []string{"nmap", "assetfinder", "nuclei"}
	tplSet  = []string{"cves", "dns", "files", "generic-detections", "panels", "subdomain-takeover", "technologies", "tokens", "vulnerable"}
)

type scan struct{ Name, Output, Duration string }

type row struct {
	ID                             int
	URL, Nmap, Assetfinder, Nuclei string
}

type view struct {
	Title, Msg, URL, Output, Total string
	Templates                      []string
	Scans                          []scan
	Rows                           []row
}

func main() {
	var err error
	if db, err = sql.Open("sqlite3", dbFile); err != nil {
		log.Fatalf("Veritabanı açılamadı: %s", err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS tarama_sonuclari (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		url TEXT NOT NULL, nmap TEXT, assetfinder TEXT, nuclei TEXT)`)
	if err != nil {
		log.Fatalf("Veritabanı tablosu oluşturulamadı: %s", err)
	}

	static, _ := fs.Sub(webFS, "web/static")
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/teknoloji-tarama", teknolojiTaramaHandler)
	http.HandleFunc("/process", processURLHandler)
	http.HandleFunc("/view", viewResultsHandler)

	fmt.Println("Web sunucusu başlatıldı: http://localhost:8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func render(w http.ResponseWriter, name string, v view) {
	if err := tmpl.ExecuteTemplate(w, name, v); err != nil {
		log.Println("Şablon hatası:", err)
	}
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	render(w, "error", view{Title: "Hata", Msg: msg})
}

// target POST isteğinden URL'yi okur ve doğrular.
func target(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "Sadece POST istekleri desteklenmektedir.")
		return "", false
	}
	url := strings.TrimSpace(r.FormValue("url"))
	if url == "" {
		fail(w, http.StatusBadRequest, "Geçerli bir URL girin.")
		return "", false
	}
	if !hostRe.MatchString(url) {
		fail(w, http.StatusBadRequest, "URL, www ile başlayan geçerli bir alan adı olmalıdır (ör. www.ornek.com).")
		return "", false
	}
	return url, true
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		fail(w, http.StatusNotFound, "Sayfa bulunamadı.")
		return
	}
	render(w, "home", view{Title: "Ana Sayfa"})
}

func teknolojiTaramaHandler(w http.ResponseWriter, r *http.Request) {
	url, ok := target(w, r)
	if !ok {
		return
	}
	render(w, "tech", view{Title: "Teknoloji Taraması", URL: url, Output: runCommand("whatweb", url), Templates: tplSet})
}

func processURLHandler(w http.ResponseWriter, r *http.Request) {
	url, ok := target(w, r)
	if !ok {
		return
	}
	scanTypes := only(r.Form["scanType"], scanSet)
	if len(scanTypes) == 0 {
		fail(w, http.StatusBadRequest, "En az bir tarama türü seçin.")
		return
	}
	templates := only(r.Form["selectedTemplates"], tplSet)

	start := time.Now()
	results := map[string]string{}
	var scans []scan
	for _, t := range scanTypes {
		t0 := time.Now()
		var out string
		switch t {
		case "nmap":
			out = runCommand("nmap", "-Pn", "-p", "80,443,22,21", "-T3", url)
		case "assetfinder":
			out = orDefault(runCommand("assetfinder", url), "Tarama sonucu bulunamadı.")
		case "nuclei":
			out = orDefault(runNuclei(url, templates), "Zafiyet bulunamadı.")
		}
		results[t] = out
		scans = append(scans, scan{Name: strings.ToUpper(t[:1]) + t[1:], Output: out, Duration: dur(time.Since(t0))})
	}

	_, err := db.Exec(`INSERT INTO tarama_sonuclari (url, nmap, assetfinder, nuclei) VALUES (?, ?, ?, ?)`,
		url, results["nmap"], results["assetfinder"], results["nuclei"])
	if err != nil {
		log.Println("Sonuçlar kaydedilemedi:", err)
	}

	render(w, "results", view{Title: "Tarama Sonuçları", URL: url, Total: dur(time.Since(start)), Scans: scans})
}

func viewResultsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT id, url, COALESCE(nmap,''), COALESCE(assetfinder,''), COALESCE(nuclei,'') FROM tarama_sonuclari ORDER BY id DESC`)
	if err != nil {
		fail(w, http.StatusInternalServerError, "Sonuçlar alınamadı.")
		return
	}
	defer rows.Close()

	v := view{Title: "Geçmiş"}
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.ID, &x.URL, &x.Nmap, &x.Assetfinder, &x.Nuclei); err != nil {
			fail(w, http.StatusInternalServerError, "Sonuçlar alınamadı.")
			return
		}
		v.Rows = append(v.Rows, x)
	}
	render(w, "history", v)
}

func runNuclei(url string, templates []string) string {
	args := []string{"-u", url, "-c", "10", "--rate-limit", "200", "--timeout", "300", "--silent"}
	if len(templates) > 0 {
		args = append(args, "-t", strings.Join(templates, ","))
	}
	return runCommand("nuclei", args...)
}

// runCommand komutu shell kullanmadan çalıştırır; ANSI renk kodlarını temizler.
func runCommand(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(ansiRe.ReplaceAllString(string(out), ""))
	if err != nil {
		return strings.TrimSpace(fmt.Sprintf("Hata: %s\n%s", err, text))
	}
	return text
}

// only girdiden yalnızca izin verilen değerleri döndürür.
func only(vals, allowed []string) []string {
	var out []string
	for _, v := range vals {
		for _, a := range allowed {
			if v == a {
				out = append(out, v)
				break
			}
		}
	}
	return out
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func dur(d time.Duration) string { return d.Round(time.Millisecond).String() }
