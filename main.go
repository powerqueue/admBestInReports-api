package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

// Templates
var homeHTML string
var homeTpl *template.Template

var aboutHTML string
var aboutTpl *template.Template

var servicesHTML string
var servicesTpl *template.Template

var galleryHTML string
var galleryTpl *template.Template

var pricesHTML string
var pricesTpl *template.Template

var contactHTML string
var contactTpl *template.Template

var notFoundHTML string
var notFoundTpl *template.Template

func init() {

	data, err := ioutil.ReadFile("./HTML/index.html")
	if err != nil {
		fmt.Println("File home.html reading error", err)
		return
	}
	homeHTML = string(data)
	homeTpl = template.Must(template.New("index").Parse(homeHTML))

	data, err = ioutil.ReadFile("HTML/about.html")
	if err != nil {
		fmt.Println("File about.html reading error", err)
		return
	}
	aboutHTML = string(data)
	aboutTpl = template.Must(template.New("about").Parse(aboutHTML))

	data, err = ioutil.ReadFile("HTML/services.html")
	if err != nil {
		fmt.Println("File services.html reading error", err)
		return
	}
	servicesHTML = string(data)
	servicesTpl = template.Must(template.New("services").Parse(servicesHTML))

	data, err = ioutil.ReadFile("HTML/gallery.html")
	if err != nil {
		fmt.Println("File gallery.html reading error", err)
		return
	}
	galleryHTML = string(data)
	galleryTpl = template.Must(template.New("gallery").Parse(galleryHTML))

	data, err = ioutil.ReadFile("HTML/prices.html")
	if err != nil {
		fmt.Println("File prices.html reading error", err)
		return
	}
	pricesHTML = string(data)
	pricesTpl = template.Must(template.New("prices").Parse(pricesHTML))

	data, err = ioutil.ReadFile("HTML/contact.html")
	if err != nil {
		fmt.Println("File contact.html reading error", err)
		return
	}
	contactHTML = string(data)
	contactTpl = template.Must(template.New("contact").Parse(contactHTML))

	data, err = ioutil.ReadFile("HTML/404.html")
	if err != nil {
		fmt.Println("File 404.html reading error", err)
		return
	}
	notFoundHTML = string(data)
	notFoundTpl = template.Must(template.New("notFound").Parse(notFoundHTML))

}

func main() {

	serverCfg := Config{
		Host:         ":8086",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	htmlServer := Start(serverCfg)
	defer htmlServer.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan

	fmt.Println("main : shutting down")
}

// Config provides basic configuration
type Config struct {
	Host         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// HTMLServer represents the web service that serves up HTML
type HTMLServer struct {
	server *http.Server
	wg     sync.WaitGroup
}

// Start launches the HTML Server
func Start(cfg Config) *HTMLServer {

	// Setup Context
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup Handlers
	router := mux.NewRouter()

	router.HandleFunc("/", homeHandler)
	router.HandleFunc("/home", homeHandler)

	router.HandleFunc("/about", aboutHandler)
	router.HandleFunc("/services", servicesHandler)
	router.HandleFunc("/gallery", galleryHandler)
	router.HandleFunc("/prices", pricesHandler)
	router.HandleFunc("/contact", contactHandler)
	router.HandleFunc("/404", notFoundHandler)

	router.PathPrefix("/HTML/assets/").Handler(http.StripPrefix("/HTML/assets/", http.FileServer(http.Dir("./HTML/assets"))))
	// router.PathPrefix("/now-ui/").Handler(http.StripPrefix("/now-ui/", http.FileServer(http.Dir("./now-ui/"))))

	// Create the HTML Server
	htmlServer := HTMLServer{
		server: &http.Server{
			Addr:           cfg.Host,
			Handler:        router,
			ReadTimeout:    cfg.ReadTimeout,
			WriteTimeout:   cfg.WriteTimeout,
			MaxHeaderBytes: 1 << 20,
		},
	}

	// Add to the WaitGroup for the listener goroutine
	htmlServer.wg.Add(1)

	// Start the listener
	go func() {
		fmt.Printf("\nHTMLServer : Service started : Host=%v\n", cfg.Host)
		htmlServer.server.ListenAndServe()
		htmlServer.wg.Done()
	}()

	return &htmlServer
}

//Exception struct for jwt auth
type Exception struct {
	Message string `json:"message"`
}

//isAuthorized function
func isAuthorized(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header["Token"] != nil {
			token, err := jwt.Parse(req.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return mySigningKey, nil
			})

			if err != nil {
				json.NewEncoder(w).Encode(Exception{Message: err.Error()})
				return
			}
			if token.Valid {
				// context.Set(req, "decoded", token.Claims)
				next(w, req)
			} else {
				json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
			}

		} else {
			fmt.Fprintf(w, "Not Authorized")
		}
	})
}

var mySigningKey = []byte("mysupersecretphrase")

// Stop turns off the HTML Server
func (htmlServer *HTMLServer) Stop() error {
	// Create a context to attempt a graceful 5 second shutdown.
	const timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Printf("\nHTMLServer : Service stopping\n")

	// Attempt the graceful shutdown by closing the listener
	// and completing all inflight requests
	if err := htmlServer.server.Shutdown(ctx); err != nil {
		// Looks like we timed out on the graceful shutdown. Force close.
		if err := htmlServer.server.Close(); err != nil {
			fmt.Printf("\nHTMLServer : Service stopping : Error=%v\n", err)
			return err
		}
	}

	// Wait for the listener to report that it is closed.
	htmlServer.wg.Wait()
	fmt.Printf("\nHTMLServer : Stopped\n")
	return nil
}

// Push the given resource to the client.
func push(w http.ResponseWriter, resource string) {
	pusher, ok := w.(http.Pusher)
	if ok {
		if err := pusher.Push(resource, nil); err == nil {
			return
		}
	}
}

// HomeHandler renders the dashboard template
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// push(w, "../HTML/assets/css/custom.css")
	// push(w, "../HTML/assets/css/custom-rtl.css")
	// push(w, "../HTML/assets/css/style.css")
	// push(w, "../HTML/assets/css/style-rtl.css")
	// push(w, "../now-ui/assets/css/now-ui-dashboard.css?v=1.0.1")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fullData := map[string]interface{}{
		"NavigationBar": template.HTML(homeHTML),
	}
	render(w, r, homeTpl, "home", fullData)
}

// AboutHandler renders the dashboard template
func aboutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fullData := map[string]interface{}{
		"NavigationBar": template.HTML(aboutHTML),
	}
	render(w, r, aboutTpl, "about", fullData)
}

// ServicesHandler renders the dashboard template
func servicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fullData := map[string]interface{}{
		"NavigationBar": template.HTML(servicesHTML),
	}
	render(w, r, servicesTpl, "services", fullData)
}

// GalleryHandler renders the dashboard template
func galleryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fullData := map[string]interface{}{
		"NavigationBar": template.HTML(galleryHTML),
	}
	render(w, r, galleryTpl, "gallery", fullData)
}

// PricesHandler renders the dashboard template
func pricesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fullData := map[string]interface{}{
		"NavigationBar": template.HTML(pricesHTML),
	}
	render(w, r, pricesTpl, "prices", fullData)
}

// ContactHandler renders the dashboard template
func contactHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fullData := map[string]interface{}{
		"NavigationBar": template.HTML(contactHTML),
	}
	render(w, r, contactTpl, "contact", fullData)
}

// NotFoundHandler renders the dashboard template
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fullData := map[string]interface{}{
		"NavigationBar": template.HTML(notFoundHTML),
	}
	render(w, r, notFoundTpl, "notFound", fullData)
}

// Render a template, or server error.
func render(w http.ResponseWriter, r *http.Request, tpl *template.Template, name string, data interface{}) {
	buf := new(bytes.Buffer)
	if err := tpl.ExecuteTemplate(buf, name, data); err != nil {
		fmt.Printf("\nRender Error: %v\n", err)
		return
	}
	w.Write(buf.Bytes())
}
