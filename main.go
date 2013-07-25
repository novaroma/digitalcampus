package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", index)
	log.Println("listening...")
	err := http.ListenAndServe(":"+os.Getenv("PORT"), nil)
	if err != nil {
		panic(err)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	log.Printf("Responding to request %s with index handler.\n", r.URL)
	t, err := template.ParseFiles("./client/index.html.tmpl")
	if err != nil {
		log.Println(err)
	}

	t.Execute(w, nil)
}
