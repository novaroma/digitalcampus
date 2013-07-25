// Copyright (c) 2013 Nova Roma. All rights resrved. 
// This Source Code Form is subject to the terms of the Mozilla Public License, 
// v.2.0. If a copy of the MPL was not distributed with this file, You can 
// obtain one at http://mozilla.org/MPL/2.0/.
package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", index)
	http.Handle("/content/", http.StripPrefix("/content/", http.FileServer(http.Dir("./client"))))
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
