// Copyright (c) 2013 Nova Roma. All rights reserved. 
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
)

func main() {
	// Handler function registrations
	http.HandleFunc("/", index)
	http.Handle("/content/", http.StripPrefix("/content/", http.FileServer(http.Dir("./client"))))

	// Start up the server 
	log.Printf("listening on port %s...%s", os.Getenv("PORT"), lineEnding)
	err := http.ListenAndServe(":"+os.Getenv("PORT"), nil)
	if err != nil {
		panic(err)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	log.Printf("Responding to request %s with index handler.%v", r.URL, lineEnding)
	t, err := template.ParseFiles("./client/index.html.tmpl")
	if err != nil {
		log.Println(err)
	}

	t.Execute(w, nil)
	log.Printf("Successfully handled request %s.", r.URL)
}
